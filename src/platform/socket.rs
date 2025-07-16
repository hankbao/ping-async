// platform/socket.rs
#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::io;
use std::mem;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use byteorder::NetworkEndian;
use futures::channel::mpsc::UnboundedSender;
use ippacket::{Bytes, IcmpHeader, IcmpType4, IcmpType6};
use rand::random;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{net::UdpSocket, task, time};

use crate::{IcmpEchoReply, IcmpEchoStatus, PING_DEFAULT_TIMEOUT, PING_DEFAULT_TTL};

pub struct IcmpEchoRequestor {
    socket: Arc<UdpSocket>,
    target_addr: IpAddr,
    timeout: Duration,
    identifier: u16,
    sequence: u16,
    reply_tx: UnboundedSender<IcmpEchoReply>,
}

impl IcmpEchoRequestor {
    pub fn new(
        reply_tx: UnboundedSender<IcmpEchoReply>,
        target_addr: IpAddr,
        source_addr: Option<IpAddr>,
        ttl: Option<u8>,
        timeout: Option<Duration>,
    ) -> io::Result<Self> {
        let socket = match target_addr {
            IpAddr::V4(_) => Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?,
            IpAddr::V6(_) => Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6))?,
        };
        socket.set_nonblocking(true)?;

        let ttl = ttl.unwrap_or(PING_DEFAULT_TTL);
        let timeout = timeout.unwrap_or(PING_DEFAULT_TIMEOUT);

        if target_addr.is_ipv4() {
            socket.set_ttl(ttl as u32)?;
        } else {
            socket.set_unicast_hops_v6(ttl as u32)?;
        }

        // bind the source address if provided
        if let Some(source_addr) = source_addr {
            match (target_addr, source_addr) {
                (IpAddr::V4(_), IpAddr::V4(ip)) => {
                    socket.bind(&SocketAddrV4::new(ip, 0).into())?;
                }
                (IpAddr::V6(_), IpAddr::V6(ip)) => {
                    socket.bind(&SocketAddrV6::new(ip, 0, 0, 0).into())?;
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "source and target address must be the same IP version",
                    ));
                }
            }
        }

        // connect to the target address
        socket.connect(&SocketAddr::new(target_addr, 0).into())?;

        Ok(IcmpEchoRequestor {
            socket: Arc::new(UdpSocket::from_std(socket.into())?),
            target_addr,
            timeout,
            identifier: random(),
            sequence: 0,
            reply_tx,
        })
    }

    pub async fn send(&self) -> io::Result<()> {
        let payload = vec![0u8; IcmpHeader::len() + mem::size_of::<u128>()];
        let byte = Bytes::new(payload.into_boxed_slice());
        let packet = byte.clone();

        let (mut header, mut data) = IcmpHeader::with_bytes(byte)?;
        if self.target_addr.is_ipv4() {
            header.set_icmp_type(IcmpType4::EchoRequest.value());
        } else {
            header.set_icmp_type(IcmpType6::EchoRequest.value());
        }
        header.set_icmp_code(0);
        header.set_id(self.identifier);
        header.set_seq(self.sequence);

        let socket_clone = Arc::clone(&self.socket);
        let tx_clone = self.reply_tx.clone();
        let target_clone = self.target_addr.clone();

        let mut tick = time::interval(self.timeout);
        // approximately 0ms have elapsed. The first tick above completes immediately.
        tick.tick().await;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("failed to get timestamp: {}", e),
                )
            })?
            .as_nanos();

        data.write_u128::<NetworkEndian>(0, now).unwrap();
        if self.target_addr.is_ipv4() {
            header.calculate_checksum(data.pair_iter());
        }

        let beginning = Instant::now();
        self.socket.send(&packet.as_slice()).await?;

        task::spawn(async move {
            tokio::select! {
                _ = tick.tick() => {
                    let _ = tx_clone.unbounded_send(IcmpEchoReply::new(
                        target_clone,
                        IcmpEchoStatus::TimedOut,
                        beginning.elapsed(),
                    ));
                    return;
                }
                header = IcmpEchoRequestor::recv_loop(socket_clone, target_clone) => {
                    match header {
                        Ok((_, data)) => {
                            // we don't test identifier and sequence number here
                            IcmpEchoRequestor::parse_icmp_data(
                                data,
                                tx_clone,
                                target_clone,
                                beginning,
                            );
                        }
                        Err(e) => {
                            log::debug!("error upon recving ICMP packet: {}", e);
                            let _ = tx_clone.unbounded_send(IcmpEchoReply::new(
                                target_clone,
                                IcmpEchoStatus::Unknown,
                                beginning.elapsed(),
                            ));
                        }
                    }
                }
            }
        });

        Ok(())
    }

    async fn recv_loop(socket: Arc<UdpSocket>, target: IpAddr) -> io::Result<(IcmpHeader, Bytes)> {
        loop {
            let mut buf = vec![0u8; 1024];

            let size = socket.recv(&mut buf).await?;
            let payload: Box<[u8]>;

            #[cfg(target_os = "macos")]
            {
                if target.is_ipv4() {
                    // skip the IP header for icmp on macOS
                    payload = Vec::from(&buf[20..size]).into_boxed_slice();
                } else {
                    payload = Vec::from(&buf[..size]).into_boxed_slice();
                }
            }

            #[cfg(target_os = "linux")]
            {
                payload = Vec::from(&buf[..size]).into_boxed_slice();
            }

            let (header, data) = IcmpHeader::with_bytes(Bytes::new(payload))?;
            match (target, header.icmp_type()) {
                (IpAddr::V4(_), x) if x == IcmpType4::EchoReply.value() => {
                    return Ok((header, data))
                }
                (IpAddr::V6(_), x) if x == IcmpType6::EchoReply.value() => {
                    return Ok((header, data))
                }
                _ => continue, // ignore the ECHO_REQUEST packet when ping ::1 on macOS
            }
        }
    }

    fn parse_icmp_data(
        data: Bytes,
        tx: UnboundedSender<IcmpEchoReply>,
        target: IpAddr,
        beginning: Instant,
    ) {
        if data.len() != mem::size_of::<u128>() {
            let _ = tx.unbounded_send(IcmpEchoReply::new(
                target,
                IcmpEchoStatus::Unknown,
                beginning.elapsed(),
            ));
            return;
        }

        let sent = data.read_u128::<NetworkEndian>(0).unwrap();
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(now) => {
                let rtt = now.as_nanos() - sent;
                let _ = tx.unbounded_send(IcmpEchoReply::new(
                    target,
                    IcmpEchoStatus::Success,
                    Duration::from_nanos(rtt as u64),
                ));
            }
            Err(e) => {
                log::debug!("failed to get system time: {}", e);

                let _ = tx.unbounded_send(IcmpEchoReply::new(
                    target,
                    IcmpEchoStatus::Unknown,
                    beginning.elapsed(),
                ));
            }
        }
    }
}
