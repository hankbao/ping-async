// platform/socket.rs

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{
    atomic::{AtomicU16, Ordering},
    Arc, Mutex, OnceLock,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::channel::oneshot;
use rand::random;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{net::UdpSocket, time};

use crate::{
    icmp::IcmpPacket, IcmpEchoReply, IcmpEchoStatus, PING_DEFAULT_TIMEOUT, PING_DEFAULT_TTL,
};

type RequestRegistry = Arc<Mutex<HashMap<u16, oneshot::Sender<IcmpEchoReply>>>>;

struct RouterContext {
    target_addr: IpAddr,
    socket: Arc<UdpSocket>,
    registry: RequestRegistry,
    failed: Arc<Mutex<Option<io::Error>>>,
}

/// Requestor for sending ICMP Echo Requests (ping) and receiving replies on Unix systems.
///
/// This implementation uses ICMP sockets with Tokio for async operations. It requires
/// unprivileged ICMP socket support, which is available on macOS by default and on
/// Linux when the `net.ipv4.ping_group_range` sysctl parameter is properly configured.
///
/// The requestor spawns a background task to handle incoming replies and is safe to
/// clone and use across multiple threads and async tasks.
///
/// # Platform Requirements
///
/// - **macOS**: Works with unprivileged sockets out of the box
/// - **Linux**: Requires `net.ipv4.ping_group_range` sysctl to allow unprivileged ICMP sockets
///
/// # Examples
///
/// ```rust,no_run
/// use ping_async::IcmpEchoRequestor;
/// use std::net::IpAddr;
///
/// #[tokio::main]
/// async fn main() -> std::io::Result<()> {
///     let target = "8.8.8.8".parse::<IpAddr>().unwrap();
///     let pinger = IcmpEchoRequestor::new(target, None, None, None)?;
///     
///     let reply = pinger.send().await?;
///     println!("Reply: {:?}", reply);
///     
///     Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct IcmpEchoRequestor {
    inner: Arc<RequestorInner>,
}

struct RequestorInner {
    socket: Arc<UdpSocket>,
    target_addr: IpAddr,
    timeout: Duration,
    identifier: u16,
    sequence: AtomicU16,
    registry: RequestRegistry,
    router_abort: OnceLock<tokio::task::AbortHandle>,
    router_context: RouterContext,
}

impl IcmpEchoRequestor {
    /// Creates a new ICMP echo requestor for the specified target address.
    ///
    /// # Arguments
    ///
    /// * `target_addr` - The IP address to ping (IPv4 or IPv6)
    /// * `source_addr` - Optional source IP address to bind to. Must match the IP version of `target_addr`
    /// * `ttl` - Optional Time-To-Live value. Defaults to [`PING_DEFAULT_TTL`](crate::PING_DEFAULT_TTL)
    /// * `timeout` - Optional timeout duration. Defaults to [`PING_DEFAULT_TIMEOUT`](crate::PING_DEFAULT_TIMEOUT)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The source address type doesn't match the target address type (IPv4 vs IPv6)
    /// - ICMP socket creation fails (typically due to insufficient permissions)
    /// - Socket configuration fails
    ///
    /// # Platform Requirements
    ///
    /// - **Linux**: Requires `net.ipv4.ping_group_range` sysctl parameter to allow unprivileged ICMP sockets.
    ///   Check with: `sysctl net.ipv4.ping_group_range`
    /// - **macOS**: Works with unprivileged sockets by default
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use ping_async::IcmpEchoRequestor;
    /// use std::net::IpAddr;
    /// use std::time::Duration;
    ///
    /// // Basic usage with defaults
    /// let pinger = IcmpEchoRequestor::new(
    ///     "8.8.8.8".parse().unwrap(),
    ///     None,
    ///     None,
    ///     None
    /// )?;
    ///
    /// // With custom source address and timeout
    /// let pinger = IcmpEchoRequestor::new(
    ///     "2001:4860:4860::8888".parse().unwrap(),
    ///     Some("::1".parse().unwrap()),
    ///     Some(64),
    ///     Some(Duration::from_millis(500))
    /// )?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn new(
        target_addr: IpAddr,
        source_addr: Option<IpAddr>,
        ttl: Option<u8>,
        timeout: Option<Duration>,
    ) -> io::Result<Self> {
        // Check if the target address matches the source address type
        match (target_addr, source_addr) {
            (IpAddr::V4(_), Some(IpAddr::V6(_))) | (IpAddr::V6(_), Some(IpAddr::V4(_))) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Source address type does not match target address type",
                ));
            }
            _ => {}
        }

        let timeout = timeout.unwrap_or(PING_DEFAULT_TIMEOUT);
        let identifier = random();
        let sequence = AtomicU16::new(0);

        let socket = Arc::new(create_socket(target_addr, source_addr, ttl)?);
        let registry = Arc::new(Mutex::new(HashMap::new()));

        // Create a context for the router task
        let router_context = RouterContext {
            target_addr,
            socket: Arc::clone(&socket),
            registry: Arc::clone(&registry),
            failed: Arc::new(Mutex::new(None)),
        };

        Ok(IcmpEchoRequestor {
            inner: Arc::new(RequestorInner {
                socket,
                target_addr,
                timeout,
                identifier,
                sequence,
                registry,
                router_abort: OnceLock::new(),
                router_context,
            }),
        })
    }

    /// Sends an ICMP echo request and waits for a reply.
    ///
    /// This method is async and will complete when either:
    /// - An echo reply is received
    /// - The configured timeout expires
    /// - An error occurs
    ///
    /// The requestor uses lazy initialization - the background reply router task
    /// is only spawned on the first call to `send()`. The requestor can be used
    /// multiple times and is safe to use concurrently from multiple async tasks.
    ///
    /// # Returns
    ///
    /// Returns an [`IcmpEchoReply`](crate::IcmpEchoReply) containing:
    /// - The destination IP address
    /// - The status of the ping operation  
    /// - The measured round-trip time
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The socket send operation fails immediately
    /// - The background router task has failed (typically due to permission loss)
    /// - Internal communication channels fail unexpectedly
    ///
    /// Note that timeout and unreachable conditions are returned as successful
    /// `IcmpEchoReply` with appropriate status values, not as errors.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use ping_async::{IcmpEchoRequestor, IcmpEchoStatus};
    ///
    /// #[tokio::main]
    /// async fn main() -> std::io::Result<()> {
    ///     let pinger = IcmpEchoRequestor::new(
    ///         "8.8.8.8".parse().unwrap(),
    ///         None, None, None
    ///     )?;
    ///     
    ///     // Send multiple pings using the same requestor
    ///     for i in 0..3 {
    ///         let reply = pinger.send().await?;
    ///         
    ///         match reply.status() {
    ///             IcmpEchoStatus::Success => {
    ///                 println!("Ping {}: {:?}", i, reply.round_trip_time());
    ///             }
    ///             IcmpEchoStatus::TimedOut => {
    ///                 println!("Ping {} timed out", i);
    ///             }
    ///             _ => {
    ///                 println!("Ping {} failed: {:?}", i, reply.status());
    ///             }
    ///         }
    ///     }
    ///     
    ///     Ok(())
    /// }
    /// ```
    pub async fn send(&self) -> io::Result<IcmpEchoReply> {
        // Check if router failed already
        if let Some(failed) = self
            .inner
            .router_context
            .failed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            return Err(failed);
        }

        // lazy spawning
        self.ensure_router_running();

        let sequence = self.inner.sequence.fetch_add(1, Ordering::SeqCst);
        let key = sequence;

        // Use timestamp as our payload
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| io::Error::other(format!("timestamp error: {e}")))?
            .as_nanos() as u64;
        let payload = timestamp.to_be_bytes();

        let packet = IcmpPacket::new_echo_request(
            self.inner.target_addr,
            self.inner.identifier,
            sequence,
            &payload,
        );

        let target = SocketAddr::new(self.inner.target_addr, 0);
        let reply_rx = match self.inner.socket.send_to(packet.as_bytes(), target).await {
            Ok(_) => {
                let (tx, rx) = oneshot::channel();

                self.inner
                    .registry
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert(key, tx);

                rx
            }
            Err(e) => match e.kind() {
                io::ErrorKind::NetworkUnreachable
                | io::ErrorKind::NetworkDown
                | io::ErrorKind::HostUnreachable => {
                    return Ok(IcmpEchoReply::new(
                        self.inner.target_addr,
                        IcmpEchoStatus::Unreachable,
                        Duration::ZERO,
                    ));
                }
                _ => return Err(e),
            },
        };

        let timeout = self.inner.timeout;
        let target_addr = self.inner.target_addr;

        tokio::select! {
            result = reply_rx => {
                match result {
                    Ok(reply) => Ok(reply),
                    Err(_) => {
                        // Channel closed - router probably failed
                        Err(io::Error::other("reply channel closed"))
                    }
                }
            }
            _ = time::sleep(timeout) => {
                // Remove from registry on timeout
                self.inner.registry.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(&key);

                // Calculate RTT for timed out request
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| io::Error::other(format!("timestamp error: {e}")))?
                    .as_nanos() as u64;
                let rtt = Duration::from_nanos(now - timestamp);

                Ok(IcmpEchoReply::new(
                    target_addr,
                    IcmpEchoStatus::TimedOut,
                    rtt,
                ))
            }
        }
    }

    fn ensure_router_running(&self) {
        let target_addr = self.inner.router_context.target_addr;
        let identifier = self.inner.identifier;
        let socket = Arc::clone(&self.inner.router_context.socket);
        let registry = Arc::clone(&self.inner.router_context.registry);
        let failed = Arc::clone(&self.inner.router_context.failed);

        self.inner.router_abort.get_or_init(|| {
            let handle = tokio::spawn(reply_router_loop(
                target_addr,
                identifier,
                socket,
                registry,
                failed,
            ));
            handle.abort_handle()
        });
    }
}

impl Drop for RequestorInner {
    fn drop(&mut self) {
        if let Some(abort_handle) = self.router_abort.get() {
            abort_handle.abort();
        }
    }
}

async fn reply_router_loop(
    target_addr: IpAddr,
    identifier: u16,
    socket: Arc<UdpSocket>,
    registry: RequestRegistry,
    failed: Arc<Mutex<Option<io::Error>>>,
) {
    loop {
        let mut buf = vec![0u8; 1024];

        match socket.recv(&mut buf).await {
            Ok(size) => {
                buf.truncate(size);

                if let Some(reply_packet) = IcmpPacket::parse_reply(&buf, target_addr) {
                    // Check if this is a reply to our request by comparing identifier, ignoring if not
                    // identifier may be rewritten by some implementations (e.g., Linux on Docker Mac)
                    if reply_packet.identifier() != identifier {
                        continue;
                    }

                    // Use sequence number to find the waiting sender
                    let key = reply_packet.sequence();
                    let sender = registry
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .remove(&key);

                    if let Some(sender) = sender {
                        // Extract timestamp from payload to calculate RTT
                        let payload = reply_packet.payload();

                        let reply = if payload.len() >= 8 {
                            let sent_timestamp = u64::from_be_bytes([
                                payload[0], payload[1], payload[2], payload[3], payload[4],
                                payload[5], payload[6], payload[7],
                            ]);

                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_nanos() as u64;
                            let rtt = Duration::from_nanos(now.saturating_sub(sent_timestamp));

                            IcmpEchoReply::new(target_addr, IcmpEchoStatus::Success, rtt)
                        } else {
                            // Report Unknown error if payload is too short
                            IcmpEchoReply::new(target_addr, IcmpEchoStatus::Unknown, Duration::ZERO)
                        };

                        // Send reply to waiting thread
                        let _ = sender.send(reply);
                    }
                }
            }
            Err(e) => {
                match e.kind() {
                    // Fatal errors - router cannot continue
                    io::ErrorKind::PermissionDenied |        // Lost privileges
                    io::ErrorKind::AddrNotAvailable |        // Address no longer available
                    io::ErrorKind::ConnectionAborted |       // Socket forcibly closed
                    io::ErrorKind::NotConnected => {         // Socket disconnected
                        // Clear pending requests so they don't hang
                        registry.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clear();

                        // Mark the failed flag
                        let mut failed_lock = failed.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                        *failed_lock = Some(e);

                        return;
                    }

                    // Continue with temporary network issues, etc.
                    _ => continue,
                }
            }
        }
    }
}

fn create_socket(
    target_addr: IpAddr,
    source_addr: Option<IpAddr>,
    ttl: Option<u8>,
) -> io::Result<UdpSocket> {
    let socket = match target_addr {
        IpAddr::V4(_) => Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?,
        IpAddr::V6(_) => Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6))?,
    };
    socket.set_nonblocking(true)?;

    let ttl = ttl.unwrap_or(PING_DEFAULT_TTL);
    if target_addr.is_ipv4() {
        socket.set_ttl_v4(ttl as u32)?;
    } else {
        socket.set_unicast_hops_v6(ttl as u32)?;
    }

    // Bind the socket to the source address if provided
    if let Some(source_addr) = source_addr {
        socket.bind(&SocketAddr::new(source_addr, 0).into())?;
    }

    UdpSocket::from_std(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[cfg(test)]
    fn is_router_spawned(pinger: &IcmpEchoRequestor) -> bool {
        pinger.inner.router_abort.get().is_some()
    }

    #[tokio::test]
    async fn test_lazy_router_spawning() -> io::Result<()> {
        // Create a requestor but don't call send() yet
        let pinger = IcmpEchoRequestor::new("127.0.0.1".parse().unwrap(), None, None, None)?;

        // Router should not be spawned yet - this is the key test for lazy initialization
        assert!(
            !is_router_spawned(&pinger),
            "Router should not be spawned after new()"
        );

        // Now call send() - this should trigger lazy router spawning
        let reply = pinger.send().await?;
        assert_eq!(reply.destination(), "127.0.0.1".parse::<IpAddr>().unwrap());

        // Verify router is now spawned
        assert!(
            is_router_spawned(&pinger),
            "Router should be spawned after first send()"
        );

        // Subsequent sends should reuse the same router
        let reply2 = pinger.send().await?;
        assert_eq!(reply2.destination(), "127.0.0.1".parse::<IpAddr>().unwrap());

        // Router should still be spawned
        assert!(
            is_router_spawned(&pinger),
            "Router should remain spawned after subsequent sends"
        );

        Ok(())
    }
}
