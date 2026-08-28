// platform/socket.rs

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::channel::oneshot;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::time::{self, Instant};

use crate::{
    icmp::{IcmpErrorInfo, IcmpPacket},
    IcmpEchoReply, IcmpEchoStatus, PING_DEFAULT_TIMEOUT, PING_DEFAULT_TTL,
};

/// Receive buffer requested for the ICMP socket. On macOS every ICMP `SOCK_DGRAM` socket
/// receives every echo reply on the host and the default 8 KiB buffer overflows under
/// bursts, dropping the socket's own replies.
const RECV_BUFFER_SIZE: usize = 1 << 20;

/// One in-flight request registered under its ICMP sequence number.
struct RegistryEntry {
    /// Unique per request for the lifetime of the requestor; lets a guard tell its own
    /// entry apart from a newer request that reused the same sequence number.
    request_id: u64,
    /// Timestamp carried in the echo request payload; a reply must echo it back.
    sent_timestamp: u64,
    tx: oneshot::Sender<IcmpEchoReply>,
}

/// Registry of in-flight requests plus the allocation state for sequence numbers.
struct Registry {
    next_sequence: u16,
    next_request_id: u64,
    entries: HashMap<u16, RegistryEntry>,
}

impl Registry {
    fn new() -> Self {
        Registry {
            next_sequence: 0,
            next_request_id: 1,
            entries: HashMap::new(),
        }
    }

    /// Allocates a sequence number that is not currently in flight and registers the
    /// request under it. Returns the sequence number and the request's unique id.
    ///
    /// Walks the 16-bit space from `next_sequence` until a vacant value is found; fails only
    /// if all 65 536 values are in flight (in which case no id is consumed).
    fn allocate(
        &mut self,
        sent_timestamp: u64,
        tx: oneshot::Sender<IcmpEchoReply>,
    ) -> io::Result<(u16, u64)> {
        let mut candidate = self.next_sequence;
        for _ in 0..=usize::from(u16::MAX) {
            match self.entries.entry(candidate) {
                Entry::Vacant(vacant) => {
                    let request_id = self.next_request_id;
                    self.next_request_id += 1;
                    vacant.insert(RegistryEntry {
                        request_id,
                        sent_timestamp,
                        tx,
                    });
                    self.next_sequence = candidate.wrapping_add(1);
                    return Ok((candidate, request_id));
                }
                Entry::Occupied(_) => candidate = candidate.wrapping_add(1),
            }
        }
        Err(io::Error::other(
            "all 65536 ICMP sequence numbers are in flight",
        ))
    }

    /// Removes the entry for `sequence` only if it still belongs to `request_id`.
    fn remove_if_owner(&mut self, sequence: u16, request_id: u64) -> bool {
        match self.entries.entry(sequence) {
            Entry::Occupied(occupied) if occupied.get().request_id == request_id => {
                occupied.remove();
                true
            }
            _ => false,
        }
    }
}

type SharedRegistry = Arc<Mutex<Registry>>;

fn lock_registry(registry: &SharedRegistry) -> MutexGuard<'_, Registry> {
    registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Removes a request's registry entry when the request ends for any reason — reply
/// delivered (already removed by the router: no-op), local timeout, send error, or the
/// `send()` future being dropped mid-flight. Only ever removes the entry it created.
struct RegistryGuard {
    registry: SharedRegistry,
    sequence: u16,
    request_id: u64,
}

impl Drop for RegistryGuard {
    fn drop(&mut self) {
        lock_registry(&self.registry).remove_if_owner(self.sequence, self.request_id);
    }
}

/// Persistent record of a fatal router error, stored so that all subsequent
/// `send()` calls fail fast with the same error information.
struct RouterError {
    kind: io::ErrorKind,
    message: String,
}

impl RouterError {
    fn from_io_error(e: &io::Error) -> Self {
        RouterError {
            kind: e.kind(),
            message: e.to_string(),
        }
    }

    fn to_io_error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}

type SharedFailure = Arc<Mutex<Option<RouterError>>>;

fn lock_failure(failed: &SharedFailure) -> MutexGuard<'_, Option<RouterError>> {
    failed
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct RouterContext {
    target_addr: IpAddr,
    socket: Arc<UdpSocket>,
    registry: SharedRegistry,
    failed: SharedFailure,
}

/// Why `run_request` could not produce a reply.
#[derive(Debug)]
enum RequestFailure {
    /// The send stage failed with an error that is not reported as `Unreachable`.
    Send(io::Error),
    /// The reply channel was closed without a reply (the router dropped the sender).
    ReplyChannelClosed,
}

/// Runs one request under a single deadline that bounds both the send stage and the wait
/// for the reply. Contains no socket or registry access, so it is testable with stub
/// futures.
///
/// - The send stage expiring, or the reply not arriving by `deadline`, yields `TimedOut`.
/// - A send error of kind `NetworkUnreachable` / `NetworkDown` / `HostUnreachable` yields
///   `Unreachable`; any other send error is returned as `RequestFailure::Send`.
/// - A cancelled reply channel is returned as `RequestFailure::ReplyChannelClosed`; the
///   caller resolves it through the router's persisted failure state.
async fn run_request(
    deadline: Instant,
    send_stage: impl Future<Output = io::Result<()>>,
    reply_rx: oneshot::Receiver<IcmpEchoReply>,
    target_addr: IpAddr,
    started_at: Instant,
) -> Result<IcmpEchoReply, RequestFailure> {
    let timed_out =
        || IcmpEchoReply::new(target_addr, IcmpEchoStatus::TimedOut, started_at.elapsed());

    match time::timeout_at(deadline, send_stage).await {
        Err(_elapsed) => return Ok(timed_out()),
        Ok(Err(e)) => {
            return match e.kind() {
                io::ErrorKind::NetworkUnreachable
                | io::ErrorKind::NetworkDown
                | io::ErrorKind::HostUnreachable => Ok(IcmpEchoReply::new(
                    target_addr,
                    IcmpEchoStatus::Unreachable,
                    Duration::ZERO,
                )),
                _ => Err(RequestFailure::Send(e)),
            };
        }
        Ok(Ok(())) => {}
    }

    tokio::select! {
        result = reply_rx => match result {
            Ok(reply) => Ok(reply),
            Err(_canceled) => Err(RequestFailure::ReplyChannelClosed),
        },
        _ = time::sleep_until(deadline) => Ok(timed_out()),
    }
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
    registry: SharedRegistry,
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

        let (socket, identifier) = create_socket(target_addr, source_addr, ttl)?;
        let socket = Arc::new(socket);
        let registry: SharedRegistry = Arc::new(Mutex::new(Registry::new()));

        // Create a context for the router task
        let router_context = RouterContext {
            target_addr,
            socket: Arc::clone(&socket),
            registry: Arc::clone(&registry),
            failed: Arc::new(Mutex::new(None::<RouterError>)),
        };

        Ok(IcmpEchoRequestor {
            inner: Arc::new(RequestorInner {
                socket,
                target_addr,
                timeout,
                identifier,
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
    /// The configured timeout bounds the whole operation, including the send itself.
    /// Dropping the returned future before it resolves is safe: the request's registry
    /// entry is released immediately.
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
    /// - All 65 536 ICMP sequence numbers are currently in flight
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
        // Check if router failed already — error is persistent, not consumed
        if let Some(ref router_error) = *lock_failure(&self.inner.router_context.failed) {
            return Err(router_error.to_io_error());
        }

        // lazy spawning
        self.ensure_router_running();

        // One deadline bounds the send stage and the reply wait.
        let started_at = Instant::now();
        let deadline = started_at + self.inner.timeout;

        // Use timestamp as our payload
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| io::Error::other(format!("timestamp error: {e}")))?
            .as_nanos() as u64;
        let payload = timestamp.to_be_bytes();

        // Register in the registry BEFORE sending so fast replies (e.g. loopback)
        // are not dropped by the router due to a missing entry. The guard removes the
        // entry on every exit path, including the future being dropped.
        let (tx, reply_rx) = oneshot::channel();
        let (sequence, request_id) = lock_registry(&self.inner.registry).allocate(timestamp, tx)?;
        let _guard = RegistryGuard {
            registry: Arc::clone(&self.inner.registry),
            sequence,
            request_id,
        };

        let packet = IcmpPacket::new_echo_request(
            self.inner.target_addr,
            self.inner.identifier,
            sequence,
            &payload,
        );
        let target = SocketAddr::new(self.inner.target_addr, 0);
        let send_stage = async {
            self.inner
                .socket
                .send_to(packet.as_bytes(), target)
                .await
                .map(|_| ())
        };

        match run_request(
            deadline,
            send_stage,
            reply_rx,
            self.inner.target_addr,
            started_at,
        )
        .await
        {
            Ok(reply) => Ok(reply),
            Err(RequestFailure::Send(e)) => Err(e),
            Err(RequestFailure::ReplyChannelClosed) => {
                // Channel closed — check if router failed for a consistent error
                if let Some(ref router_error) = *lock_failure(&self.inner.router_context.failed) {
                    Err(router_error.to_io_error())
                } else {
                    Err(io::Error::other("reply channel closed"))
                }
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

/// Delivers an echo reply to the waiting request, if any.
///
/// The entry is removed only if the reply carries the timestamp the request was sent with
/// (the payload is echoed back verbatim); a stale reply for an earlier request that used
/// the same sequence number leaves the current entry untouched. Compare-and-remove happens
/// under a single lock acquisition. Returns whether a waiter was completed.
fn deliver_echo_reply(
    registry: &SharedRegistry,
    identifier: u16,
    target_addr: IpAddr,
    packet: &IcmpPacket,
) -> bool {
    if packet.identifier() != identifier {
        return false;
    }
    let payload = packet.payload();
    if payload.len() < 8 {
        return false;
    }
    let sent_timestamp = u64::from_be_bytes([
        payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
        payload[7],
    ]);

    let entry = {
        let mut registry = lock_registry(registry);
        match registry.entries.entry(packet.sequence()) {
            Entry::Occupied(occupied) if occupied.get().sent_timestamp == sent_timestamp => {
                occupied.remove()
            }
            _ => return false,
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let rtt = Duration::from_nanos(now.saturating_sub(sent_timestamp));
    let _ = entry.tx.send(IcmpEchoReply::new(
        target_addr,
        IcmpEchoStatus::Success,
        rtt,
    ));
    true
}

/// Delivers an ICMP error (Destination Unreachable, Time Exceeded) that embedded one of our
/// echo requests to the waiting request, matched by identifier and sequence. ICMP errors
/// carry only the embedded ICMP header, not the payload, so they match on sequence alone.
fn deliver_error(
    registry: &SharedRegistry,
    identifier: u16,
    target_addr: IpAddr,
    info: &IcmpErrorInfo,
) -> bool {
    if info.identifier != identifier {
        return false;
    }
    let entry = lock_registry(registry).entries.remove(&info.sequence);
    match entry {
        Some(entry) => {
            let _ = entry
                .tx
                .send(IcmpEchoReply::new(target_addr, info.status, Duration::ZERO));
            true
        }
        None => false,
    }
}

/// Persists a fatal router error and cancels every in-flight request.
fn fail_router(registry: &SharedRegistry, failed: &SharedFailure, error: &io::Error) {
    // Store the error persistently so all future send() calls fail fast
    *lock_failure(failed) = Some(RouterError::from_io_error(error));

    // Drain the registry — dropping senders closes channels, which causes in-flight
    // send() calls to see a closed channel and check `failed` for a consistent error.
    lock_registry(registry).entries.clear();
}

/// Whether a `recv` error is fatal for the router (it cannot continue).
fn is_fatal_recv_error(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::PermissionDenied |        // Lost privileges
        io::ErrorKind::AddrNotAvailable |        // Address no longer available
        io::ErrorKind::ConnectionAborted |       // Socket forcibly closed
        io::ErrorKind::NotConnected // Socket disconnected
    )
}

async fn reply_router_loop(
    target_addr: IpAddr,
    identifier: u16,
    socket: Arc<UdpSocket>,
    registry: SharedRegistry,
    failed: SharedFailure,
) {
    let mut buf = vec![0u8; 1024];

    loop {
        match socket.recv(&mut buf).await {
            Ok(size) => {
                let data = &buf[..size];

                if let Some(reply_packet) = IcmpPacket::parse_reply(data, target_addr) {
                    deliver_echo_reply(&registry, identifier, target_addr, &reply_packet);
                } else if let Some(error_info) = IcmpPacket::parse_error_reply(data, target_addr) {
                    deliver_error(&registry, identifier, target_addr, &error_info);
                }
            }
            Err(e) => {
                if is_fatal_recv_error(e.kind()) {
                    fail_router(&registry, &failed, &e);
                    return;
                }
                // Continue with temporary network issues, etc.
            }
        }
    }
}

fn create_socket(
    target_addr: IpAddr,
    source_addr: Option<IpAddr>,
    ttl: Option<u8>,
) -> io::Result<(UdpSocket, u16)> {
    let socket = match target_addr {
        IpAddr::V4(_) => Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?,
        IpAddr::V6(_) => Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6))?,
    };
    socket.set_nonblocking(true)?;

    // Best effort: Linux clamps to rmem_max silently; macOS only fails if
    // kern.ipc.maxsockbuf was lowered below the request.
    let _ = socket.set_recv_buffer_size(RECV_BUFFER_SIZE);

    let ttl = ttl.unwrap_or(PING_DEFAULT_TTL);
    if target_addr.is_ipv4() {
        socket.set_ttl_v4(ttl as u32)?;
    } else {
        socket.set_unicast_hops_v6(ttl as u32)?;
    }

    // Platform-specific ICMP identifier handling
    //
    // macOS/BSD systems preserve the ICMP identifier field throughout the ping process.
    // When we send an ICMP ECHO request with a specific identifier (e.g., 6789),
    // the reply will contain the same identifier value. This allows us to use
    // random identifiers for distinguishing between different ping sessions.
    #[cfg(not(target_os = "linux"))]
    let identifier = {
        // On macOS, use random identifier and bind to source address if provided
        if let Some(source_addr) = source_addr {
            socket.bind(&SocketAddr::new(source_addr, 0).into())?;
        }
        rand::random()
    };

    // Linux systems behave differently with unprivileged ICMP sockets (SOCK_DGRAM).
    // The Linux kernel automatically replaces the ICMP identifier field with the
    // socket's local port number. This means:
    // 1. Any identifier we set will be ignored and replaced by the kernel
    // 2. ICMP replies are routed back based on the socket port, not the identifier
    // 3. We must bind the socket to get a port assignment from the kernel
    // 4. The port number becomes our effective identifier for matching replies
    //
    // This behavior ensures proper delivery of ICMP replies to the correct socket
    // in a multi-process environment, since the kernel handles routing internally.
    #[cfg(target_os = "linux")]
    let identifier = {
        // Bind with port 0 to let kernel assign a unique port number.
        // This port will be used as the ICMP identifier by the kernel.
        let bind_addr = source_addr.unwrap_or(match target_addr {
            IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        });
        socket.bind(&SocketAddr::new(bind_addr, 0).into())?;

        // Extract the kernel-assigned port number, which will be used as the ICMP identifier
        let local_addr = socket.local_addr()?;
        local_addr
            .as_socket()
            .ok_or(io::Error::other(
                "Failed to get kernel-assigned ICMP identifier",
            ))?
            .port()
    };

    let udp_socket = UdpSocket::from_std(socket.into())?;
    Ok((udp_socket, identifier))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    use crate::icmp::IcmpType;

    fn is_router_spawned(pinger: &IcmpEchoRequestor) -> bool {
        pinger.inner.router_abort.get().is_some()
    }

    /// Makes `ensure_router_running` a no-op so replies are never delivered.
    fn disable_router(pinger: &IcmpEchoRequestor) {
        let handle = tokio::spawn(async {}).abort_handle();
        assert!(
            pinger.inner.router_abort.set(handle).is_ok(),
            "router not yet spawned"
        );
    }

    fn registry_len(pinger: &IcmpEchoRequestor) -> usize {
        lock_registry(&pinger.inner.registry).entries.len()
    }

    fn dummy_sender() -> oneshot::Sender<IcmpEchoReply> {
        let (tx, _rx) = oneshot::channel();
        tx
    }

    fn echo_reply_packet(target: IpAddr, identifier: u16, sequence: u16, ts: u64) -> IcmpPacket {
        IcmpPacket::new(
            IcmpType::echo_reply_for(target),
            0,
            identifier,
            sequence,
            &ts.to_be_bytes(),
        )
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

    // ---- registry allocation ---------------------------------------------------------

    #[test]
    fn allocate_skips_occupied_and_wraps() {
        let mut registry = Registry::new();
        for seq in 0..=2u16 {
            registry.entries.insert(
                seq,
                RegistryEntry {
                    request_id: 0,
                    sent_timestamp: 0,
                    tx: dummy_sender(),
                },
            );
        }
        let (seq, _) = registry.allocate(1, dummy_sender()).unwrap();
        assert_eq!(seq, 3);

        let mut registry = Registry::new();
        registry.next_sequence = u16::MAX;
        registry.entries.insert(
            u16::MAX,
            RegistryEntry {
                request_id: 0,
                sent_timestamp: 0,
                tx: dummy_sender(),
            },
        );
        let (seq, _) = registry.allocate(1, dummy_sender()).unwrap();
        assert_eq!(seq, 0, "walk wraps from u16::MAX to 0");
        assert_eq!(registry.next_sequence, 1);
    }

    #[test]
    fn allocate_fails_when_exhausted_without_consuming_an_id() {
        let mut registry = Registry::new();
        let mut last_id = 0;
        for _ in 0..=usize::from(u16::MAX) {
            let (_, id) = registry.allocate(0, dummy_sender()).unwrap();
            assert!(id > last_id, "ids are strictly increasing");
            last_id = id;
        }
        assert_eq!(registry.entries.len(), 65_536);
        let next_id_before = registry.next_request_id;
        assert!(registry.allocate(0, dummy_sender()).is_err());
        assert_eq!(registry.next_request_id, next_id_before);
    }

    #[test]
    fn guard_only_removes_its_own_entry() {
        let registry: SharedRegistry = Arc::new(Mutex::new(Registry::new()));

        let (seq, id1) = lock_registry(&registry)
            .allocate(1, dummy_sender())
            .unwrap();
        let guard1 = RegistryGuard {
            registry: Arc::clone(&registry),
            sequence: seq,
            request_id: id1,
        };

        // The router completes the request; the sequence becomes free.
        lock_registry(&registry).entries.remove(&seq);

        // Force the next allocation to reuse the same sequence number.
        lock_registry(&registry).next_sequence = seq;
        let (seq2, id2) = lock_registry(&registry)
            .allocate(2, dummy_sender())
            .unwrap();
        assert_eq!(seq2, seq);
        assert_ne!(id2, id1);
        assert!(id2 > id1);
        let guard2 = RegistryGuard {
            registry: Arc::clone(&registry),
            sequence: seq2,
            request_id: id2,
        };

        drop(guard1);
        {
            let reg = lock_registry(&registry);
            let entry = reg.entries.get(&seq).expect("newer entry must survive");
            assert_eq!(entry.request_id, id2);
        }

        drop(guard2);
        assert!(lock_registry(&registry).entries.is_empty());
    }

    #[tokio::test]
    async fn cancelled_send_leaks_no_registry_entry() -> io::Result<()> {
        let pinger = IcmpEchoRequestor::new("127.0.0.1".parse().unwrap(), None, None, None)?;
        disable_router(&pinger);

        let result = tokio::time::timeout(Duration::from_millis(10), pinger.send()).await;
        assert!(
            result.is_err(),
            "no router: the future must still be pending"
        );
        assert_eq!(
            registry_len(&pinger),
            0,
            "dropped future must release its entry"
        );

        // A fresh requestor is unaffected.
        let fresh = IcmpEchoRequestor::new("127.0.0.1".parse().unwrap(), None, None, None)?;
        let reply = fresh.send().await?;
        assert_eq!(reply.destination(), "127.0.0.1".parse::<IpAddr>().unwrap());
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn recv_buffer_is_enlarged_on_macos() {
        let pinger =
            IcmpEchoRequestor::new("127.0.0.1".parse().unwrap(), None, None, None).unwrap();
        let size = socket2::SockRef::from(&*pinger.inner.socket)
            .recv_buffer_size()
            .unwrap();
        assert!(size >= RECV_BUFFER_SIZE, "SO_RCVBUF is {size}");
    }

    // ---- router delivery -------------------------------------------------------------

    #[test]
    fn stale_reply_with_wrong_timestamp_is_rejected() {
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        let identifier = 0x1234;
        let registry: SharedRegistry = Arc::new(Mutex::new(Registry::new()));
        let (tx, mut rx) = oneshot::channel();
        let (seq, _) = lock_registry(&registry).allocate(2, tx).unwrap();

        let stale = echo_reply_packet(target, identifier, seq, 1);
        assert!(!deliver_echo_reply(&registry, identifier, target, &stale));
        assert!(lock_registry(&registry).entries.contains_key(&seq));
        assert!(
            rx.try_recv().unwrap().is_none(),
            "waiter must still be pending"
        );

        let fresh = echo_reply_packet(target, identifier, seq, 2);
        assert!(deliver_echo_reply(&registry, identifier, target, &fresh));
        assert!(!lock_registry(&registry).entries.contains_key(&seq));
        let reply = rx.try_recv().unwrap().expect("exactly one delivery");
        assert_eq!(reply.status(), IcmpEchoStatus::Success);

        let again = echo_reply_packet(target, identifier, seq, 2);
        assert!(!deliver_echo_reply(&registry, identifier, target, &again));

        // Wrong identifier is ignored even with a matching entry.
        let (tx, _rx) = oneshot::channel();
        let (seq, _) = lock_registry(&registry).allocate(3, tx).unwrap();
        let other = echo_reply_packet(target, identifier.wrapping_add(1), seq, 3);
        assert!(!deliver_echo_reply(&registry, identifier, target, &other));
        assert!(lock_registry(&registry).entries.contains_key(&seq));
    }

    // ---- end-to-end deadline ---------------------------------------------------------

    fn target() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    #[tokio::test]
    async fn run_request_pending_send_stage_times_out() {
        let registry: SharedRegistry = Arc::new(Mutex::new(Registry::new()));
        let (tx, rx) = oneshot::channel();
        let (seq, id) = lock_registry(&registry).allocate(0, tx).unwrap();
        let guard = RegistryGuard {
            registry: Arc::clone(&registry),
            sequence: seq,
            request_id: id,
        };

        let started = Instant::now();
        let result = run_request(
            started + Duration::from_millis(50),
            futures::future::pending(),
            rx,
            target(),
            started,
        )
        .await;
        let reply = result.expect("timed out reply");
        assert_eq!(reply.status(), IcmpEchoStatus::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(150));

        drop(guard);
        assert!(lock_registry(&registry).entries.is_empty());
    }

    #[tokio::test]
    async fn run_request_no_reply_times_out_at_deadline() {
        let (_tx, rx) = oneshot::channel();
        let started = Instant::now();
        let reply = run_request(
            started + Duration::from_millis(50),
            async { Ok(()) },
            rx,
            target(),
            started,
        )
        .await
        .ok()
        .unwrap();
        assert_eq!(reply.status(), IcmpEchoStatus::TimedOut);
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(45) && elapsed < Duration::from_millis(150));
    }

    #[tokio::test]
    async fn run_request_reply_before_deadline() {
        let (tx, rx) = oneshot::channel();
        let started = Instant::now();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = tx.send(IcmpEchoReply::new(
                target(),
                IcmpEchoStatus::Success,
                Duration::from_millis(1),
            ));
        });
        let reply = run_request(
            started + Duration::from_millis(500),
            async { Ok(()) },
            rx,
            target(),
            started,
        )
        .await
        .ok()
        .unwrap();
        assert_eq!(reply.status(), IcmpEchoStatus::Success);
        assert!(started.elapsed() < Duration::from_millis(400));
    }

    #[tokio::test]
    async fn run_request_maps_send_errors() {
        let started = Instant::now();
        let (_tx, rx) = oneshot::channel();
        let reply = run_request(
            started + Duration::from_millis(500),
            async { Err(io::Error::from(io::ErrorKind::HostUnreachable)) },
            rx,
            target(),
            started,
        )
        .await
        .ok()
        .unwrap();
        assert_eq!(reply.status(), IcmpEchoStatus::Unreachable);

        let (_tx, rx) = oneshot::channel();
        let result = run_request(
            started + Duration::from_millis(500),
            async { Err(io::Error::other("boom")) },
            rx,
            target(),
            started,
        )
        .await;
        assert!(matches!(result, Err(RequestFailure::Send(ref e)) if e.to_string() == "boom"));
    }

    #[tokio::test]
    async fn run_request_slow_send_stage_is_bounded_by_deadline() {
        let (_tx, rx) = oneshot::channel();
        let started = Instant::now();
        let reply = run_request(
            started + Duration::from_millis(50),
            async {
                tokio::time::sleep(Duration::from_millis(200)).await;
                Ok(())
            },
            rx,
            target(),
            started,
        )
        .await
        .ok()
        .unwrap();
        assert_eq!(reply.status(), IcmpEchoStatus::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(150));
    }

    #[tokio::test]
    async fn run_request_reports_closed_reply_channel() {
        let (tx, rx) = oneshot::channel();
        let started = Instant::now();
        drop(tx);
        let result = run_request(
            started + Duration::from_millis(500),
            async { Ok(()) },
            rx,
            target(),
            started,
        )
        .await;
        assert!(matches!(result, Err(RequestFailure::ReplyChannelClosed)));
        assert!(started.elapsed() < Duration::from_millis(400));
    }

    async fn fatal_router_error_scenario(persist: bool) -> io::Error {
        let pinger = IcmpEchoRequestor::new(
            "127.0.0.1".parse().unwrap(),
            None,
            None,
            Some(Duration::from_secs(2)),
        )
        .unwrap();
        disable_router(&pinger);

        let waiter = {
            let pinger = pinger.clone();
            tokio::spawn(async move { pinger.send().await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(registry_len(&pinger), 1);

        if persist {
            fail_router(
                &pinger.inner.registry,
                &pinger.inner.router_context.failed,
                &io::Error::new(io::ErrorKind::PermissionDenied, "boom"),
            );
        } else {
            lock_registry(&pinger.inner.registry).entries.clear();
        }

        let started = Instant::now();
        let result = waiter.await.unwrap();
        assert!(started.elapsed() < Duration::from_millis(500));
        result.expect_err("closed channel must surface as an error")
    }

    #[tokio::test]
    async fn fatal_router_error_reaches_waiting_send() {
        let err = fatal_router_error_scenario(true).await;
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(err.to_string(), "boom");

        let err = fatal_router_error_scenario(false).await;
        assert_eq!(err.to_string(), "reply channel closed");
    }
}
