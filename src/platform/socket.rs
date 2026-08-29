// platform/socket.rs

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::channel::oneshot;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::Interest;
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

/// Serializes error-queue draining with its publication (and, in the router, with the
/// fatal/non-fatal classification). Never held across an `.await`.
type ErrQueueLock = Arc<Mutex<()>>;

fn lock_errqueue(lock: &ErrQueueLock) -> MutexGuard<'_, ()> {
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// State shared between the requestor's `send()` path and the router task.
struct RouterContext {
    target_addr: IpAddr,
    socket: Arc<UdpSocket>,
    registry: SharedRegistry,
    failed: SharedFailure,
    /// Number of supported ICMP error-queue messages drained by anyone (router or
    /// `send()`), published under `errqueue_lock`. Always 0 on macOS.
    errqueue_drained: Arc<AtomicUsize>,
    errqueue_lock: ErrQueueLock,
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
            errqueue_drained: Arc::new(AtomicUsize::new(0)),
            errqueue_lock: Arc::new(Mutex::new(())),
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
    /// # Platform Notes
    ///
    /// On Linux, ICMP Destination Unreachable / Time Exceeded messages are received through
    /// the socket error queue (`IP_RECVERR` / `IPV6_RECVERR`) and reported as
    /// `Unreachable` / `TimedOut` before the local timeout, like on macOS. The other ICMP
    /// errors that embed the request (Parameter Problem, ICMPv6 Packet Too Big) resolve it
    /// as `Unknown`, as on Windows.
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
        let send_stage = self.send_stage(packet.as_bytes(), target);

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

    /// The send stage of one request: a single `send_to` on macOS.
    #[cfg(not(target_os = "linux"))]
    async fn send_stage(&self, bytes: &[u8], target: SocketAddr) -> io::Result<()> {
        self.inner.socket.send_to(bytes, target).await.map(|_| ())
    }

    /// The send stage of one request on Linux: `send_to`, retried exactly once after
    /// draining the error queue.
    ///
    /// With `IP_RECVERR` enabled every ICMP error also sets the socket's one-shot `sk_err`,
    /// and the kernel's send path consumes it (`sock_alloc_send_pskb` returns and clears a
    /// pending error) *after* the route lookup succeeded. So a `send_to` failure is either a
    /// genuine local error for this destination — which repeats on retry — or another
    /// request's swallowed ICMP errno, in which case the queued message still has to be
    /// dispatched to its own waiter and the retry succeeds.
    #[cfg(target_os = "linux")]
    async fn send_stage(&self, bytes: &[u8], target: SocketAddr) -> io::Result<()> {
        if self.inner.socket.send_to(bytes, target).await.is_ok() {
            return Ok(());
        }
        let ctx = &self.inner.router_context;
        let infos = {
            let _guard = lock_errqueue(&ctx.errqueue_lock);
            let infos = errqueue::drain(self.inner.socket.as_raw_fd(), ctx.target_addr);
            ctx.errqueue_drained
                .fetch_add(infos.len(), Ordering::SeqCst);
            infos
        };
        for info in &infos {
            deliver_error(&ctx.registry, self.inner.identifier, ctx.target_addr, info);
        }
        self.inner.socket.send_to(bytes, target).await.map(|_| ())
    }

    fn ensure_router_running(&self) {
        let ctx = &self.inner.router_context;
        let socket = Arc::clone(&ctx.socket);
        let state = RouterState {
            registry: Arc::clone(&ctx.registry),
            failed: Arc::clone(&ctx.failed),
            errqueue_drained: Arc::clone(&ctx.errqueue_drained),
            errqueue_lock: Arc::clone(&ctx.errqueue_lock),
            identifier: self.inner.identifier,
            target_addr: ctx.target_addr,
            last_gen: 0,
            fatal_streak: 0,
        };

        self.inner.router_abort.get_or_init(|| {
            let handle = tokio::spawn(reply_router_loop(socket, state));
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

/// Delivers an ICMP error (Destination Unreachable, Time Exceeded, Parameter Problem,
/// Packet Too Big) that embedded one of our echo requests to the waiting request, matched
/// by identifier and sequence. ICMP errors carry only the embedded ICMP header, not the
/// payload, so they match on sequence alone.
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

/// Per-router state; the shared `Arc`s are the same instances as the requestor's.
struct RouterState {
    registry: SharedRegistry,
    failed: SharedFailure,
    errqueue_drained: Arc<AtomicUsize>,
    errqueue_lock: ErrQueueLock,
    identifier: u16,
    target_addr: IpAddr,
    /// `errqueue_drained` as observed by the previous handled wake.
    last_gen: usize,
    /// Consecutive wakes that ended in a fatal-kind receive error with nothing drained.
    fatal_streak: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouterStep {
    Continue,
    Exit,
}

/// What a readiness wake turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WakeAction {
    /// `try_recv` returned a datagram.
    Datagram,
    /// `try_recv` returned `WouldBlock`: drain the error queue, keep going.
    DrainAndContinue,
    /// `try_recv` returned an error: drain the error queue, then classify the error.
    DrainAndClassify,
}

fn wake_action(wake: &io::Result<usize>) -> WakeAction {
    match wake {
        Ok(_) => WakeAction::Datagram,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => WakeAction::DrainAndContinue,
        Err(_) => WakeAction::DrainAndClassify,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouterAction {
    Continue,
    Fatal,
}

/// Whether an error kind could mean the socket is unusable.
fn is_fatal_kind(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::PermissionDenied |        // Lost privileges
        io::ErrorKind::AddrNotAvailable |        // Address no longer available
        io::ErrorKind::ConnectionAborted |       // Socket forcibly closed
        io::ErrorKind::NotConnected // Socket disconnected
    )
}

/// Classifies a receive error. Returns the action and the new fatal streak.
///
/// A socket's `sk_err` is a one-shot value consumed by the failing receive, and on a ping
/// socket every value the router can see is derived from a queued ICMP error (with
/// `IP_RECVERR` even an IPv6 "administratively prohibited" surfaces as `EACCES` /
/// `PermissionDenied`). After one error read, a healthy socket's next receive yields a
/// datagram or `WouldBlock`; only an unusable socket fails again. So:
///
/// 1. anything drained from the error queue since the last wake → `Continue`, streak reset;
/// 2. otherwise a fatal-kind error increments the streak and is `Fatal` only on the second
///    consecutive observation;
/// 3. any other error → `Continue`, streak reset.
fn router_action(
    kind: io::ErrorKind,
    drained_since_last_wake: usize,
    fatal_streak: u8,
) -> (RouterAction, u8) {
    if drained_since_last_wake > 0 {
        return (RouterAction::Continue, 0);
    }
    if is_fatal_kind(kind) {
        let streak = fatal_streak.saturating_add(1);
        if streak >= 2 {
            (RouterAction::Fatal, streak)
        } else {
            (RouterAction::Continue, streak)
        }
    } else {
        (RouterAction::Continue, 0)
    }
}

/// Handles one readiness wake of the router. `wake` is the `try_recv` result (`buf[..n]`
/// holds the datagram on `Ok(n)`); `drain` removes and parses the error-queue messages
/// (production: `errqueue::drain`, a no-op on macOS).
fn handle_wake(
    state: &mut RouterState,
    wake: io::Result<usize>,
    buf: &[u8],
    drain: &mut dyn FnMut() -> Vec<IcmpErrorInfo>,
) -> RouterStep {
    let action = wake_action(&wake);

    if let (WakeAction::Datagram, Ok(size)) = (action, &wake) {
        let data = &buf[..*size];
        if let Some(reply_packet) = IcmpPacket::parse_reply(data, state.target_addr) {
            deliver_echo_reply(
                &state.registry,
                state.identifier,
                state.target_addr,
                &reply_packet,
            );
        } else if let Some(error_info) = IcmpPacket::parse_error_reply(data, state.target_addr) {
            deliver_error(
                &state.registry,
                state.identifier,
                state.target_addr,
                &error_info,
            );
        }
        state.last_gen = state.errqueue_drained.load(Ordering::SeqCst);
        state.fatal_streak = 0;
        return RouterStep::Continue;
    }

    // Non-datagram wake: drain, publish and (for a real error) classify — all under the
    // error-queue lock so a message removed by a concurrent `send()` drain is always
    // published before we classify. Dispatch happens after the lock is released.
    let (infos, router_action) = {
        let _guard = lock_errqueue(&state.errqueue_lock);
        let infos = drain();
        state
            .errqueue_drained
            .fetch_add(infos.len(), Ordering::SeqCst);
        let now = state.errqueue_drained.load(Ordering::SeqCst);
        let drained_since_last_wake = now.wrapping_sub(state.last_gen);
        state.last_gen = now;

        let router_action = match (action, &wake) {
            (WakeAction::DrainAndClassify, Err(e)) => {
                let (router_action, streak) =
                    router_action(e.kind(), drained_since_last_wake, state.fatal_streak);
                state.fatal_streak = streak;
                router_action
            }
            _ => {
                state.fatal_streak = 0;
                RouterAction::Continue
            }
        };
        (infos, router_action)
    };

    for info in &infos {
        deliver_error(&state.registry, state.identifier, state.target_addr, info);
    }

    match (router_action, wake) {
        (RouterAction::Fatal, Err(e)) => {
            fail_router(&state.registry, &state.failed, &e);
            RouterStep::Exit
        }
        _ => RouterStep::Continue,
    }
}

/// One non-blocking receive through Tokio's readiness bookkeeping.
///
/// The router waits on `READABLE | ERROR` because a queued ICMP error surfaces as
/// `EPOLLERR`, which Tokio reports as error readiness, not read readiness. `try_io` only
/// understands a single interest, so on `WouldBlock` the `ERROR` bit is cleared separately;
/// the caller drains the error queue right after, and an error queued after this point
/// arrives with a newer readiness tick, so no wake can be lost — and without the clear the
/// router would spin on a permanently set `ERROR` bit.
fn try_receive(
    socket: &UdpSocket,
    scratch: &mut [MaybeUninit<u8>],
    buf: &mut [u8],
) -> io::Result<usize> {
    let received = match socket.try_io(Interest::READABLE, || {
        socket2::SockRef::from(socket).recv(scratch)
    }) {
        Ok(received) => received,
        Err(e) => {
            if e.kind() == io::ErrorKind::WouldBlock {
                let _ = socket.try_io(Interest::ERROR, || {
                    Err::<(), io::Error>(io::ErrorKind::WouldBlock.into())
                });
            }
            return Err(e);
        }
    };
    let received = received.min(buf.len());
    // SAFETY: `recv` initialised the first `received` bytes of `scratch`.
    let initialised =
        unsafe { std::slice::from_raw_parts(scratch.as_ptr().cast::<u8>(), received) };
    buf[..received].copy_from_slice(initialised);
    Ok(received)
}

async fn reply_router_loop(socket: Arc<UdpSocket>, mut state: RouterState) {
    let mut scratch: Vec<MaybeUninit<u8>> = vec![MaybeUninit::uninit(); 1024];
    let mut buf = vec![0u8; 1024];

    #[cfg(target_os = "linux")]
    let mut drain = {
        let fd = socket.as_raw_fd();
        let target_addr = state.target_addr;
        move || errqueue::drain(fd, target_addr)
    };
    #[cfg(not(target_os = "linux"))]
    let mut drain = Vec::new;

    loop {
        let wake = match socket.ready(Interest::READABLE | Interest::ERROR).await {
            Ok(_ready) => try_receive(&socket, &mut scratch, &mut buf),
            Err(e) => Err(e),
        };
        if handle_wake(&mut state, wake, &buf, &mut drain) == RouterStep::Exit {
            return;
        }
    }
}

/// Linux socket error queue: how ICMP errors reach a ping socket.
///
/// The kernel's `ping_err()` drops ICMP errors for an unconnected ping socket unless
/// `IP_RECVERR` / `IPV6_RECVERR` is set; with it, each error is queued to the socket's
/// error queue (readable with `recvmsg(MSG_ERRQUEUE)`) and `sk_err` is set, which the next
/// `recv` reports once. The queued message's data is the embedded original echo request
/// starting at its ICMP header, and the `sock_extended_err` control message carries the
/// origin and the ICMP type.
#[cfg(target_os = "linux")]
mod errqueue {
    use std::io;
    use std::mem;
    use std::net::IpAddr;
    use std::os::fd::{AsRawFd, RawFd};
    use std::ptr;

    use socket2::Socket;

    use crate::icmp::{IcmpErrorInfo, IcmpPacket};

    /// Enables delivery of ICMP errors through the socket error queue.
    pub(super) fn set_recverr(socket: &Socket, is_ipv6: bool) -> io::Result<()> {
        let (level, name) = if is_ipv6 {
            (libc::SOL_IPV6, libc::IPV6_RECVERR)
        } else {
            (libc::SOL_IP, libc::IP_RECVERR)
        };
        let enable: libc::c_int = 1;
        // SAFETY: plain setsockopt on a valid descriptor with a correctly sized value.
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                level,
                name,
                &enable as *const libc::c_int as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Interprets one error-queue message: `origin` / `ee_type` from the
    /// `sock_extended_err` control message, `data` = the message payload (the embedded
    /// echo request starting at its ICMP header). Only ICMP-originated Destination
    /// Unreachable / Time Exceeded messages for our address family are reported.
    pub(super) fn parse_extended_error(
        origin: u8,
        ee_type: u8,
        data: &[u8],
        target_addr: IpAddr,
    ) -> Option<IcmpErrorInfo> {
        let expected_origin = if target_addr.is_ipv4() {
            libc::SO_EE_ORIGIN_ICMP
        } else {
            libc::SO_EE_ORIGIN_ICMP6
        };
        if origin != expected_origin {
            return None;
        }
        let status = IcmpPacket::error_status(target_addr, ee_type)?;
        let (identifier, sequence) = IcmpPacket::parse_embedded_echo_request(data, target_addr)?;
        Some(IcmpErrorInfo {
            identifier,
            sequence,
            status,
        })
    }

    /// Receives one message from the error queue without blocking.
    ///
    /// `Ok(None)`: the queue is empty. `Ok(Some(None))`: a message that is not a supported
    /// ICMP error. `Ok(Some(Some(info)))`: a supported ICMP error.
    fn recv_one(fd: RawFd, target_addr: IpAddr) -> io::Result<Option<Option<IcmpErrorInfo>>> {
        let mut data = [0u8; 1500];
        // 8-byte aligned control buffer (cmsghdr alignment).
        let mut control = [0u64; 64];

        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr() as *mut libc::c_void,
            iov_len: data.len(),
        };
        // SAFETY: msghdr is plain data; all pointers reference live local buffers.
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = mem::size_of_val(&control) as _;

        // SAFETY: valid descriptor and a fully initialised msghdr.
        let received =
            unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT) };
        if received < 0 {
            let err = io::Error::last_os_error();
            return if err.kind() == io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(err)
            };
        }
        let received = received as usize;

        // SAFETY: CMSG_* walk the control buffer described by `msg`, which is still alive.
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        while !cmsg.is_null() {
            let header: libc::cmsghdr = unsafe { ptr::read_unaligned(cmsg) };
            let is_recverr = (header.cmsg_level == libc::SOL_IP
                && header.cmsg_type == libc::IP_RECVERR)
                || (header.cmsg_level == libc::SOL_IPV6 && header.cmsg_type == libc::IPV6_RECVERR);
            if is_recverr {
                let ee: libc::sock_extended_err =
                    unsafe { ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const _) };
                return Ok(Some(parse_extended_error(
                    ee.ee_origin,
                    ee.ee_type,
                    &data[..received],
                    target_addr,
                )));
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
        }
        Ok(Some(None))
    }

    /// Removes every queued message and returns the supported ICMP errors among them.
    /// Never blocks; stops at `EAGAIN` or any other receive error.
    pub(super) fn drain(fd: RawFd, target_addr: IpAddr) -> Vec<IcmpErrorInfo> {
        let mut infos = Vec::new();
        loop {
            match recv_one(fd, target_addr) {
                Ok(Some(Some(info))) => infos.push(info),
                Ok(Some(None)) => continue,
                Ok(None) | Err(_) => break,
            }
        }
        infos
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

    // Without this the Linux kernel silently drops ICMP errors for the socket.
    #[cfg(target_os = "linux")]
    errqueue::set_recverr(&socket, target_addr.is_ipv6())?;

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

    fn target() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    const TEST_IDENTIFIER: u16 = 0x1234;

    fn test_state() -> RouterState {
        RouterState {
            registry: Arc::new(Mutex::new(Registry::new())),
            failed: Arc::new(Mutex::new(None)),
            errqueue_drained: Arc::new(AtomicUsize::new(0)),
            errqueue_lock: Arc::new(Mutex::new(())),
            identifier: TEST_IDENTIFIER,
            target_addr: target(),
            last_gen: 0,
            fatal_streak: 0,
        }
    }

    fn register(state: &RouterState, ts: u64) -> (u16, oneshot::Receiver<IcmpEchoReply>) {
        let (tx, rx) = oneshot::channel();
        let (seq, _) = lock_registry(&state.registry).allocate(ts, tx).unwrap();
        (seq, rx)
    }

    fn no_drain() -> Vec<IcmpErrorInfo> {
        Vec::new()
    }

    fn err(kind: io::ErrorKind) -> io::Result<usize> {
        Err(io::Error::from(kind))
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

    // `IcmpEchoRequestor::new` registers the socket with the Tokio reactor, so this
    // needs a runtime even though nothing is awaited.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn recv_buffer_is_enlarged_on_macos() {
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
        let target = target();
        let identifier = TEST_IDENTIFIER;
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

    // ---- router wake handling --------------------------------------------------------

    #[test]
    fn router_action_table() {
        use io::ErrorKind::*;
        use RouterAction::*;
        assert_eq!(router_action(PermissionDenied, 0, 0), (Continue, 1));
        assert_eq!(router_action(PermissionDenied, 0, 1), (Fatal, 2));
        assert_eq!(router_action(PermissionDenied, 1, 1), (Continue, 0));
        assert_eq!(router_action(HostUnreachable, 0, 0), (Continue, 0));
        assert_eq!(router_action(HostUnreachable, 0, 7), (Continue, 0));
        assert_eq!(router_action(NetworkUnreachable, 0, 0), (Continue, 0));
        assert_eq!(router_action(ConnectionRefused, 0, 0), (Continue, 0));
        assert_eq!(router_action(Other, 0, 0), (Continue, 0));
        assert_eq!(router_action(AddrNotAvailable, 0, 1), (Fatal, 2));
        assert_eq!(router_action(ConnectionAborted, 0, 1), (Fatal, 2));
        assert_eq!(router_action(NotConnected, 0, 1), (Fatal, 2));
        assert_eq!(router_action(NotConnected, 3, 1), (Continue, 0));
    }

    #[test]
    fn wake_action_table() {
        assert_eq!(wake_action(&Ok(64)), WakeAction::Datagram);
        assert_eq!(
            wake_action(&err(io::ErrorKind::WouldBlock)),
            WakeAction::DrainAndContinue
        );
        assert_eq!(
            wake_action(&err(io::ErrorKind::HostUnreachable)),
            WakeAction::DrainAndClassify
        );
        assert_eq!(
            wake_action(&err(io::ErrorKind::PermissionDenied)),
            WakeAction::DrainAndClassify
        );
    }

    #[test]
    fn cross_drainer_interleaving_never_fatal_on_first_sight() {
        // (i) The send() path removed the message but has not published yet.
        let mut state = test_state();
        let (seq, _rx) = register(&state, 1);
        let step = handle_wake(
            &mut state,
            err(io::ErrorKind::PermissionDenied),
            &[],
            &mut no_drain,
        );
        assert_eq!(step, RouterStep::Continue);
        assert_eq!(state.fatal_streak, 1);
        assert!(lock_registry(&state.registry).entries.contains_key(&seq));
        assert!(lock_failure(&state.failed).is_none());

        // (ii) Publication lands between the wakes; the next wake counts it.
        state.errqueue_drained.fetch_add(1, Ordering::SeqCst);
        let step = handle_wake(
            &mut state,
            err(io::ErrorKind::PermissionDenied),
            &[],
            &mut no_drain,
        );
        assert_eq!(step, RouterStep::Continue);
        assert_eq!(state.fatal_streak, 0);
        assert_eq!(state.last_gen, 1);
        assert!(lock_registry(&state.registry).entries.contains_key(&seq));
        assert!(lock_failure(&state.failed).is_none());

        // (iii) Control: two consecutive fatal-kind errors with nothing published.
        let mut state = test_state();
        let (seq, _rx) = register(&state, 1);
        let first = handle_wake(
            &mut state,
            err(io::ErrorKind::PermissionDenied),
            &[],
            &mut no_drain,
        );
        assert_eq!(first, RouterStep::Continue);
        let second = handle_wake(
            &mut state,
            err(io::ErrorKind::PermissionDenied),
            &[],
            &mut no_drain,
        );
        assert_eq!(second, RouterStep::Exit);
        assert!(!lock_registry(&state.registry).entries.contains_key(&seq));
        let failed = lock_failure(&state.failed);
        assert_eq!(
            failed.as_ref().map(|e| e.kind),
            Some(io::ErrorKind::PermissionDenied)
        );
        drop(failed);

        // (iv) A healthy read in between resets the streak.
        let mut state = test_state();
        let (_seq, _rx) = register(&state, 1);
        assert_eq!(
            handle_wake(
                &mut state,
                err(io::ErrorKind::PermissionDenied),
                &[],
                &mut no_drain
            ),
            RouterStep::Continue
        );
        assert_eq!(
            handle_wake(
                &mut state,
                err(io::ErrorKind::WouldBlock),
                &[],
                &mut no_drain
            ),
            RouterStep::Continue
        );
        assert_eq!(state.fatal_streak, 0);
        assert_eq!(
            handle_wake(
                &mut state,
                err(io::ErrorKind::PermissionDenied),
                &[],
                &mut no_drain
            ),
            RouterStep::Continue
        );
        assert!(lock_failure(&state.failed).is_none());
    }

    /// (v) Two consecutive fatal-kind wakes while a send-side batch is still unpublished:
    /// the router's second wake must block on `errqueue_lock` until the batch is published.
    fn blocked_second_wake(publish: bool) -> (RouterState, RouterStep) {
        let mut state = test_state();
        let (_seq, _rx) = register(&state, 1);
        assert_eq!(
            handle_wake(
                &mut state,
                err(io::ErrorKind::PermissionDenied),
                &[],
                &mut no_drain
            ),
            RouterStep::Continue
        );
        assert_eq!(state.fatal_streak, 1);

        let lock = Arc::clone(&state.errqueue_lock);
        let counter = Arc::clone(&state.errqueue_drained);
        // Simulate a send() drain that removed two messages but has not published.
        let guard = lock.lock().unwrap();

        let worker = std::thread::spawn(move || {
            let step = handle_wake(
                &mut state,
                err(io::ErrorKind::PermissionDenied),
                &[],
                &mut no_drain,
            );
            (state, step)
        });
        std::thread::sleep(Duration::from_millis(50));
        assert!(!worker.is_finished(), "second wake must block on the lock");

        if publish {
            counter.fetch_add(2, Ordering::SeqCst);
        }
        drop(guard);
        worker.join().unwrap()
    }

    #[test]
    fn blocked_wake_sees_publication_before_classifying() {
        let (state, step) = blocked_second_wake(true);
        assert_eq!(step, RouterStep::Continue);
        assert_eq!(state.fatal_streak, 0);
        assert_eq!(state.last_gen, 2);
        assert_eq!(lock_registry(&state.registry).entries.len(), 1);
        assert!(lock_failure(&state.failed).is_none());

        // Control: released without publishing -> the outcome hinges on publication.
        let (state, step) = blocked_second_wake(false);
        assert_eq!(step, RouterStep::Exit);
        assert!(lock_registry(&state.registry).entries.is_empty());
        assert!(lock_failure(&state.failed).is_some());
    }

    #[test]
    fn would_block_wake_drains_and_dispatches() {
        for kind in [io::ErrorKind::WouldBlock, io::ErrorKind::HostUnreachable] {
            let mut state = test_state();
            let (seq, mut rx) = register(&state, 1);
            let calls = std::cell::Cell::new(0);
            let mut drain = || {
                calls.set(calls.get() + 1);
                vec![IcmpErrorInfo {
                    identifier: TEST_IDENTIFIER,
                    sequence: seq,
                    status: IcmpEchoStatus::Unreachable,
                }]
            };
            let step = handle_wake(&mut state, err(kind), &[], &mut drain);
            assert_eq!(step, RouterStep::Continue, "{kind:?}");
            assert_eq!(calls.get(), 1, "drainer called exactly once ({kind:?})");
            let reply = rx.try_recv().unwrap().expect("waiter resolved");
            assert_eq!(reply.status(), IcmpEchoStatus::Unreachable);
            assert!(!lock_registry(&state.registry).entries.contains_key(&seq));
            assert_eq!(state.errqueue_drained.load(Ordering::SeqCst), 1);
            assert_eq!(state.last_gen, 1);
            assert!(lock_failure(&state.failed).is_none());
        }

        // Negative control: a datagram wake never drains.
        let mut state = test_state();
        let (seq, mut rx) = register(&state, 7);
        let packet = echo_reply_packet(target(), TEST_IDENTIFIER, seq, 7);
        let mut buf = vec![0u8; 1024];
        let bytes = packet.as_bytes();
        // On macOS parse_reply expects an outer IPv4 header; build the datagram the way the
        // kernel delivers it on this platform.
        let datagram: Vec<u8> = if cfg!(target_os = "macos") {
            let mut d = vec![0x45u8; 1];
            d.extend_from_slice(&[0u8; 19]);
            d.extend_from_slice(bytes);
            d
        } else {
            bytes.to_vec()
        };
        buf[..datagram.len()].copy_from_slice(&datagram);
        let mut drain = || panic!("drainer must not be called for a datagram");
        let step = handle_wake(&mut state, Ok(datagram.len()), &buf, &mut drain);
        assert_eq!(step, RouterStep::Continue);
        let reply = rx.try_recv().unwrap().expect("echo reply delivered");
        assert_eq!(reply.status(), IcmpEchoStatus::Success);
        assert_eq!(state.errqueue_drained.load(Ordering::SeqCst), 0);
    }

    // ---- Linux error queue -----------------------------------------------------------

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use crate::platform::socket::errqueue::parse_extended_error;

        fn embedded_echo(is_v6: bool, identifier: u16, sequence: u16) -> Vec<u8> {
            let mut d = vec![if is_v6 { 128u8 } else { 8u8 }, 0, 0, 0];
            d.extend_from_slice(&identifier.to_be_bytes());
            d.extend_from_slice(&sequence.to_be_bytes());
            d.extend_from_slice(&[0u8; 8]); // timestamp payload, if present
            d
        }

        #[test]
        fn parse_extended_error_table() {
            let v4: IpAddr = "127.0.0.1".parse().unwrap();
            let v6: IpAddr = "::1".parse().unwrap();

            let info =
                parse_extended_error(libc::SO_EE_ORIGIN_ICMP, 3, &embedded_echo(false, 1, 2), v4)
                    .unwrap();
            assert_eq!(
                (info.identifier, info.sequence, info.status),
                (1, 2, IcmpEchoStatus::Unreachable)
            );
            let info =
                parse_extended_error(libc::SO_EE_ORIGIN_ICMP, 11, &embedded_echo(false, 3, 4), v4)
                    .unwrap();
            assert_eq!(
                (info.identifier, info.sequence, info.status),
                (3, 4, IcmpEchoStatus::TimedOut)
            );
            let info =
                parse_extended_error(libc::SO_EE_ORIGIN_ICMP6, 1, &embedded_echo(true, 5, 6), v6)
                    .unwrap();
            assert_eq!(
                (info.identifier, info.sequence, info.status),
                (5, 6, IcmpEchoStatus::Unreachable)
            );
            let info =
                parse_extended_error(libc::SO_EE_ORIGIN_ICMP6, 3, &embedded_echo(true, 7, 8), v6)
                    .unwrap();
            assert_eq!(
                (info.identifier, info.sequence, info.status),
                (7, 8, IcmpEchoStatus::TimedOut)
            );
            // Parameter Problem (v4 type 12) and Packet Too Big / Parameter Problem
            // (v6 types 2 / 4) resolve the request as Unknown instead of being dropped.
            let info = parse_extended_error(
                libc::SO_EE_ORIGIN_ICMP,
                12,
                &embedded_echo(false, 9, 10),
                v4,
            )
            .unwrap();
            assert_eq!(
                (info.identifier, info.sequence, info.status),
                (9, 10, IcmpEchoStatus::Unknown)
            );
            for ee_type in [2u8, 4u8] {
                let info = parse_extended_error(
                    libc::SO_EE_ORIGIN_ICMP6,
                    ee_type,
                    &embedded_echo(true, 11, 12),
                    v6,
                )
                .unwrap();
                assert_eq!(
                    (info.identifier, info.sequence, info.status),
                    (11, 12, IcmpEchoStatus::Unknown),
                    "ee_type {ee_type}"
                );
            }

            // Wrong origin, unsupported type (Redirect), short data, non-echo type byte
            assert!(parse_extended_error(
                libc::SO_EE_ORIGIN_LOCAL,
                3,
                &embedded_echo(false, 1, 2),
                v4
            )
            .is_none());
            assert!(parse_extended_error(
                libc::SO_EE_ORIGIN_ICMP6,
                1,
                &embedded_echo(false, 1, 2),
                v4
            )
            .is_none());
            assert!(parse_extended_error(
                libc::SO_EE_ORIGIN_ICMP,
                5,
                &embedded_echo(false, 1, 2),
                v4
            )
            .is_none());
            assert!(parse_extended_error(
                libc::SO_EE_ORIGIN_ICMP,
                3,
                &embedded_echo(false, 1, 2)[..7],
                v4
            )
            .is_none());
            let mut reply = embedded_echo(false, 1, 2);
            reply[0] = 0;
            assert!(parse_extended_error(libc::SO_EE_ORIGIN_ICMP, 3, &reply, v4).is_none());
        }

        fn env_target(var: &str) -> Option<IpAddr> {
            match std::env::var(var) {
                Ok(v) => Some(v.parse().expect("valid IP address")),
                Err(_) => {
                    eprintln!("{var} not set; skipping");
                    None
                }
            }
        }

        /// Run in WSL2 / on a LAN as
        /// `PING_ASYNC_UNREACHABLE_TARGET=<unused on-link IPv4 address> cargo test -- --ignored`
        /// (ARP failure -> ICMP Host Unreachable after ~3 s) and
        /// `PING_ASYNC_TTL1_TARGET=<remote host>` (Time Exceeded from the first gateway).
        #[tokio::test]
        #[ignore]
        async fn icmp_errors_arrive_before_local_timeout() {
            let timeout = Duration::from_secs(6);
            let cases = [
                (
                    "PING_ASYNC_UNREACHABLE_TARGET",
                    None,
                    IcmpEchoStatus::Unreachable,
                    timeout,
                ),
                (
                    "PING_ASYNC_TTL1_TARGET",
                    Some(1u8),
                    IcmpEchoStatus::TimedOut,
                    Duration::from_secs(1),
                ),
            ];
            for (var, ttl, expected, bound) in cases {
                let Some(target) = env_target(var) else {
                    continue;
                };
                let pinger = IcmpEchoRequestor::new(target, None, ttl, Some(timeout)).unwrap();

                for round in 1..=2 {
                    let started = Instant::now();
                    let reply = pinger.send().await.unwrap();
                    let elapsed = started.elapsed();
                    println!("{var} round {round}: {reply:?} after {elapsed:?}");
                    assert_eq!(reply.status(), expected, "{var} round {round}");
                    assert!(elapsed < bound, "{var} round {round} took {elapsed:?}");
                    assert_eq!(registry_len(&pinger), 0);
                }
                assert!(
                    pinger
                        .inner
                        .router_context
                        .errqueue_drained
                        .load(Ordering::SeqCst)
                        >= 1,
                    "{var}: errors must have come through the error queue"
                );
            }
        }

        /// One concurrent-send run: `count` requests are started `spacing` apart while ICMP
        /// errors arrive for the earlier ones (the sk_err-swallowed-by-sendmsg scenario).
        /// Every request must resolve through an ICMP error — never through the local
        /// timeout, which is what a swallowed `sk_err` without a following drain looks like.
        /// The two outcomes share the `TimedOut` status for Time Exceeded, so they are told
        /// apart by elapsed time (`bound` is well below the local timeout).
        async fn concurrent_scenario(
            target: IpAddr,
            ttl: Option<u8>,
            count: usize,
            spacing: Duration,
            bound: Duration,
        ) {
            let timeout = Duration::from_secs(8);
            let pinger = IcmpEchoRequestor::new(target, None, ttl, Some(timeout)).unwrap();

            let mut handles = Vec::with_capacity(count);
            let started = Instant::now();
            for _ in 0..count {
                let p = pinger.clone();
                handles.push(tokio::spawn(async move {
                    let t0 = Instant::now();
                    let reply = p.send().await;
                    (reply, t0.elapsed())
                }));
                tokio::time::sleep(spacing).await;
            }

            let (mut icmp_errors, mut late, mut other) = (0usize, 0usize, 0usize);
            for handle in handles {
                let (reply, elapsed) = handle.await.unwrap();
                let reply = reply.expect("send() must not error");
                match reply.status() {
                    IcmpEchoStatus::TimedOut | IcmpEchoStatus::Unreachable if elapsed < bound => {
                        icmp_errors += 1
                    }
                    IcmpEchoStatus::TimedOut => late += 1,
                    _ => other += 1,
                }
            }
            let drained = pinger
                .inner
                .router_context
                .errqueue_drained
                .load(Ordering::SeqCst);
            println!(
                "{target} ttl={ttl:?}: icmp_errors={icmp_errors} late={late} other={other}                  drained={drained} in {:?}",
                started.elapsed()
            );
            assert_eq!(other, 0);
            assert_eq!(
                late, 0,
                "a request hit the local timeout: swallowed error not dispatched?"
            );
            assert_eq!(icmp_errors, count);
            assert!(drained >= count, "drained={drained}");
            assert_eq!(registry_len(&pinger), 0);
        }

        /// Concurrent sends while ICMP errors arrive. Run with
        /// `PING_ASYNC_TTL1_TARGET=<remote host>` (200 requests 20 ms apart, one Time
        /// Exceeded from the first gateway each — the high-rate variant) and/or
        /// `PING_ASYNC_UNREACHABLE_TARGET=<unused on-link IPv4 address>` (40 requests 100 ms
        /// apart). The ARP-failure variant must stay slow: `neigh_invalidate` emits all
        /// queued Host Unreachables in one burst and the kernel's global ICMP rate limiter
        /// (`net.ipv4.icmp_msgs_burst`, default 50) silently drops the rest before they
        /// reach any socket — a kernel property, not an error-queue loss.
        #[tokio::test]
        #[ignore]
        async fn concurrent_sends_during_icmp_errors() {
            let mut ran = false;
            if let Some(target) = env_target("PING_ASYNC_TTL1_TARGET") {
                concurrent_scenario(
                    target,
                    Some(1),
                    200,
                    Duration::from_millis(20),
                    Duration::from_secs(2),
                )
                .await;
                ran = true;
            }
            if let Some(target) = env_target("PING_ASYNC_UNREACHABLE_TARGET") {
                concurrent_scenario(
                    target,
                    None,
                    40,
                    Duration::from_millis(100),
                    Duration::from_secs(6),
                )
                .await;
                ran = true;
            }
            assert!(
                ran,
                "set PING_ASYNC_TTL1_TARGET and/or PING_ASYNC_UNREACHABLE_TARGET"
            );
        }
    }
}
