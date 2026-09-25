// platform/socket.rs

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::channel::oneshot;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::time::{self, Instant};

use crate::{
    icmp::{IcmpErrorInfo, IcmpPacket},
    IcmpEchoReply, IcmpEchoStatus, IcmpOutcome, PING_DEFAULT_REQUEST_DATA_LENGTH,
    PING_DEFAULT_TIMEOUT, PING_DEFAULT_TTL, PING_MAX_REQUEST_DATA_LENGTH,
    PING_MIN_REQUEST_DATA_LENGTH,
};

/// Receive buffer requested for the ICMP socket. On macOS every ICMP `SOCK_DGRAM` socket
/// receives every echo reply on the host and the default 8 KiB buffer overflows under
/// bursts, dropping the socket's own replies.
const RECV_BUFFER_SIZE: usize = 1 << 20;

struct SequenceSpace {
    next: AtomicU32,
}

impl SequenceSpace {
    fn new(start: u32) -> Self {
        Self {
            next: AtomicU32::new(start),
        }
    }

    fn allocate(&self) -> io::Result<u16> {
        self.next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                (value <= u32::from(u16::MAX)).then_some(value + 1)
            })
            .map(|value| value as u16)
            .map_err(|_| io::Error::other("ICMP sequence space is exhausted"))
    }
}

static SHORT_SEQUENCE_SPACE: OnceLock<SequenceSpace> = OnceLock::new();

fn allocate_short_sequence() -> io::Result<u16> {
    static RANDOM_START: OnceLock<u16> = OnceLock::new();
    SHORT_SEQUENCE_SPACE
        .get_or_init(|| SequenceSpace::new(u32::from(*RANDOM_START.get_or_init(rand::random))))
        .allocate()
}

/// One in-flight request registered under its ICMP sequence number.
struct RegistryEntry {
    /// Unique per request for the lifetime of the requestor; lets a guard tell its own
    /// entry apart from any replacement under the same key.
    request_id: u64,
    sent_timestamp: u64,
    sent_payload: Vec<u8>,
    payload_len: usize,
    tx: oneshot::Sender<IcmpEchoReply>,
}

/// Registry of in-flight requests plus the allocation state for sequence numbers.
struct Registry {
    next_sequence: Option<u16>,
    next_request_id: u64,
    entries: HashMap<u16, RegistryEntry>,
}

impl Registry {
    fn new() -> Self {
        Registry {
            next_sequence: Some(0),
            next_request_id: 1,
            entries: HashMap::new(),
        }
    }

    /// Allocates a sequence number that is not currently in flight and registers the
    /// request under it. Returns the sequence number and the request's unique id.
    ///
    /// Long-payload sequence numbers are monotonic for the lifetime of the requestor and
    /// are never reused. Short-payload sequence numbers come from a process-wide
    /// non-reusing space. Both policies are required because ICMP errors do not echo the
    /// request payload.
    fn allocate(
        &mut self,
        sent_timestamp: u64,
        payload_len: usize,
        tx: oneshot::Sender<IcmpEchoReply>,
    ) -> io::Result<(u16, u64)> {
        let mut candidate = if payload_len < 8 {
            allocate_short_sequence()?
        } else {
            self.next_sequence
                .ok_or_else(|| io::Error::other("ICMP sequence space is exhausted"))?
        };
        for _ in 0..=usize::from(u16::MAX) {
            match self.entries.entry(candidate) {
                Entry::Vacant(vacant) => {
                    let request_id = self.next_request_id;
                    self.next_request_id += 1;
                    let mut sent_payload = vec![0u8; payload_len];
                    if payload_len >= 8 {
                        sent_payload[..8].copy_from_slice(&sent_timestamp.to_be_bytes());
                    }
                    vacant.insert(RegistryEntry {
                        request_id,
                        sent_timestamp,
                        sent_payload,
                        payload_len,
                        tx,
                    });
                    if payload_len >= 8 {
                        self.next_sequence = candidate.checked_add(1);
                    }
                    return Ok((candidate, request_id));
                }
                Entry::Occupied(_) if payload_len >= 8 => {
                    self.next_sequence = candidate.checked_add(1);
                    candidate = self
                        .next_sequence
                        .ok_or_else(|| io::Error::other("ICMP sequence space is exhausted"))?;
                }
                Entry::Occupied(_) => {
                    candidate = candidate.wrapping_add(1);
                }
            }
        }
        Err(io::Error::other("ICMP sequence space is exhausted"))
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
    /// Number of error-queue messages removed by anyone (router or `send()`) — every
    /// message, whether or not it is a supported ICMP error — published under
    /// `errqueue_lock`. A removed message is what explains a one-shot `sk_err` observed
    /// by a receive or a send. Always 0 on macOS.
    errqueue_drained: Arc<AtomicUsize>,
    errqueue_lock: ErrQueueLock,
}

/// What one drain of the error queue removed: every message (`removed`, including ones
/// that are not supported ICMP errors, such as a Redirect queued with `EREMOTEIO`) and
/// the supported ICMP errors among them, ready to dispatch.
#[derive(Default)]
struct Drained {
    removed: usize,
    infos: Vec<IcmpErrorInfo>,
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
    sequence: u16,
    started_at: Instant,
) -> Result<IcmpEchoReply, RequestFailure> {
    // Invoked at the moment a deadline is observed to have passed; the completion instant
    // is taken before the elapsed time is read so that it records that observation.
    let timed_out = || {
        let completed_at = std::time::Instant::now();
        IcmpEchoReply::with_evidence(
            target_addr,
            IcmpEchoStatus::TimedOut,
            IcmpOutcome::LocalTimeout,
            None,
            Some(sequence),
            started_at.elapsed(),
            completed_at,
        )
    };

    match time::timeout_at(deadline, send_stage).await {
        Err(_elapsed) => return Ok(timed_out()),
        Ok(Err(e)) => {
            return match e.kind() {
                io::ErrorKind::NetworkUnreachable
                | io::ErrorKind::NetworkDown
                | io::ErrorKind::HostUnreachable => {
                    // The send failure has been classified as an echo outcome.
                    let outcome = match e.kind() {
                        io::ErrorKind::HostUnreachable => IcmpOutcome::HostUnreachable,
                        _ => IcmpOutcome::NetworkUnreachable,
                    };
                    let completed_at = std::time::Instant::now();
                    Ok(IcmpEchoReply::with_evidence(
                        target_addr,
                        outcome.coarse(),
                        outcome,
                        None,
                        Some(sequence),
                        Duration::ZERO,
                        completed_at,
                    ))
                }
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
    payload_len: usize,
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
        Self::with_payload_len(
            target_addr,
            source_addr,
            ttl,
            timeout,
            PING_DEFAULT_REQUEST_DATA_LENGTH,
        )
    }

    /// Creates a requestor that transmits exactly `payload_len` payload bytes.
    pub fn with_payload_len(
        target_addr: IpAddr,
        source_addr: Option<IpAddr>,
        ttl: Option<u8>,
        timeout: Option<Duration>,
        payload_len: usize,
    ) -> io::Result<Self> {
        if !(PING_MIN_REQUEST_DATA_LENGTH..=PING_MAX_REQUEST_DATA_LENGTH).contains(&payload_len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "payload_len {payload_len} is outside {PING_MIN_REQUEST_DATA_LENGTH}..={PING_MAX_REQUEST_DATA_LENGTH}"
                ),
            ));
        }

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
                payload_len,
                registry,
                router_abort: OnceLock::new(),
                router_context,
            }),
        })
    }

    /// Returns the exact payload length used on the wire.
    pub fn payload_len(&self) -> usize {
        self.inner.payload_len
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
    /// - The instant at which the outcome was determined
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
    /// the socket error queue (`IP_RECVERR` / `IPV6_RECVERR`) before the local timeout.
    /// Their coarse status is `Unreachable`; `IcmpOutcome` retains the network subtype and
    /// distinguishes Time Exceeded from a local deadline. The other ICMP errors that embed
    /// the request (Parameter Problem, ICMPv6 Packet Too Big) resolve as `Unknown`.
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
        // lazy spawning
        self.ensure_router_running();

        // One deadline bounds the send stage and the reply wait.
        let started_at = Instant::now();
        let deadline = started_at + self.inner.timeout;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| io::Error::other(format!("timestamp error: {e}")))?
            .as_nanos() as u64;
        let payload_len = self.inner.payload_len;
        let mut payload = vec![0u8; payload_len];
        if payload_len >= 8 {
            payload[..8].copy_from_slice(&timestamp.to_be_bytes());
        }

        // Register in the registry BEFORE sending so fast replies (e.g. loopback)
        // are not dropped by the router due to a missing entry. Registration fails fast
        // with the persisted error if the router has already failed (the check and the
        // allocation are one critical section, see `register_request`). The guard removes
        // the entry on every exit path, including the future being dropped.
        let (tx, reply_rx) = oneshot::channel();
        let (sequence, request_id) = self.inner.register_request(timestamp, payload_len, tx)?;
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
            sequence,
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

    /// The send stage of one request on Linux: `send_to`, retried after every failure that
    /// a queued ICMP error explains.
    ///
    /// With `IP_RECVERR` enabled every ICMP error (including a Redirect or Source Quench,
    /// queued with `EREMOTEIO`) also sets the socket's one-shot `sk_err`, and the kernel's
    /// send path consumes it (`sock_alloc_send_pskb` returns and clears a pending error)
    /// *after* the route lookup succeeded — so the failing `send_to` never transmitted
    /// anything. Such a failure is another request's swallowed ICMP errno: the queued
    /// message still has to be dispatched to its own waiter, and this request has to be
    /// sent again. Because a new error can arrive between one drain and the next attempt,
    /// this is a loop, not a single retry: after each failure the queue is drained and
    /// dispatched, and the send is repeated as long as *someone* (this drain or the router,
    /// via the shared `errqueue_drained` counter) removed a message since before the
    /// attempt. Only a failure with nothing removed is a genuine local error for this
    /// destination and is returned. The caller's deadline bounds the loop.
    #[cfg(target_os = "linux")]
    async fn send_stage(&self, bytes: &[u8], target: SocketAddr) -> io::Result<()> {
        let ctx = &self.inner.router_context;
        loop {
            let removed_before = ctx.errqueue_drained.load(Ordering::SeqCst);
            let error = match self.inner.socket.send_to(bytes, target).await {
                Ok(_) => return Ok(()),
                Err(e) => e,
            };
            let drained = {
                let _guard = lock_errqueue(&ctx.errqueue_lock);
                let drained = errqueue::drain(self.inner.socket.as_raw_fd(), ctx.target_addr);
                ctx.errqueue_drained
                    .fetch_add(drained.removed, Ordering::SeqCst);
                drained
            };
            for info in &drained.infos {
                deliver_error(
                    &ctx.registry,
                    self.inner.identifier,
                    ctx.target_addr,
                    info,
                    None,
                );
            }
            if ctx.errqueue_drained.load(Ordering::SeqCst) == removed_before {
                // Nothing was queued: the errno is this destination's own.
                return Err(error);
            }
        }
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

impl RequestorInner {
    /// Registers a request, or fails fast with the persisted router error.
    ///
    /// The failure check and the allocation happen under the registry lock, and
    /// [`fail_router`] publishes the failure and clears the registry under that same lock
    /// (lock order: registry, then failure). So a request either observes the failure, or
    /// is registered before the failure is published and is then cancelled by the clear —
    /// it can never be registered after the router has cleared the registry and exited,
    /// which would leave it waiting for a reply nobody can deliver.
    fn register_request(
        &self,
        sent_timestamp: u64,
        payload_len: usize,
        tx: oneshot::Sender<IcmpEchoReply>,
    ) -> io::Result<(u16, u64)> {
        let mut registry = lock_registry(&self.registry);
        if let Some(ref router_error) = *lock_failure(&self.router_context.failed) {
            return Err(router_error.to_io_error());
        }
        registry.allocate(sent_timestamp, payload_len, tx)
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
    responder: Option<IpAddr>,
    packet: &IcmpPacket,
) -> bool {
    let responder =
        responder.filter(|addr| !addr.is_unspecified() && addr.is_ipv4() == target_addr.is_ipv4());
    if packet.identifier() != identifier {
        return false;
    }
    let payload = packet.payload();

    let entry = {
        let mut registry = lock_registry(registry);
        match registry.entries.entry(packet.sequence()) {
            Entry::Occupied(occupied) => {
                let entry = occupied.get();
                if payload.len() != entry.payload_len || payload != entry.sent_payload {
                    return false;
                }
                occupied.remove()
            }
            Entry::Vacant(_) => return false,
        }
    };

    let sent_timestamp = entry.sent_timestamp;

    // The reply has been matched to a live request: the outcome is decided.
    let completed_at = std::time::Instant::now();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let rtt = Duration::from_nanos(now.saturating_sub(sent_timestamp));
    let _ = entry.tx.send(IcmpEchoReply::with_evidence(
        target_addr,
        IcmpEchoStatus::Success,
        IcmpOutcome::EchoReply,
        responder,
        Some(packet.sequence()),
        rtt,
        completed_at,
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
    fallback_responder: Option<IpAddr>,
) -> bool {
    let responder = info
        .responder
        .or(fallback_responder)
        .filter(|addr| !addr.is_unspecified() && addr.is_ipv4() == target_addr.is_ipv4());
    if info.identifier != identifier {
        return false;
    }
    let entry = lock_registry(registry).entries.remove(&info.sequence);
    match entry {
        Some(entry) => {
            // The error has been matched to a live request; its status is known.
            let completed_at = std::time::Instant::now();
            let _ = entry.tx.send(IcmpEchoReply::with_evidence(
                target_addr,
                info.status,
                info.outcome,
                responder,
                Some(info.sequence),
                Duration::ZERO,
                completed_at,
            ));
            true
        }
        None => false,
    }
}

/// Persists a fatal router error and cancels every in-flight request.
///
/// Both happen under the registry lock (lock order: registry, then failure — the same
/// order as `RequestorInner::register_request`), so no request can be registered between
/// the failure being published and the registry being cleared.
fn fail_router(registry: &SharedRegistry, failed: &SharedFailure, error: &io::Error) {
    let mut registry = lock_registry(registry);

    // Store the error persistently so all future send() calls fail fast
    *lock_failure(failed) = Some(RouterError::from_io_error(error));

    // Drain the registry — dropping senders closes channels, which causes in-flight
    // send() calls to see a closed channel and check `failed` for a consistent error.
    registry.entries.clear();
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

fn wake_action(wake: &io::Result<(usize, Option<SocketAddr>)>) -> WakeAction {
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
    wake: io::Result<(usize, Option<SocketAddr>)>,
    buf: &[u8],
    drain: &mut dyn FnMut() -> Drained,
) -> RouterStep {
    let action = wake_action(&wake);

    if let (WakeAction::Datagram, Ok((size, from))) = (action, &wake) {
        let data = &buf[..*size];
        let responder = from
            .map(|addr| addr.ip())
            .filter(|addr| !addr.is_unspecified() && addr.is_ipv4() == state.target_addr.is_ipv4());
        if let Some(reply_packet) = IcmpPacket::parse_reply(data, state.target_addr) {
            deliver_echo_reply(
                &state.registry,
                state.identifier,
                state.target_addr,
                responder,
                &reply_packet,
            );
        } else if let Some(error_info) = IcmpPacket::parse_error_reply(data, state.target_addr) {
            deliver_error(
                &state.registry,
                state.identifier,
                state.target_addr,
                &error_info,
                responder,
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
        let Drained { removed, infos } = drain();
        state.errqueue_drained.fetch_add(removed, Ordering::SeqCst);
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
        deliver_error(
            &state.registry,
            state.identifier,
            state.target_addr,
            info,
            None,
        );
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
) -> io::Result<(usize, Option<SocketAddr>)> {
    let (received, from) = match socket.try_io(Interest::READABLE, || {
        socket2::SockRef::from(socket).recv_from(scratch)
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
    // SAFETY: `recv_from` initialised the first `received` bytes of `scratch`.
    let initialised =
        unsafe { std::slice::from_raw_parts(scratch.as_ptr().cast::<u8>(), received) };
    buf[..received].copy_from_slice(initialised);
    Ok((received, from.as_socket()))
}

async fn reply_router_loop(socket: Arc<UdpSocket>, mut state: RouterState) {
    let mut scratch: Vec<MaybeUninit<u8>> = vec![MaybeUninit::uninit(); 2048];
    let mut buf = vec![0u8; 2048];

    #[cfg(target_os = "linux")]
    let mut drain = {
        let fd = socket.as_raw_fd();
        let target_addr = state.target_addr;
        move || errqueue::drain(fd, target_addr)
    };
    #[cfg(not(target_os = "linux"))]
    let mut drain = Drained::default;

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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::fd::{AsRawFd, RawFd};
    use std::ptr;

    use socket2::Socket;

    use super::Drained;
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

    fn parse_offender(cmsg: *mut libc::cmsghdr, target_addr: IpAddr) -> Option<IpAddr> {
        // SAFETY: `cmsg` points to the control-buffer header being iterated.
        let header: libc::cmsghdr = unsafe { ptr::read_unaligned(cmsg) };
        let data_len = header
            .cmsg_len
            .checked_sub(mem::size_of::<libc::cmsghdr>())?;
        let ee_len = mem::size_of::<libc::sock_extended_err>();
        if data_len < ee_len + mem::size_of::<libc::sockaddr>() {
            return None;
        }
        // SAFETY: the preceding length check covers the extended-error structure.
        let offender = unsafe {
            libc::CMSG_DATA(cmsg)
                .cast::<u8>()
                .add(ee_len)
                .cast::<libc::sockaddr>()
        };
        // SAFETY: the control message contains a sockaddr after the extended-error data.
        let family = unsafe { ptr::read_unaligned(offender) }.sa_family as libc::c_int;
        match target_addr {
            IpAddr::V4(_) if family == libc::AF_INET => {
                if data_len < ee_len + mem::size_of::<libc::sockaddr_in>() {
                    return None;
                }
                // SAFETY: the address-family-specific structure is present in the cmsg.
                let address = unsafe { ptr::read_unaligned(offender.cast::<libc::sockaddr_in>()) };
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    address.sin_addr.s_addr,
                ))))
            }
            IpAddr::V6(_) if family == libc::AF_INET6 => {
                if data_len < ee_len + mem::size_of::<libc::sockaddr_in6>() {
                    return None;
                }
                // SAFETY: the address-family-specific structure is present in the cmsg.
                let address = unsafe { ptr::read_unaligned(offender.cast::<libc::sockaddr_in6>()) };
                Some(IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)))
            }
            _ => None,
        }
    }

    /// Interprets one error-queue message: `origin` / `ee_type` / `ee_code` from the
    /// `sock_extended_err` control message, `responder` from its offender address, and
    /// `data` = the message payload (the embedded echo request starting at its ICMP
    /// header). Only ICMP-originated errors for our address family are reported.
    #[cfg(test)]
    pub(super) fn parse_extended_error(
        origin: u8,
        ee_type: u8,
        data: &[u8],
        target_addr: IpAddr,
    ) -> Option<IcmpErrorInfo> {
        parse_extended_error_with_code(origin, ee_type, 0, None, data, target_addr)
    }

    pub(super) fn parse_extended_error_with_code(
        origin: u8,
        ee_type: u8,
        ee_code: u8,
        responder: Option<IpAddr>,
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
        let outcome = IcmpPacket::error_outcome(target_addr, ee_type, ee_code)?;
        let (identifier, sequence) = IcmpPacket::parse_embedded_echo_request(data, target_addr)?;
        Some(IcmpErrorInfo {
            identifier,
            sequence,
            status: outcome.coarse(),
            outcome,
            responder,
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
                return Ok(Some(parse_extended_error_with_code(
                    ee.ee_origin,
                    ee.ee_type,
                    ee.ee_code,
                    parse_offender(cmsg, target_addr),
                    &data[..received],
                    target_addr,
                )));
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
        }
        Ok(Some(None))
    }

    /// Removes every queued message and returns how many were removed together with the
    /// supported ICMP errors among them. Never blocks; stops at `EAGAIN` or any other
    /// receive error.
    pub(super) fn drain(fd: RawFd, target_addr: IpAddr) -> Drained {
        let mut drained = Drained::default();
        // Stops at `Ok(None)` (queue empty) or any receive error.
        while let Ok(Some(info)) = recv_one(fd, target_addr) {
            drained.removed += 1;
            if let Some(info) = info {
                drained.infos.push(info);
            }
        }
        drained
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
        let (seq, _) = lock_registry(&state.registry).allocate(ts, 8, tx).unwrap();
        (seq, rx)
    }

    fn no_drain() -> Drained {
        Drained::default()
    }

    fn err(kind: io::ErrorKind) -> io::Result<(usize, Option<SocketAddr>)> {
        Err(io::Error::from(kind))
    }

    /// A deadline `TimedOut` is stamped when the timer was observed to have fired: never
    /// before the deadline and never after the caller sees the reply.
    fn assert_completed_at_deadline(reply: &IcmpEchoReply, deadline: Instant) {
        let now = std::time::Instant::now();
        assert!(
            deadline.into_std() <= reply.completed_at() && reply.completed_at() <= now,
            "completed_at {:?} must lie within [{:?}, {now:?}]",
            reply.completed_at(),
            deadline.into_std()
        );
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

    #[test]
    fn short_sequence_space_exhausts_without_wrapping() {
        let space = SequenceSpace::new(u32::from(u16::MAX));
        assert_eq!(space.allocate().unwrap(), u16::MAX);
        assert!(space.allocate().is_err());
    }

    #[tokio::test]
    async fn payload_length_accepts_boundaries_and_rejects_out_of_range() {
        for payload_len in [0, 1, 7, 8, 32, 56, 1024] {
            let requestor =
                IcmpEchoRequestor::with_payload_len(target(), None, None, None, payload_len)
                    .unwrap();
            assert_eq!(requestor.payload_len(), payload_len);
        }
        for payload_len in [PING_MAX_REQUEST_DATA_LENGTH + 1, usize::MAX] {
            let result =
                IcmpEchoRequestor::with_payload_len(target(), None, None, None, payload_len);
            assert_eq!(
                result.as_ref().err().map(io::Error::kind),
                Some(io::ErrorKind::InvalidInput)
            );
        }
    }

    // ---- registry allocation ---------------------------------------------------------

    #[test]
    fn allocate_skips_occupied_and_exhausts_without_wrapping() {
        let mut registry = Registry::new();
        for seq in 0..=2u16 {
            registry.entries.insert(
                seq,
                RegistryEntry {
                    request_id: 0,
                    sent_timestamp: 0,
                    sent_payload: vec![0u8; 8],
                    payload_len: 8,
                    tx: dummy_sender(),
                },
            );
        }
        let (seq, _) = registry.allocate(1, 8, dummy_sender()).unwrap();
        assert_eq!(seq, 3);

        let mut registry = Registry::new();
        registry.next_sequence = Some(u16::MAX);
        registry.entries.insert(
            u16::MAX,
            RegistryEntry {
                request_id: 0,
                sent_timestamp: 0,
                sent_payload: vec![0u8; 8],
                payload_len: 8,
                tx: dummy_sender(),
            },
        );
        assert!(registry.allocate(1, 8, dummy_sender()).is_err());
        assert_eq!(registry.next_sequence, None);
    }

    #[test]
    fn allocate_fails_when_exhausted_without_consuming_an_id() {
        let mut registry = Registry::new();
        let mut last_id = 0;
        for _ in 0..=usize::from(u16::MAX) {
            let (_, id) = registry.allocate(0, 8, dummy_sender()).unwrap();
            assert!(id > last_id, "ids are strictly increasing");
            last_id = id;
        }
        assert_eq!(registry.entries.len(), 65_536);
        let next_id_before = registry.next_request_id;
        assert!(registry.allocate(0, 8, dummy_sender()).is_err());
        assert_eq!(registry.next_request_id, next_id_before);
    }

    #[test]
    fn guard_only_removes_its_own_entry() {
        let registry: SharedRegistry = Arc::new(Mutex::new(Registry::new()));

        let (seq, id1) = lock_registry(&registry)
            .allocate(1, 8, dummy_sender())
            .unwrap();
        let guard1 = RegistryGuard {
            registry: Arc::clone(&registry),
            sequence: seq,
            request_id: id1,
        };

        // The router completes the request; the sequence becomes free.
        lock_registry(&registry).entries.remove(&seq);

        // Force the next allocation to reuse the same sequence number.
        lock_registry(&registry).next_sequence = Some(seq);
        let (seq2, id2) = lock_registry(&registry)
            .allocate(2, 8, dummy_sender())
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

    #[test]
    fn stale_icmp_error_cannot_satisfy_a_later_long_request() {
        let target = target();
        let registry: SharedRegistry = Arc::new(Mutex::new(Registry::new()));
        let (tx, _rx) = oneshot::channel();
        let (old_sequence, _) = lock_registry(&registry).allocate(1, 8, tx).unwrap();
        lock_registry(&registry).entries.remove(&old_sequence);
        let (tx, mut rx) = oneshot::channel();
        let (new_sequence, _) = lock_registry(&registry).allocate(2, 8, tx).unwrap();
        assert_ne!(old_sequence, new_sequence);
        let old_error = IcmpErrorInfo {
            identifier: TEST_IDENTIFIER,
            sequence: old_sequence,
            status: IcmpEchoStatus::Unreachable,
            outcome: IcmpOutcome::TimeExceeded,
            responder: None,
        };
        assert!(!deliver_error(
            &registry,
            TEST_IDENTIFIER,
            target,
            &old_error,
            None,
        ));
        assert!(lock_registry(&registry).entries.contains_key(&new_sequence));
        assert!(rx.try_recv().unwrap().is_none());
    }

    #[tokio::test]
    async fn concurrent_short_payloads_use_distinct_sequences() -> io::Result<()> {
        let pinger = IcmpEchoRequestor::with_payload_len(
            "127.0.0.1".parse().unwrap(),
            None,
            None,
            Some(Duration::from_secs(1)),
            0,
        )?;
        let replies = futures::future::join_all((0..8).map(|_| pinger.send()))
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        let mut sequences = replies
            .iter()
            .map(|reply| reply.sequence().expect("Unix sequence"))
            .collect::<Vec<_>>();
        sequences.sort_unstable();
        sequences.dedup();
        assert_eq!(sequences.len(), replies.len());
        assert!(replies.iter().all(|reply| {
            reply.status() == IcmpEchoStatus::Success
                && reply.outcome() == IcmpOutcome::EchoReply
                && reply.responder() == Some("127.0.0.1".parse().unwrap())
        }));
        Ok(())
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
        let (seq, _) = lock_registry(&registry).allocate(2, 8, tx).unwrap();

        let stale = echo_reply_packet(target, identifier, seq, 1);
        assert!(!deliver_echo_reply(
            &registry, identifier, target, None, &stale
        ));
        assert!(lock_registry(&registry).entries.contains_key(&seq));
        assert!(
            rx.try_recv().unwrap().is_none(),
            "waiter must still be pending"
        );

        let fresh = echo_reply_packet(target, identifier, seq, 2);
        let before = std::time::Instant::now();
        assert!(deliver_echo_reply(
            &registry, identifier, target, None, &fresh
        ));
        let after = std::time::Instant::now();
        assert!(!lock_registry(&registry).entries.contains_key(&seq));
        let reply = rx.try_recv().unwrap().expect("exactly one delivery");
        assert_eq!(reply.status(), IcmpEchoStatus::Success);
        assert!(
            before <= reply.completed_at() && reply.completed_at() <= after,
            "completed_at must be stamped at delivery"
        );

        let again = echo_reply_packet(target, identifier, seq, 2);
        assert!(!deliver_echo_reply(
            &registry, identifier, target, None, &again
        ));

        // Wrong identifier is ignored even with a matching entry.
        let (tx, _rx) = oneshot::channel();
        let (seq, _) = lock_registry(&registry).allocate(3, 8, tx).unwrap();
        let other = echo_reply_packet(target, identifier.wrapping_add(1), seq, 3);
        assert!(!deliver_echo_reply(
            &registry, identifier, target, None, &other
        ));
        assert!(lock_registry(&registry).entries.contains_key(&seq));
    }

    #[test]
    fn short_payload_replies_match_without_a_timestamp() {
        for (target, responder) in [
            (target(), "127.0.0.2".parse::<IpAddr>().unwrap()),
            (
                "::1".parse::<IpAddr>().unwrap(),
                "::2".parse::<IpAddr>().unwrap(),
            ),
        ] {
            let registry: SharedRegistry = Arc::new(Mutex::new(Registry::new()));
            let (tx, mut rx) = oneshot::channel();
            let (seq, _) = lock_registry(&registry).allocate(1, 0, tx).unwrap();
            let packet = IcmpPacket::new(
                IcmpType::echo_reply_for(target),
                0,
                TEST_IDENTIFIER,
                seq,
                &[],
            );

            assert!(deliver_echo_reply(
                &registry,
                TEST_IDENTIFIER,
                target,
                Some(responder),
                &packet,
            ));
            let reply = rx.try_recv().unwrap().expect("short request delivered");
            assert_eq!(reply.status(), IcmpEchoStatus::Success);
            assert_eq!(reply.outcome(), IcmpOutcome::EchoReply);
            assert_eq!(reply.responder(), Some(responder));
            assert_eq!(reply.sequence(), Some(seq));
        }
    }

    #[test]
    fn short_payload_stale_reply_cannot_satisfy_a_later_request() {
        let target = target();
        let registry: SharedRegistry = Arc::new(Mutex::new(Registry::new()));
        let (tx, _rx) = oneshot::channel();
        let (old_sequence, _) = lock_registry(&registry).allocate(1, 0, tx).unwrap();
        lock_registry(&registry).entries.remove(&old_sequence);
        let (tx, _rx) = oneshot::channel();
        let (new_sequence, _) = lock_registry(&registry).allocate(2, 0, tx).unwrap();
        assert_ne!(old_sequence, new_sequence);
        let old_reply = IcmpPacket::new(
            IcmpType::echo_reply_for(target),
            0,
            TEST_IDENTIFIER,
            old_sequence,
            &[],
        );
        assert!(!deliver_echo_reply(
            &registry,
            TEST_IDENTIFIER,
            target,
            None,
            &old_reply,
        ));
        assert!(lock_registry(&registry).entries.contains_key(&new_sequence));
    }

    // ---- end-to-end deadline ---------------------------------------------------------

    #[tokio::test]
    async fn run_request_pending_send_stage_times_out() {
        let registry: SharedRegistry = Arc::new(Mutex::new(Registry::new()));
        let (tx, rx) = oneshot::channel();
        let (seq, id) = lock_registry(&registry).allocate(0, 8, tx).unwrap();
        let guard = RegistryGuard {
            registry: Arc::clone(&registry),
            sequence: seq,
            request_id: id,
        };

        let started = Instant::now();
        let deadline = started + Duration::from_millis(50);
        let result = run_request(
            deadline,
            futures::future::pending(),
            rx,
            target(),
            0,
            started,
        )
        .await;
        let reply = result.expect("timed out reply");
        assert_eq!(reply.status(), IcmpEchoStatus::TimedOut);
        assert_eq!(reply.outcome(), IcmpOutcome::LocalTimeout);
        assert_eq!(reply.sequence(), Some(0));
        assert!(started.elapsed() < Duration::from_millis(150));
        assert_completed_at_deadline(&reply, deadline);

        drop(guard);
        assert!(lock_registry(&registry).entries.is_empty());
    }

    #[tokio::test]
    async fn run_request_no_reply_times_out_at_deadline() {
        let (_tx, rx) = oneshot::channel();
        let started = Instant::now();
        let deadline = started + Duration::from_millis(50);
        let reply = run_request(deadline, async { Ok(()) }, rx, target(), 0, started)
            .await
            .unwrap();
        assert_eq!(reply.status(), IcmpEchoStatus::TimedOut);
        assert_eq!(reply.outcome(), IcmpOutcome::LocalTimeout);
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(45) && elapsed < Duration::from_millis(150));
        assert_completed_at_deadline(&reply, deadline);
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
            0,
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
            0,
            started,
        )
        .await
        .unwrap();
        assert_eq!(reply.status(), IcmpEchoStatus::Unreachable);
        assert_eq!(reply.outcome(), IcmpOutcome::HostUnreachable);
        let now = std::time::Instant::now();
        assert!(
            started.into_std() <= reply.completed_at() && reply.completed_at() <= now,
            "completed_at must be stamped at classification"
        );

        let (_tx, rx) = oneshot::channel();
        let result = run_request(
            started + Duration::from_millis(500),
            async { Err(io::Error::other("boom")) },
            rx,
            target(),
            0,
            started,
        )
        .await;
        assert!(matches!(result, Err(RequestFailure::Send(ref e)) if e.to_string() == "boom"));
    }

    #[tokio::test]
    async fn run_request_slow_send_stage_is_bounded_by_deadline() {
        let (_tx, rx) = oneshot::channel();
        let started = Instant::now();
        let deadline = started + Duration::from_millis(50);
        let reply = run_request(
            deadline,
            async {
                tokio::time::sleep(Duration::from_millis(200)).await;
                Ok(())
            },
            rx,
            target(),
            0,
            started,
        )
        .await
        .unwrap();
        assert_eq!(reply.status(), IcmpEchoStatus::TimedOut);
        assert_eq!(reply.outcome(), IcmpOutcome::LocalTimeout);
        assert!(started.elapsed() < Duration::from_millis(150));
        assert_completed_at_deadline(&reply, deadline);
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
            0,
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

    #[tokio::test]
    async fn send_after_fatal_failure_fails_fast_without_registering() {
        let pinger = IcmpEchoRequestor::new(
            "127.0.0.1".parse().unwrap(),
            None,
            None,
            Some(Duration::from_secs(2)),
        )
        .unwrap();
        disable_router(&pinger);
        fail_router(
            &pinger.inner.registry,
            &pinger.inner.router_context.failed,
            &io::Error::new(io::ErrorKind::PermissionDenied, "boom"),
        );

        let started = Instant::now();
        let err = pinger.send().await.expect_err("must fail fast");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(err.to_string(), "boom");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "must not wait for the deadline"
        );
        assert_eq!(registry_len(&pinger), 0);
    }

    /// Registration racing with fatal shutdown: both contend for the registry lock, and
    /// whichever wins, no request may remain registered once `fail_router` has returned —
    /// the loser either observes the failure or is cancelled by the clear.
    #[tokio::test]
    async fn registration_never_survives_fatal_shutdown() {
        for _ in 0..50 {
            let pinger =
                IcmpEchoRequestor::new("127.0.0.1".parse().unwrap(), None, None, None).unwrap();

            // Hold the registry lock so both sides queue on it, then release.
            let gate = lock_registry(&pinger.inner.registry);
            let failer = {
                let p = pinger.clone();
                std::thread::spawn(move || {
                    fail_router(
                        &p.inner.registry,
                        &p.inner.router_context.failed,
                        &io::Error::new(io::ErrorKind::PermissionDenied, "boom"),
                    )
                })
            };
            let registrar = {
                let p = pinger.clone();
                std::thread::spawn(move || {
                    let (tx, rx) = oneshot::channel();
                    (p.inner.register_request(1, 8, tx), rx)
                })
            };
            std::thread::sleep(Duration::from_millis(1));
            drop(gate);

            failer.join().unwrap();
            let (result, mut rx) = registrar.join().unwrap();
            match result {
                Err(e) => assert_eq!(e.kind(), io::ErrorKind::PermissionDenied),
                Ok(_) => assert!(
                    matches!(rx.try_recv(), Err(oneshot::Canceled)),
                    "registered before the failure: must have been cancelled by the clear"
                ),
            }
            assert_eq!(registry_len(&pinger), 0);
        }
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
        assert_eq!(wake_action(&Ok((64, None))), WakeAction::Datagram);
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
            let responder = "127.0.0.2".parse::<IpAddr>().unwrap();
            let mut drain = || {
                calls.set(calls.get() + 1);
                Drained {
                    removed: 1,
                    infos: vec![IcmpErrorInfo {
                        identifier: TEST_IDENTIFIER,
                        sequence: seq,
                        status: IcmpEchoStatus::Unreachable,
                        outcome: IcmpOutcome::DestinationUnreachable,
                        responder: Some(responder),
                    }],
                }
            };
            let before = std::time::Instant::now();
            let step = handle_wake(&mut state, err(kind), &[], &mut drain);
            let after = std::time::Instant::now();
            assert_eq!(step, RouterStep::Continue, "{kind:?}");
            assert_eq!(calls.get(), 1, "drainer called exactly once ({kind:?})");
            let reply = rx.try_recv().unwrap().expect("waiter resolved");
            assert_eq!(reply.status(), IcmpEchoStatus::Unreachable);
            assert_eq!(reply.responder(), Some(responder));
            assert!(
                before <= reply.completed_at() && reply.completed_at() <= after,
                "completed_at must be stamped at delivery ({kind:?})"
            );
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
        let before = std::time::Instant::now();
        let step = handle_wake(&mut state, Ok((datagram.len(), None)), &buf, &mut drain);
        let after = std::time::Instant::now();
        assert_eq!(step, RouterStep::Continue);
        let reply = rx.try_recv().unwrap().expect("echo reply delivered");
        assert_eq!(reply.status(), IcmpEchoStatus::Success);
        assert!(
            before <= reply.completed_at() && reply.completed_at() <= after,
            "completed_at must be stamped at delivery"
        );
        assert_eq!(state.errqueue_drained.load(Ordering::SeqCst), 0);
    }

    // ---- Linux error queue -----------------------------------------------------------

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use crate::platform::socket::errqueue::{
            parse_extended_error, parse_extended_error_with_code,
        };

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
                (3, 4, IcmpEchoStatus::Unreachable)
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
                (7, 8, IcmpEchoStatus::Unreachable)
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

        #[test]
        fn parse_extended_error_preserves_code_and_responder() {
            let target: IpAddr = "127.0.0.1".parse().unwrap();
            let responder: IpAddr = "192.0.2.1".parse().unwrap();
            let info = parse_extended_error_with_code(
                libc::SO_EE_ORIGIN_ICMP,
                3,
                1,
                Some(responder),
                &embedded_echo(false, 21, 22),
                target,
            )
            .unwrap();
            assert_eq!(info.outcome, IcmpOutcome::HostUnreachable);
            assert_eq!(info.status, IcmpEchoStatus::Unreachable);
            assert_eq!(info.responder, Some(responder));
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
                    IcmpOutcome::HostUnreachable,
                    timeout,
                ),
                (
                    "PING_ASYNC_TTL1_TARGET",
                    Some(1u8),
                    IcmpOutcome::TimeExceeded,
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
                    assert_eq!(reply.outcome(), expected, "{var} round {round}");
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
        /// Every request must resolve through its own ICMP error with exactly the
        /// `expected` status — never through the local timeout (a swallowed `sk_err` with
        /// no following drain), never as a local `Err`, and never with another request's
        /// outcome. Network Time Exceeded and the local timeout are distinguished by
        /// `IcmpOutcome`; the elapsed-time bound remains a transport qualification.
        async fn concurrent_scenario(
            target: IpAddr,
            ttl: Option<u8>,
            expected: IcmpOutcome,
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
            let mut unexpected = Vec::new();
            for (i, handle) in handles.into_iter().enumerate() {
                let (reply, elapsed) = handle.await.unwrap();
                let reply = reply.unwrap_or_else(|e| panic!("request {i}: send() errored: {e}"));
                match (reply.status(), reply.outcome()) {
                    (status, outcome)
                        if status == expected.coarse()
                            && outcome == expected
                            && elapsed < bound =>
                    {
                        icmp_errors += 1;
                    }
                    (IcmpEchoStatus::TimedOut, IcmpOutcome::LocalTimeout) if elapsed >= bound => {
                        late += 1;
                    }
                    _ => {
                        other += 1;
                        unexpected.push((i, reply, elapsed));
                    }
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
            assert_eq!(
                other, 0,
                "requests with a status other than {expected:?}: {unexpected:?}"
            );
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
                    IcmpOutcome::TimeExceeded,
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
                    IcmpOutcome::HostUnreachable,
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
