// platform/windows.rs

use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV6};
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(test)]
use std::sync::atomic::AtomicUsize;

use futures::channel::oneshot;
use static_assertions::const_assert;

use windows::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_HOST_UNREACHABLE, ERROR_IO_PENDING, ERROR_NETWORK_UNREACHABLE,
    ERROR_PORT_UNREACHABLE, ERROR_PROTOCOL_UNREACHABLE, HANDLE,
};
use windows::Win32::NetworkManagement::IpHelper::{
    Icmp6CreateFile, Icmp6ParseReplies, Icmp6SendEcho2, IcmpCloseHandle, IcmpCreateFile,
    IcmpParseReplies, IcmpSendEcho2Ex, ICMPV6_ECHO_REPLY_LH as ICMPV6_ECHO_REPLY,
    IP_DEST_HOST_UNREACHABLE, IP_DEST_NET_UNREACHABLE, IP_DEST_PORT_UNREACHABLE,
    IP_DEST_PROT_UNREACHABLE, IP_DEST_SCOPE_MISMATCH, IP_DEST_UNREACHABLE, IP_PENDING,
    IP_REQ_TIMED_OUT, IP_STATUS_BASE, IP_SUCCESS, IP_TIME_EXCEEDED, IP_TTL_EXPIRED_REASSEM,
    IP_TTL_EXPIRED_TRANSIT, MAX_IP_STATUS,
};
use windows::Win32::Networking::WinSock::{IN6_ADDR, SOCKADDR_IN6};
use windows::Win32::System::Threading::{
    CreateEventW, RegisterWaitForSingleObject, SetEvent, UnregisterWaitEx, INFINITE,
    WT_EXECUTEINWAITTHREAD, WT_EXECUTEONLYONCE,
};
use windows::Win32::System::IO::IO_STATUS_BLOCK;

#[cfg(target_pointer_width = "32")]
use windows::Win32::NetworkManagement::IpHelper::ICMP_ECHO_REPLY;
#[cfg(target_pointer_width = "64")]
use windows::Win32::NetworkManagement::IpHelper::ICMP_ECHO_REPLY32 as ICMP_ECHO_REPLY;
#[cfg(target_pointer_width = "32")]
use windows::Win32::NetworkManagement::IpHelper::IP_OPTION_INFORMATION;
#[cfg(target_pointer_width = "64")]
use windows::Win32::NetworkManagement::IpHelper::IP_OPTION_INFORMATION32 as IP_OPTION_INFORMATION;

use crate::{
    IcmpEchoReply, IcmpEchoStatus, IcmpOutcome, PING_DEFAULT_REQUEST_DATA_LENGTH,
    PING_DEFAULT_TIMEOUT, PING_DEFAULT_TTL, PING_MAX_REQUEST_DATA_LENGTH,
    PING_MIN_REQUEST_DATA_LENGTH,
};

const REPLY_BUFFER_SIZE: usize =
    size_of::<ICMP_ECHO_REPLY>() + PING_MAX_REQUEST_DATA_LENGTH + 8 + size_of::<IO_STATUS_BLOCK>();

const_assert!(
    size_of::<ICMPV6_ECHO_REPLY>()
        + PING_MAX_REQUEST_DATA_LENGTH
        + 8
        + size_of::<IO_STATUS_BLOCK>()
        <= REPLY_BUFFER_SIZE
);

/// Owner of the ICMP handle returned by `IcmpCreateFile` / `Icmp6CreateFile`.
///
/// The requestor and every in-flight [`RequestContext`] hold an `Arc` to it, so the handle
/// is closed by whichever of them is dropped last. `IcmpCloseHandle` blocks until every
/// request issued on the handle has completed in the driver; because in-flight contexts
/// keep the owner alive until their completion callback has run, the close only ever
/// happens when nothing is pending and returns immediately.
struct IcmpHandleOwner {
    handle: HANDLE,
}

// The ICMP handle is only ever used with the thread-safe icmpapi functions.
unsafe impl Send for IcmpHandleOwner {}
unsafe impl Sync for IcmpHandleOwner {}

impl Drop for IcmpHandleOwner {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // SAFETY: the handle was returned by Icmp[6]CreateFile and no request that
            // references it is still alive (they all hold an Arc to this owner).
            let _ = unsafe { IcmpCloseHandle(self.handle) };
        }
    }
}

/// Reply buffer handed to the driver. 8-byte aligned so the driver receives an aligned
/// buffer; reads still go through `ptr::read_unaligned`.
#[repr(C, align(8))]
struct ReplyBuffer([u8; REPLY_BUFFER_SIZE]);

/// Test-only resource accounting shared by a requestor and all of its request contexts.
#[cfg(test)]
#[derive(Default)]
struct RequestStats {
    contexts_live: AtomicUsize,
    waits_registered: AtomicUsize,
    events_open: AtomicUsize,
}

/// Parameters shared by every request of one requestor.
struct RequestParams {
    icmp: Arc<IcmpHandleOwner>,
    target_addr: IpAddr,
    timeout: Duration,
    #[cfg(test)]
    stats: Arc<RequestStats>,
}

/// Per-request state shared between the issuing task and the wait callback.
///
/// Ownership: exactly two strong references exist while the request is being started —
/// one held by [`start_request`] until it returns, one leaked into the wait callback with
/// `Arc::into_raw` and reclaimed there with `Arc::from_raw`.
///
/// Completion: the result is published exactly once, through [`RequestContext::publish`],
/// which builds and sends it while holding the `sender` mutex. For an outcome known
/// synchronously — the send API completed the request on the spot or rejected it — the
/// publisher is `start_request`, before it returns, so the caller's deadline can never
/// overtake a result that already exists; if the driver signalled the event as well and
/// the callback got there first, `start_request` blocks on the mutex until the callback
/// has finished sending, so the guarantee holds either way. For a pending request the
/// publisher is the wait callback, once the driver signals the event. Only the publisher
/// parses the reply buffer. The callback always runs (the event is signalled by hand for
/// synchronous outcomes) and is the single cleanup path: it unregisters the wait and
/// drops its reference.
struct RequestContext {
    /// Keeps the ICMP handle open until this context is dropped (never read).
    _icmp: Arc<IcmpHandleOwner>,
    #[cfg(test)]
    stats: Arc<RequestStats>,
    event: HANDLE,
    /// Wait handle from `RegisterWaitForSingleObject`; published before any I/O starts.
    wait_object: AtomicPtr<c_void>,
    /// Written by the driver while a request is in flight; only ever accessed through raw
    /// pointers, never through a Rust reference.
    buffer: Box<UnsafeCell<ReplyBuffer>>,
    target_addr: IpAddr,
    timeout: Duration,
    sender: Mutex<Option<ReplySender>>,
}

/// Completion channel of one request: a reply for any outcome the driver reports as an
/// echo result (including remote timeouts and unreachable destinations), or an
/// `io::Error` for a local failure of the send API.
type ReplySender = oneshot::Sender<io::Result<IcmpEchoReply>>;

fn responder_v4(address: u32) -> Option<IpAddr> {
    let address = IpAddr::V4(Ipv4Addr::from(u32::from_be(address)));
    (!address.is_unspecified()).then_some(address)
}

fn responder_v6(address: IN6_ADDR) -> Option<IpAddr> {
    let address = IpAddr::V6(address.into());
    (!address.is_unspecified()).then_some(address)
}

#[cfg(test)]
type ReplyReceiver = oneshot::Receiver<io::Result<IcmpEchoReply>>;

// SAFETY: the raw handles are only used with thread-safe Win32 functions, and the
// driver-written buffer is never touched through a reference while a request is in flight
// (see `buffer` above).
unsafe impl Send for RequestContext {}
unsafe impl Sync for RequestContext {}

impl RequestContext {
    fn new(params: &RequestParams, event: HANDLE, sender: ReplySender) -> Self {
        #[cfg(test)]
        {
            params.stats.contexts_live.fetch_add(1, Ordering::SeqCst);
            params.stats.events_open.fetch_add(1, Ordering::SeqCst);
        }
        RequestContext {
            _icmp: Arc::clone(&params.icmp),
            #[cfg(test)]
            stats: Arc::clone(&params.stats),
            event,
            wait_object: AtomicPtr::new(ptr::null_mut()),
            buffer: Box::new(UnsafeCell::new(ReplyBuffer([0u8; REPLY_BUFFER_SIZE]))),
            target_addr: params.target_addr,
            timeout: params.timeout,
            sender: Mutex::new(Some(sender)),
        }
    }

    /// Raw pointer to the reply buffer. No reference to the bytes is ever formed.
    fn buffer_ptr(&self) -> *mut u8 {
        self.buffer.get().cast::<u8>()
    }

    fn buffer_len(&self) -> u32 {
        REPLY_BUFFER_SIZE as u32
    }

    /// Publishes the request's result exactly once.
    ///
    /// The sender mutex is held from the moment the sender is taken until the result has
    /// been sent, and `make_result` runs inside that critical section. So the two
    /// completion paths are fully serialised: whichever takes the lock first builds the
    /// result (it is the only party that parses the buffer) and has it *in the channel*
    /// before releasing the lock, and the other one then observes that nothing is left to
    /// publish. In particular, when `start_request` returns `false` from here the result
    /// is already in the channel, not merely about to be. Returns whether this call
    /// published.
    fn publish(&self, make_result: impl FnOnce() -> io::Result<IcmpEchoReply>) -> bool {
        let mut slot = self
            .sender
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match slot.take() {
            Some(sender) => {
                // The receiver may already be gone (deadline elapsed or future dropped).
                let _ = sender.send(make_result());
                true
            }
            None => false,
        }
    }

    /// Builds the result for a request the driver has completed. Called by the holder of
    /// the sender only: from `start_request` for a synchronous completion, otherwise from
    /// the wait callback after the driver signalled the event. Must not panic.
    ///
    /// # Safety
    ///
    /// The driver must no longer be writing to the buffer (the send API returned a reply
    /// count, or the event has been signalled).
    unsafe fn completion_result(&self) -> io::Result<IcmpEchoReply> {
        let buf = self.buffer_ptr().cast::<c_void>();
        let len = self.buffer_len();

        let reply = match self.target_addr {
            IpAddr::V4(_) => {
                let parsed = IcmpParseReplies(buf, len);
                let last_error = GetLastError().0;
                let header: ICMP_ECHO_REPLY = ptr::read_unaligned(buf.cast::<ICMP_ECHO_REPLY>());

                if parsed != 0 {
                    let outcome = ip_error_to_icmp_outcome(header.Status);
                    let completed_at = Instant::now();
                    IcmpEchoReply::with_evidence(
                        self.target_addr,
                        ip_error_to_icmp_status(header.Status),
                        outcome,
                        responder_v4(header.Address),
                        None,
                        Duration::from_millis(header.RoundTripTime.into()),
                        completed_at,
                    )
                } else {
                    let outcome = failed_request_outcome(header.Status, last_error);
                    self.failed_reply(failed_request_status(header.Status, last_error), outcome)
                }
            }
            IpAddr::V6(_) => {
                let parsed = Icmp6ParseReplies(buf, len);
                let last_error = GetLastError().0;
                let header: ICMPV6_ECHO_REPLY =
                    ptr::read_unaligned(buf.cast::<ICMPV6_ECHO_REPLY>());

                if parsed != 0 {
                    let outcome = ip_error_to_icmp_outcome(header.Status);
                    let mut addr_raw = IN6_ADDR::default();
                    addr_raw.u.Word = header.Address.sin6_addr;
                    let completed_at = Instant::now();
                    IcmpEchoReply::with_evidence(
                        self.target_addr,
                        ip_error_to_icmp_status(header.Status),
                        outcome,
                        responder_v6(addr_raw),
                        None,
                        Duration::from_millis(header.RoundTripTime.into()),
                        completed_at,
                    )
                } else {
                    let outcome = failed_request_outcome(header.Status, last_error);
                    self.failed_reply(failed_request_status(header.Status, last_error), outcome)
                }
            }
        };
        Ok(reply)
    }

    fn failed_reply(&self, status: IcmpEchoStatus, outcome: IcmpOutcome) -> IcmpEchoReply {
        let completed_at = Instant::now();
        let rtt = if outcome == IcmpOutcome::LocalTimeout {
            self.timeout
        } else {
            Duration::ZERO
        };
        IcmpEchoReply::with_evidence(
            self.target_addr,
            status,
            outcome,
            None,
            None,
            rtt,
            completed_at,
        )
    }
}

impl Drop for RequestContext {
    fn drop(&mut self) {
        if !self.event.is_invalid() {
            // SAFETY: the event handle was created by CreateEventW and is closed exactly once.
            let closed = unsafe { CloseHandle(self.event) };
            #[cfg(test)]
            if closed.is_ok() {
                self.stats.events_open.fetch_sub(1, Ordering::SeqCst);
            }
            #[cfg(not(test))]
            let _ = closed;
        }
        #[cfg(test)]
        self.stats.contexts_live.fetch_sub(1, Ordering::SeqCst);
        // `buffer` is freed and the `Arc<IcmpHandleOwner>` released automatically.
    }
}

/// Outcome of starting the I/O for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendOutcome {
    /// The request is pending in the driver; the event will be signalled on completion.
    Pending,
    /// The request completed synchronously; the reply is already in the buffer.
    Completed,
    /// The request failed before any I/O started; no completion will be signalled.
    Failed(u32),
}

/// Classifies the raw return value of `IcmpSendEcho2Ex` / `Icmp6SendEcho2` (called with an
/// event) together with the `GetLastError()` value read immediately afterwards.
fn classify_send_result(ret: u32, last_error: u32) -> SendOutcome {
    if ret == ERROR_IO_PENDING.0 {
        // Defensive: a reply count of 997 is impossible with our buffer size.
        SendOutcome::Pending
    } else if ret != 0 {
        SendOutcome::Completed
    } else if last_error == ERROR_IO_PENDING.0 {
        SendOutcome::Pending
    } else {
        SendOutcome::Failed(last_error)
    }
}

/// Driver-side timeout in milliseconds. Floored at 1 ms: a zero timeout makes the driver
/// fail the request outright instead of leaving it pending.
fn driver_timeout_ms(timeout: Duration) -> u32 {
    timeout.as_millis().clamp(1, u32::MAX as u128) as u32
}

/// Whether `code` is an `IP_STATUS` value (the icmpapi's own status space, in which the
/// driver reports echo outcomes) rather than a Win32 error code.
fn is_ip_status(code: u32) -> bool {
    (IP_STATUS_BASE..=MAX_IP_STATUS).contains(&code) || code == IP_PENDING
}

/// Result of a request that the send API rejected immediately (no I/O was started), from
/// the `GetLastError()` value read right after the call.
///
/// A rejection that the driver expresses as an echo outcome — a timeout, or an unreachable
/// destination such as "no route" — is a reply, exactly like the same outcome reported
/// asynchronously. Anything else is a *local* failure (invalid parameters, insufficient
/// resources, unsupported networking, a buffer problem) and is an `io::Error`: a Win32
/// error code is carried as an OS error so its kind and message are preserved; an
/// `IP_STATUS` code, which has no Win32 message, is named in the message.
fn immediate_failure_result(
    code: u32,
    target_addr: IpAddr,
    timeout: Duration,
) -> io::Result<IcmpEchoReply> {
    let outcome = ip_error_to_icmp_outcome(code);
    match outcome {
        IcmpOutcome::LocalTimeout => {
            let completed_at = Instant::now();
            Ok(IcmpEchoReply::with_evidence(
                target_addr,
                outcome.coarse(),
                outcome,
                None,
                None,
                timeout,
                completed_at,
            ))
        }
        IcmpOutcome::TimeExceeded
        | IcmpOutcome::DestinationUnreachable
        | IcmpOutcome::NoRoute
        | IcmpOutcome::NetworkUnreachable
        | IcmpOutcome::HostUnreachable
        | IcmpOutcome::PortUnreachable
        | IcmpOutcome::ProtocolUnreachable => {
            let completed_at = Instant::now();
            Ok(IcmpEchoReply::with_evidence(
                target_addr,
                outcome.coarse(),
                outcome,
                None,
                None,
                Duration::ZERO,
                completed_at,
            ))
        }
        IcmpOutcome::Other if code == 0 => Err(io::Error::other(
            "ICMP echo request was rejected without an error code",
        )),
        IcmpOutcome::Other if is_ip_status(code) => Err(io::Error::other(format!(
            "ICMP echo request was rejected with IP_STATUS {code}"
        ))),
        IcmpOutcome::Other => Err(io::Error::from_raw_os_error(code as i32)),
        IcmpOutcome::EchoReply => Err(io::Error::other(
            "ICMP echo request was rejected with a success status",
        )),
    }
}

/// Status of a request that the driver completed without a parsed reply.
///
/// Precedence: the reply header's `Status` if non-zero (the buffer is zero-initialised by
/// us, so non-zero is meaningful), then `GetLastError()` if non-zero, else `Unknown`. A
/// failed request is never reported as `Success`.
fn failed_request_status(header_status: u32, last_error: u32) -> IcmpEchoStatus {
    failed_request_outcome(header_status, last_error).coarse()
}

fn failed_request_outcome(header_status: u32, last_error: u32) -> IcmpOutcome {
    let code = if header_status != 0 {
        header_status
    } else {
        last_error
    };
    match ip_error_to_icmp_outcome(code) {
        IcmpOutcome::EchoReply | IcmpOutcome::Other => IcmpOutcome::Other,
        outcome => outcome,
    }
}

/// Requestor for sending ICMP Echo Requests (ping) and receiving replies on Windows.
///
/// This implementation uses Windows-specific APIs (`IcmpSendEcho2Ex` and `Icmp6SendEcho2`)
/// that provide unprivileged ICMP functionality without requiring administrator rights.
/// The requestor is safe to clone and use across multiple threads and async tasks.
///
/// [`send`](IcmpEchoRequestor::send) must be polled inside a Tokio runtime with the time
/// driver enabled (the default for `#[tokio::main]` / `#[tokio::test]`), as on the other
/// platforms.
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
    icmp: Arc<IcmpHandleOwner>,
    target_addr: IpAddr,
    source_addr: IpAddr,
    ttl: u8,
    timeout: Duration,
    payload_len: usize,
    #[cfg(test)]
    stats: Arc<RequestStats>,
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
    /// - Windows ICMP handle creation fails (rare, typically indicates system resource issues)
    ///
    /// # Platform Notes
    ///
    /// On Windows, this uses `IcmpCreateFile()` for IPv4 or `Icmp6CreateFile()` for IPv6.
    /// These APIs don't require administrator privileges.
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
    /// // With custom timeout and TTL
    /// let pinger = IcmpEchoRequestor::new(
    ///     "2001:4860:4860::8888".parse().unwrap(),
    ///     None,
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

        match (target_addr, source_addr) {
            (IpAddr::V4(_), Some(IpAddr::V6(_))) | (IpAddr::V6(_), Some(IpAddr::V4(_))) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Source address type does not match target address type",
                ));
            }
            _ => {}
        }

        let icmp_handle = match target_addr {
            IpAddr::V4(_) => unsafe { IcmpCreateFile()? },
            IpAddr::V6(_) => unsafe { Icmp6CreateFile()? },
        };
        debug_assert!(!icmp_handle.is_invalid());

        let source_addr = source_addr.unwrap_or(match target_addr {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        });
        let ttl = ttl.unwrap_or(PING_DEFAULT_TTL);
        let timeout = timeout.unwrap_or(PING_DEFAULT_TIMEOUT);

        Ok(IcmpEchoRequestor {
            inner: Arc::new(RequestorInner {
                icmp: Arc::new(IcmpHandleOwner {
                    handle: icmp_handle,
                }),
                target_addr,
                source_addr,
                ttl,
                timeout,
                payload_len,
                #[cfg(test)]
                stats: Arc::new(RequestStats::default()),
            }),
        })
    }

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
    /// The requestor can be used multiple times and is safe to use concurrently
    /// from multiple async tasks.
    ///
    /// The future must be polled inside a Tokio runtime with the time driver enabled: the
    /// configured timeout is enforced with `tokio::time::timeout` independently of the
    /// driver, so the future resolves no later than the timeout (plus scheduling slack)
    /// even if the driver keeps the request pending. Dropping the future before it resolves
    /// is safe; the driver-owned reply buffer stays allocated until the driver completes
    /// the request.
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
    /// - The underlying Windows API call fails locally (for example with invalid
    ///   parameters or insufficient resources) instead of issuing the request
    /// - Internal communication channels fail unexpectedly
    ///
    /// Note that timeout and unreachable conditions are returned as successful
    /// `IcmpEchoReply` with appropriate status values, not as errors — also when the
    /// driver reports them immediately (for example "no route" to the destination).
    ///
    /// # Platform Notes
    ///
    /// The IPv4 driver reports its own timeouts at roughly 500 ms granularity and may
    /// complete a request slightly *before* the configured timeout; whichever deadline
    /// fires first produces the single `TimedOut` reply.
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
    ///     let reply = pinger.send().await?;
    ///
    ///     match reply.status() {
    ///         IcmpEchoStatus::Success => {
    ///             println!("Ping successful: {:?}", reply.round_trip_time());
    ///         }
    ///         IcmpEchoStatus::TimedOut => {
    ///             println!("Ping timed out");
    ///         }
    ///         _ => {
    ///             println!("Ping failed: {:?}", reply.status());
    ///         }
    ///     }
    ///
    ///     Ok(())
    /// }
    /// ```
    pub async fn send(&self) -> io::Result<IcmpEchoReply> {
        let (reply_tx, reply_rx) = oneshot::channel();

        self.handle_send(reply_tx)?;

        await_reply(self.inner.timeout, self.inner.target_addr, reply_rx).await
    }

    fn handle_send(&self, reply_tx: ReplySender) -> io::Result<()> {
        let inner = Arc::clone(&self.inner);
        start_request(
            &self.inner.request_params(),
            reply_tx,
            move |event, buffer, len| inner.do_send(event, buffer, len),
        )
    }
}

/// Waits for the result of a started request under the configured deadline.
///
/// A result that is already in the channel wins over an elapsed deadline: `timeout` polls
/// the receiver before its timer, so an outcome published synchronously by
/// [`start_request`] is returned even for a zero deadline. Only a request that is still
/// pending in the driver when the deadline elapses resolves as `TimedOut`.
async fn await_reply(
    timeout: Duration,
    target_addr: IpAddr,
    reply_rx: oneshot::Receiver<io::Result<IcmpEchoReply>>,
) -> io::Result<IcmpEchoReply> {
    match tokio::time::timeout(timeout, reply_rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_canceled)) => Err(io::Error::other("reply channel closed unexpectedly")),
        Err(_elapsed) => {
            // The deadline has been observed to pass: the outcome is decided.
            let completed_at = Instant::now();
            Ok(IcmpEchoReply::with_evidence(
                target_addr,
                IcmpEchoStatus::TimedOut,
                IcmpOutcome::LocalTimeout,
                None,
                None,
                timeout,
                completed_at,
            ))
        }
    }
}

impl RequestorInner {
    fn request_params(&self) -> RequestParams {
        RequestParams {
            icmp: Arc::clone(&self.icmp),
            target_addr: self.target_addr,
            timeout: self.timeout,
            #[cfg(test)]
            stats: Arc::clone(&self.stats),
        }
    }

    /// Starts the I/O for one request. `buffer` is the driver-owned reply buffer.
    fn do_send(&self, event: HANDLE, buffer: *mut u8, buffer_len: u32) -> SendOutcome {
        let ip_option = IP_OPTION_INFORMATION {
            Ttl: self.ttl,
            ..Default::default()
        };

        let req_data = vec![0u8; self.payload_len];
        let req_ptr = req_data.as_ptr().cast::<c_void>();
        let req_len = self.payload_len as u16;
        let timeout_ms = driver_timeout_ms(self.timeout);

        let ret = match (self.target_addr, self.source_addr) {
            (IpAddr::V4(taddr), IpAddr::V4(saddr)) => unsafe {
                IcmpSendEcho2Ex(
                    self.icmp.handle,
                    Some(event),
                    None,
                    None,
                    u32::from(saddr).to_be(),
                    u32::from(taddr).to_be(),
                    req_ptr,
                    req_len,
                    Some(&ip_option as *const _ as *const _),
                    buffer as *mut _,
                    buffer_len,
                    timeout_ms,
                )
            },
            (IpAddr::V6(taddr), IpAddr::V6(saddr)) => unsafe {
                let src_saddr: SOCKADDR_IN6 = SocketAddrV6::new(saddr, 0, 0, 0).into();
                let dst_saddr: SOCKADDR_IN6 = SocketAddrV6::new(taddr, 0, 0, 0).into();

                Icmp6SendEcho2(
                    self.icmp.handle,
                    Some(event),
                    None,
                    None,
                    &src_saddr,
                    &dst_saddr,
                    req_ptr,
                    req_len,
                    Some(&ip_option as *const _ as *const _),
                    buffer as *mut _,
                    buffer_len,
                    timeout_ms,
                )
            },
            _ => unreachable!("source and target address families are checked in new()"),
        };
        // Must be read immediately after the API call.
        let last_error = unsafe { GetLastError() }.0;

        classify_send_result(ret, last_error)
    }
}

/// Runs the request lifecycle: create the event, register the wait, publish the wait
/// handle, then start the I/O.
///
/// `start_io(event, buffer, buffer_len)` performs the actual I/O start (the icmpapi call in
/// production, a stub in tests). It runs strictly after the wait handle has been published,
/// while the event is still nonsignaled, so the callback cannot observe unpublished state.
///
/// After registration the callback owns its raw `Arc` reference exclusively; this function
/// never reclaims it. A synchronous completion or an immediate failure is published to
/// the caller *before this function returns* (see [`RequestContext`]), and the event is
/// then signalled by hand so that the callback still runs for cleanup.
fn start_request(
    params: &RequestParams,
    reply_tx: ReplySender,
    start_io: impl FnOnce(HANDLE, *mut u8, u32) -> SendOutcome,
) -> io::Result<()> {
    // Auto-reset, initially nonsignaled event for the completion wait.
    let event = unsafe { CreateEventW(None, false, false, None)? };

    let context = Arc::new(RequestContext::new(params, event, reply_tx));

    // Reference owned by the callback from now on.
    let callback_ref = Arc::into_raw(Arc::clone(&context));

    let mut wait_object = HANDLE::default();
    let registered = unsafe {
        RegisterWaitForSingleObject(
            &mut wait_object,
            event,
            Some(wait_callback),
            Some(callback_ref as *const c_void),
            INFINITE,
            WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE,
        )
    };
    if let Err(e) = registered {
        // Nothing is in flight and the callback can never run: reclaim its reference.
        // Dropping the last reference closes the event.
        // SAFETY: `callback_ref` came from Arc::into_raw above and was never handed to a
        // wait that could invoke the callback.
        drop(unsafe { Arc::from_raw(callback_ref) });
        return Err(e.into());
    }
    #[cfg(test)]
    params.stats.waits_registered.fetch_add(1, Ordering::SeqCst);

    // Publish the wait handle before anything can signal the event.
    context.wait_object.store(wait_object.0, Ordering::Release);

    let outcome = start_io(event, context.buffer_ptr(), context.buffer_len());
    if outcome == SendOutcome::Pending {
        return Ok(());
    }

    // The outcome is known now: publish it before returning, so that the caller's deadline
    // (even a zero one) cannot overtake it. `publish` serialises this with the callback:
    // if the driver signalled the event as well and the callback is already running,
    // exactly one of the two builds and sends the result, and either way the result is in
    // the channel by the time `publish` returns here.
    context.publish(|| match outcome {
        // SAFETY: the send API returned a reply count, so the driver has finished writing
        // the reply into the buffer.
        SendOutcome::Completed => unsafe { context.completion_result() },
        // The send API rejected the request before any I/O started.
        SendOutcome::Failed(code) => {
            immediate_failure_result(code, context.target_addr, context.timeout)
        }
        SendOutcome::Pending => unreachable!(),
    });

    // Signal the event by hand so the callback runs for cleanup (it finds the sender gone
    // and only unregisters the wait and releases its reference). If the driver signalled
    // it too, the second signal is harmless: the wait fires once and the event is only
    // closed by the last owner of the context. SetEvent cannot fail on a valid event we
    // created and have not closed; if it ever did, the caller still has its result and
    // only the cleanup is leaked — the context is never freed twice, because the
    // callback's reference is not reclaimed here.
    let _ = unsafe { SetEvent(event) };

    Ok(())
}

fn ip_error_to_icmp_outcome(code: u32) -> IcmpOutcome {
    match code {
        IP_SUCCESS => IcmpOutcome::EchoReply,
        IP_REQ_TIMED_OUT => IcmpOutcome::LocalTimeout,
        IP_TIME_EXCEEDED | IP_TTL_EXPIRED_REASSEM | IP_TTL_EXPIRED_TRANSIT => {
            IcmpOutcome::TimeExceeded
        }
        IP_DEST_NET_UNREACHABLE => IcmpOutcome::NetworkUnreachable,
        IP_DEST_HOST_UNREACHABLE => IcmpOutcome::HostUnreachable,
        IP_DEST_PORT_UNREACHABLE => IcmpOutcome::PortUnreachable,
        IP_DEST_PROT_UNREACHABLE => IcmpOutcome::ProtocolUnreachable,
        IP_DEST_SCOPE_MISMATCH | IP_DEST_UNREACHABLE => IcmpOutcome::DestinationUnreachable,
        code if code == ERROR_NETWORK_UNREACHABLE.0 => IcmpOutcome::NetworkUnreachable,
        code if code == ERROR_HOST_UNREACHABLE.0 => IcmpOutcome::HostUnreachable,
        code if code == ERROR_PROTOCOL_UNREACHABLE.0 => IcmpOutcome::ProtocolUnreachable,
        code if code == ERROR_PORT_UNREACHABLE.0 => IcmpOutcome::PortUnreachable,
        _ => IcmpOutcome::Other,
    }
}

fn ip_error_to_icmp_status(code: u32) -> IcmpEchoStatus {
    ip_error_to_icmp_outcome(code).coarse()
}

/// Completion callback: publishes the result of a request that was still pending when
/// `start_request` returned, and is the single cleanup path for every request.
///
/// Runs on a thread-pool wait thread once the event is signalled. It must not panic (a
/// panic in an `extern "system"` function aborts the process) and must not block.
unsafe extern "system" fn wait_callback(ptr: *mut c_void, _timer_fired: bool) {
    // SAFETY: `ptr` is the reference leaked with Arc::into_raw in start_request; the
    // callback runs at most once (WT_EXECUTEONLYONCE), so it is reclaimed exactly once.
    let context = Arc::from_raw(ptr as *const RequestContext);

    // A no-op if start_request already published a synchronous outcome (the buffer is
    // then not ours to parse). The lock is only ever held briefly by start_request, so
    // this does not block the wait thread in any meaningful way.
    // SAFETY: the event has been signalled, so the driver is done with the buffer.
    context.publish(|| context.completion_result());

    let wait_object = context.wait_object.load(Ordering::Acquire);
    if !wait_object.is_null() {
        // Non-blocking unregistration: a blocking one from inside the callback deadlocks.
        // From within the callback this reports ERROR_IO_PENDING, which means "accepted".
        let result = UnregisterWaitEx(HANDLE(wait_object), None);
        #[cfg(test)]
        {
            let accepted = match &result {
                Ok(()) => true,
                Err(e) => e.code() == ERROR_IO_PENDING.to_hresult(),
            };
            if accepted {
                context
                    .stats
                    .waits_registered
                    .fetch_sub(1, Ordering::SeqCst);
            }
        }
        #[cfg(not(test))]
        let _ = result;
    }

    // Drops the callback's reference; if it is the last one, the event is closed, the
    // buffer freed and the ICMP handle released.
    drop(context);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Weak;

    use windows::Win32::NetworkManagement::IpHelper::{
        IP_DEST_HOST_UNREACHABLE, IP_REQ_TIMED_OUT, IP_SUCCESS,
    };

    fn clean(stats: &RequestStats) -> bool {
        stats.contexts_live.load(Ordering::SeqCst) == 0
            && stats.waits_registered.load(Ordering::SeqCst) == 0
            && stats.events_open.load(Ordering::SeqCst) == 0
    }

    /// The reply's completion instant lies between `before` (taken before the request was
    /// started) and now.
    fn assert_completed_between(reply: &IcmpEchoReply, before: Instant) {
        let now = Instant::now();
        assert!(
            before <= reply.completed_at() && reply.completed_at() <= now,
            "completed_at {:?} must lie within [{before:?}, {now:?}]",
            reply.completed_at()
        );
    }

    async fn wait_until_clean(stats: &RequestStats, cap: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < cap {
            if clean(stats) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        clean(stats)
    }

    async fn wait_until_dead(weak: &Weak<IcmpHandleOwner>, cap: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < cap {
            if weak.upgrade().is_none() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        weak.upgrade().is_none()
    }

    fn snapshot(stats: &RequestStats) -> (usize, usize, usize) {
        (
            stats.contexts_live.load(Ordering::SeqCst),
            stats.waits_registered.load(Ordering::SeqCst),
            stats.events_open.load(Ordering::SeqCst),
        )
    }

    /// Requestor plus handles to its internals for hand-driven lifecycle tests.
    struct Fixture {
        requestor: IcmpEchoRequestor,
        stats: Arc<RequestStats>,
        weak_owner: Weak<IcmpHandleOwner>,
    }

    fn fixture(target: &str, timeout: Duration) -> Fixture {
        let requestor =
            IcmpEchoRequestor::new(target.parse().unwrap(), None, None, Some(timeout)).unwrap();
        let stats = Arc::clone(&requestor.inner.stats);
        let weak_owner = Arc::downgrade(&requestor.inner.icmp);
        Fixture {
            requestor,
            stats,
            weak_owner,
        }
    }

    /// Captured event handle of a stub-started request so the test can signal it by hand.
    #[derive(Clone, Default)]
    struct CapturedEvent(Arc<Mutex<Option<isize>>>);

    impl CapturedEvent {
        fn capture(&self, event: HANDLE) {
            *self.0.lock().unwrap() = Some(event.0 as isize);
        }

        fn signal(&self) {
            let raw = self.0.lock().unwrap().expect("event captured");
            unsafe { SetEvent(HANDLE(raw as *mut c_void)).unwrap() };
        }
    }

    /// Starts a request through the production lifecycle with a stub I/O starter.
    fn start_stub(fx: &Fixture, outcome: SendOutcome) -> (ReplyReceiver, CapturedEvent) {
        let (tx, rx) = oneshot::channel();
        let captured = CapturedEvent::default();
        let c = captured.clone();
        start_request(
            &fx.requestor.inner.request_params(),
            tx,
            move |event, _buf, _len| {
                c.capture(event);
                outcome
            },
        )
        .unwrap();
        (rx, captured)
    }

    // ---- pure classification helpers -------------------------------------------------

    #[test]
    fn responder_helpers_drop_unspecified_addresses() {
        assert_eq!(responder_v4(0), None);
        assert_eq!(
            responder_v4(u32::from_be(0xc0000201)),
            Some("192.0.2.1".parse().unwrap())
        );
        let mut unspecified = IN6_ADDR::default();
        unspecified.u.Byte = [0; 16];
        assert_eq!(responder_v6(unspecified), None);
        let mut responder = IN6_ADDR::default();
        responder.u.Byte = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(
            responder_v6(responder),
            Some("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn payload_length_accepts_boundaries_and_rejects_out_of_range() {
        for payload_len in [0, 1, 7, 8, 32, 56, 1024] {
            let requestor = IcmpEchoRequestor::with_payload_len(
                "127.0.0.1".parse().unwrap(),
                None,
                None,
                None,
                payload_len,
            )
            .unwrap();
            assert_eq!(requestor.payload_len(), payload_len);
        }
        for payload_len in [PING_MAX_REQUEST_DATA_LENGTH + 1, usize::MAX] {
            let result = IcmpEchoRequestor::with_payload_len(
                "127.0.0.1".parse().unwrap(),
                None,
                None,
                None,
                payload_len,
            );
            assert_eq!(
                result.as_ref().err().map(io::Error::kind),
                Some(io::ErrorKind::InvalidInput)
            );
        }
    }

    #[test]
    fn classify_send_result_table() {
        assert_eq!(classify_send_result(1, 0), SendOutcome::Completed);
        assert_eq!(classify_send_result(1, 12345), SendOutcome::Completed);
        assert_eq!(
            classify_send_result(0, ERROR_IO_PENDING.0),
            SendOutcome::Pending
        );
        assert_eq!(
            classify_send_result(ERROR_IO_PENDING.0, 0),
            SendOutcome::Pending
        );
        assert_eq!(
            classify_send_result(0, IP_REQ_TIMED_OUT),
            SendOutcome::Failed(IP_REQ_TIMED_OUT)
        );
        assert_eq!(classify_send_result(0, 0), SendOutcome::Failed(0));
    }

    #[test]
    fn failed_request_status_table() {
        assert_eq!(
            failed_request_status(IP_REQ_TIMED_OUT, 0),
            IcmpEchoStatus::TimedOut
        );
        assert_eq!(
            failed_request_status(0, IP_REQ_TIMED_OUT),
            IcmpEchoStatus::TimedOut
        );
        assert_eq!(
            failed_request_status(IP_DEST_HOST_UNREACHABLE, 0),
            IcmpEchoStatus::Unreachable
        );
        assert_eq!(failed_request_status(0, 0), IcmpEchoStatus::Unknown);
        assert_eq!(
            failed_request_status(0, IP_SUCCESS),
            IcmpEchoStatus::Unknown
        );
        // header wins over last_error when both are non-zero
        assert_eq!(
            failed_request_status(IP_DEST_HOST_UNREACHABLE, IP_REQ_TIMED_OUT),
            IcmpEchoStatus::Unreachable
        );
    }

    #[test]
    fn ip_error_to_icmp_status_table() {
        use windows::Win32::NetworkManagement::IpHelper::{
            IP_BUF_TOO_SMALL, IP_DEST_ADDR_UNREACHABLE, IP_DEST_NO_ROUTE, IP_DEST_PROHIBITED,
            IP_PARAM_PROBLEM,
        };
        assert_eq!(ip_error_to_icmp_status(IP_SUCCESS), IcmpEchoStatus::Success);
        assert_eq!(ip_error_to_icmp_outcome(IP_SUCCESS), IcmpOutcome::EchoReply);
        assert_eq!(
            ip_error_to_icmp_status(IP_REQ_TIMED_OUT),
            IcmpEchoStatus::TimedOut
        );
        assert_eq!(
            ip_error_to_icmp_outcome(IP_TIME_EXCEEDED),
            IcmpOutcome::TimeExceeded
        );
        assert_eq!(
            ip_error_to_icmp_status(IP_TIME_EXCEEDED),
            IcmpEchoStatus::Unreachable
        );
        for code in [
            IP_DEST_HOST_UNREACHABLE,
            IP_DEST_NO_ROUTE,
            IP_DEST_ADDR_UNREACHABLE,
            IP_DEST_PROHIBITED,
            IP_DEST_SCOPE_MISMATCH,
            ERROR_HOST_UNREACHABLE.0,
        ] {
            assert_eq!(
                ip_error_to_icmp_status(code),
                IcmpEchoStatus::Unreachable,
                "{code}"
            );
        }
        assert_eq!(
            ip_error_to_icmp_status(IP_PARAM_PROBLEM),
            IcmpEchoStatus::Unknown
        );
        assert_eq!(
            ip_error_to_icmp_status(IP_BUF_TOO_SMALL),
            IcmpEchoStatus::Unknown
        );
    }

    #[test]
    fn immediate_failure_result_table() {
        use windows::Win32::Foundation::{ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY};
        use windows::Win32::NetworkManagement::IpHelper::{IP_BUF_TOO_SMALL, IP_GENERAL_FAILURE};

        let target: IpAddr = "127.0.0.1".parse().unwrap();
        let timeout = Duration::from_millis(750);
        let before = Instant::now();
        // Every reply is stamped at classification: after `before`, no later than the check.
        let stamped_now = |reply: &IcmpEchoReply| {
            before <= reply.completed_at() && reply.completed_at() <= Instant::now()
        };

        // Echo outcomes the driver reports immediately are replies.
        let reply = immediate_failure_result(IP_REQ_TIMED_OUT, target, timeout).unwrap();
        assert_eq!(reply.status(), IcmpEchoStatus::TimedOut);
        assert_eq!(reply.outcome(), IcmpOutcome::LocalTimeout);
        assert_eq!(reply.round_trip_time(), timeout);
        assert_eq!(reply.destination(), target);
        assert!(stamped_now(&reply));
        let reply = immediate_failure_result(IP_DEST_HOST_UNREACHABLE, target, timeout).unwrap();
        assert_eq!(reply.status(), IcmpEchoStatus::Unreachable);
        assert_eq!(reply.outcome(), IcmpOutcome::HostUnreachable);
        assert_eq!(reply.round_trip_time(), Duration::ZERO);
        assert!(stamped_now(&reply));
        let reply = immediate_failure_result(ERROR_HOST_UNREACHABLE.0, target, timeout).unwrap();
        assert_eq!(reply.status(), IcmpEchoStatus::Unreachable);
        assert!(stamped_now(&reply));

        // Local Win32 failures keep their OS error code and kind.
        let err = immediate_failure_result(ERROR_INVALID_PARAMETER.0, target, timeout).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(ERROR_INVALID_PARAMETER.0 as i32));
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let err = immediate_failure_result(ERROR_NOT_ENOUGH_MEMORY.0, target, timeout).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(ERROR_NOT_ENOUGH_MEMORY.0 as i32));

        // IP_STATUS codes that are not echo outcomes are local failures too.
        for code in [IP_BUF_TOO_SMALL, IP_GENERAL_FAILURE, IP_PENDING] {
            let err = immediate_failure_result(code, target, timeout).unwrap_err();
            assert_eq!(err.raw_os_error(), None, "{code}");
            assert!(err.to_string().contains(&code.to_string()), "{err}");
        }
        // A rejection without an error code is never a Success reply.
        let err = immediate_failure_result(0, target, timeout).unwrap_err();
        assert_eq!(err.raw_os_error(), None);
    }

    #[test]
    fn driver_timeout_ms_table() {
        assert_eq!(driver_timeout_ms(Duration::ZERO), 1);
        assert_eq!(driver_timeout_ms(Duration::from_micros(500)), 1);
        assert_eq!(driver_timeout_ms(Duration::from_millis(1)), 1);
        assert_eq!(driver_timeout_ms(Duration::from_secs(1)), 1000);
        assert_eq!(driver_timeout_ms(Duration::from_secs(u64::MAX)), u32::MAX);
    }

    // ---- hand-signalled lifecycle (no network) --------------------------------------

    #[tokio::test]
    async fn stub_failed_timed_out_maps_and_cleans() {
        let fx = fixture("127.0.0.1", Duration::from_secs(1));
        let before = Instant::now();
        let (rx, _ev) = start_stub(&fx, SendOutcome::Failed(IP_REQ_TIMED_OUT));
        let reply = rx.await.unwrap().unwrap();
        assert_eq!(reply.status(), IcmpEchoStatus::TimedOut);
        assert_completed_between(&reply, before);
        assert!(wait_until_clean(&fx.stats, Duration::from_secs(2)).await);
    }

    #[tokio::test]
    async fn stub_failed_unreachable_maps_and_cleans() {
        let fx = fixture("127.0.0.1", Duration::from_secs(1));
        let before = Instant::now();
        let (rx, _ev) = start_stub(&fx, SendOutcome::Failed(IP_DEST_HOST_UNREACHABLE));
        let reply = rx.await.unwrap().unwrap();
        assert_eq!(reply.status(), IcmpEchoStatus::Unreachable);
        assert_completed_between(&reply, before);
        assert!(wait_until_clean(&fx.stats, Duration::from_secs(2)).await);
    }

    /// An immediate local failure of the send API surfaces as an `io::Error` carrying the
    /// Win32 code — not as an `Unknown` reply — is published before `start_request`
    /// returns (not by the wait thread), and releases every resource.
    #[tokio::test]
    async fn stub_failed_local_error_is_io_error_and_cleans() {
        use windows::Win32::Foundation::ERROR_INVALID_PARAMETER;

        let fx = fixture("127.0.0.1", Duration::from_secs(1));
        let (mut rx, _ev) = start_stub(&fx, SendOutcome::Failed(ERROR_INVALID_PARAMETER.0));
        let result = rx
            .try_recv()
            .expect("channel open")
            .expect("result must already be published when start_request returns");
        let err = result.expect_err("local failure must be an error");
        assert_eq!(err.raw_os_error(), Some(ERROR_INVALID_PARAMETER.0 as i32));
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(wait_until_clean(&fx.stats, Duration::from_secs(2)).await);
    }

    /// The public `send()` propagates that error through its deadline wrapper.
    #[tokio::test]
    async fn send_propagates_immediate_local_error() {
        use windows::Win32::Foundation::ERROR_NOT_SUPPORTED;

        let fx = fixture("127.0.0.1", Duration::from_secs(1));
        let (reply_tx, reply_rx) = oneshot::channel();
        start_request(
            &fx.requestor.inner.request_params(),
            reply_tx,
            |_event, _buf, _len| SendOutcome::Failed(ERROR_NOT_SUPPORTED.0),
        )
        .unwrap();
        let err = await_reply(
            fx.requestor.inner.timeout,
            fx.requestor.inner.target_addr,
            reply_rx,
        )
        .await
        .expect_err("local failure must be an error");
        assert_eq!(err.raw_os_error(), Some(ERROR_NOT_SUPPORTED.0 as i32));
        assert!(wait_until_clean(&fx.stats, Duration::from_secs(2)).await);
    }

    /// Mirrors `send()` for a stub-started request: start it, then wait under `deadline`
    /// exactly like the public method does.
    async fn send_like(
        fx: &Fixture,
        deadline: Duration,
        outcome: SendOutcome,
    ) -> io::Result<IcmpEchoReply> {
        let (reply_tx, reply_rx) = oneshot::channel();
        start_request(
            &fx.requestor.inner.request_params(),
            reply_tx,
            move |_event, _buf, _len| outcome,
        )
        .unwrap();
        await_reply(deadline, fx.requestor.inner.target_addr, reply_rx).await
    }

    /// Outcomes known when the send API returns must reach the caller even when the
    /// deadline has already elapsed: a zero (or sub-millisecond) deadline may never turn
    /// an immediate local failure into `Ok(TimedOut)`, nor an immediate remote outcome or
    /// a synchronous completion into a deadline timeout.
    #[tokio::test]
    async fn immediate_outcomes_beat_an_elapsed_deadline() {
        use windows::Win32::Foundation::ERROR_INVALID_PARAMETER;

        for deadline in [Duration::ZERO, Duration::from_micros(200)] {
            let fx = fixture("127.0.0.1", deadline);

            // Immediate local failure: an error, never a timeout reply.
            let err = send_like(
                &fx,
                deadline,
                SendOutcome::Failed(ERROR_INVALID_PARAMETER.0),
            )
            .await
            .expect_err("local failure must stay an error under a zero deadline");
            assert_eq!(err.raw_os_error(), Some(ERROR_INVALID_PARAMETER.0 as i32));

            // Immediate remote outcome: the driver's status, not the deadline's.
            let reply = send_like(&fx, deadline, SendOutcome::Failed(IP_DEST_HOST_UNREACHABLE))
                .await
                .unwrap();
            assert_eq!(reply.status(), IcmpEchoStatus::Unreachable);

            // Synchronous completion: the (stub, zeroed) buffer is parsed and published by
            // start_request itself, i.e. the result is in the channel before the caller
            // even starts its deadline — which is what makes `await_reply` return it.
            let (mut rx, _ev) = start_stub(&fx, SendOutcome::Completed);
            let published = rx
                .try_recv()
                .expect("channel open")
                .expect("synchronous completion must be published before start_request returns");
            let reply = published.expect("a completed request is a reply, not an error");
            assert_ne!(reply.status(), IcmpEchoStatus::Success);

            assert!(wait_until_clean(&fx.stats, Duration::from_secs(2)).await);
        }
    }

    /// A synchronous completion for which the driver *also* signals the event, so the wait
    /// callback contends with `start_request` for publishing. Whichever wins, the result
    /// must be in the channel when `start_request` returns — never can a zero deadline
    /// find the channel empty because the callback took the sender but has not sent yet.
    /// `callback_head_start` makes the callback win deterministically; `None` lets them race.
    async fn contended_synchronous_completion(callback_head_start: Option<Duration>) {
        let fx = fixture("127.0.0.1", Duration::ZERO);
        for i in 0..200 {
            let (reply_tx, mut reply_rx) = oneshot::channel();
            start_request(
                &fx.requestor.inner.request_params(),
                reply_tx,
                move |event, _buf, _len| {
                    // The driver signals the event for a synchronous completion.
                    unsafe { SetEvent(event).unwrap() };
                    if let Some(head_start) = callback_head_start {
                        std::thread::sleep(head_start);
                    }
                    SendOutcome::Completed
                },
            )
            .unwrap();
            let published = reply_rx
                .try_recv()
                .expect("channel open")
                .unwrap_or_else(|| {
                    panic!("iteration {i}: result not published when start_request returned")
                });
            let reply = published.expect("a completed request is a reply, not an error");
            assert_ne!(reply.status(), IcmpEchoStatus::Success);
        }
        assert!(wait_until_clean(&fx.stats, Duration::from_secs(5)).await);
    }

    #[tokio::test]
    async fn contended_synchronous_completion_racing_callback() {
        contended_synchronous_completion(None).await;
    }

    #[tokio::test]
    async fn contended_synchronous_completion_callback_first() {
        contended_synchronous_completion(Some(Duration::from_millis(2))).await;
    }

    /// The same through the deadline wrapper, as `send()` does it: a zero deadline must
    /// return the completed request's reply, not the deadline's `TimedOut`. The context
    /// is given a 1 s timeout while the deadline is zero, so the two are distinguishable
    /// by value: a published reply that parses as a timeout carries rtt = 1 s, the
    /// deadline path's `TimedOut` carries rtt = 0.
    #[tokio::test]
    async fn contended_synchronous_completion_beats_zero_deadline() {
        let fx = fixture("127.0.0.1", Duration::from_secs(1));
        for i in 0..50 {
            let (reply_tx, reply_rx) = oneshot::channel();
            start_request(
                &fx.requestor.inner.request_params(),
                reply_tx,
                |event, _buf, _len| {
                    unsafe { SetEvent(event).unwrap() };
                    std::thread::sleep(Duration::from_millis(1));
                    SendOutcome::Completed
                },
            )
            .unwrap();
            let reply = await_reply(Duration::ZERO, fx.requestor.inner.target_addr, reply_rx)
                .await
                .unwrap();
            assert_ne!(reply.status(), IcmpEchoStatus::Success);
            assert!(
                !(reply.status() == IcmpEchoStatus::TimedOut
                    && reply.round_trip_time() == Duration::ZERO),
                "iteration {i}: the deadline overtook a synchronous completion: {reply:?}"
            );
        }
        assert!(wait_until_clean(&fx.stats, Duration::from_secs(5)).await);
    }

    #[tokio::test]
    async fn stub_pending_hand_signalled_completes_once() {
        let fx = fixture("127.0.0.1", Duration::from_secs(1));
        let (rx, ev) = start_stub(&fx, SendOutcome::Pending);
        assert_eq!(snapshot(&fx.stats), (1, 1, 1));
        ev.signal();
        let reply = rx.await.unwrap().unwrap();
        assert_ne!(reply.status(), IcmpEchoStatus::Success);
        assert!(wait_until_clean(&fx.stats, Duration::from_secs(2)).await);
    }

    #[tokio::test]
    async fn stub_pending_completion_before_normal_deadline() {
        let fx = fixture("::1", Duration::from_secs(1));
        let (rx, ev) = start_stub(&fx, SendOutcome::Pending);
        let start = Instant::now();
        let signaller = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            ev.signal();
        });
        let result = tokio::time::timeout(Duration::from_secs(1), rx).await;
        assert!(result.is_ok(), "completion must win before the deadline");
        assert!(start.elapsed() < Duration::from_millis(900));
        signaller.await.unwrap();
        assert!(wait_until_clean(&fx.stats, Duration::from_secs(2)).await);
    }

    async fn deadline_expires_then_late_signal(deadline: Duration) {
        let fx = fixture("127.0.0.1", Duration::from_secs(1));
        let (rx, ev) = start_stub(&fx, SendOutcome::Pending);
        let start = Instant::now();
        let result = tokio::time::timeout(deadline, rx).await;
        assert!(result.is_err(), "deadline must elapse");
        assert!(start.elapsed() < Duration::from_millis(250));
        // The future stopped waiting, but the "driver" is still busy: nothing freed early.
        assert_eq!(snapshot(&fx.stats), (1, 1, 1));
        tokio::time::sleep(Duration::from_millis(300).saturating_sub(start.elapsed())).await;
        ev.signal();
        assert!(wait_until_clean(&fx.stats, Duration::from_secs(2)).await);
    }

    #[tokio::test]
    async fn stub_pending_normal_deadline_expires_late_signal_cleans() {
        deadline_expires_then_late_signal(Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn stub_pending_zero_deadline_late_signal_cleans() {
        deadline_expires_then_late_signal(Duration::ZERO).await;
    }

    #[tokio::test]
    async fn stub_pending_sub_millisecond_deadline_late_signal_cleans() {
        deadline_expires_then_late_signal(Duration::from_micros(200)).await;
    }

    #[tokio::test]
    async fn stub_completed_drives_callback_via_manual_signal() {
        let fx = fixture("127.0.0.1", Duration::from_secs(1));
        let before = Instant::now();
        let (rx, _ev) = start_stub(&fx, SendOutcome::Completed);
        let result = tokio::time::timeout(Duration::from_secs(1), rx).await;
        let reply = result
            .expect("manual SetEvent must complete the request before the deadline")
            .unwrap()
            .unwrap();
        assert_ne!(reply.status(), IcmpEchoStatus::Success);
        // The zeroed stub buffer does not parse, so this reply was built by `failed_reply`.
        assert_completed_between(&reply, before);
        assert!(wait_until_clean(&fx.stats, Duration::from_secs(2)).await);
    }

    /// The deadline wrapper stamps its `TimedOut` when the timer fires: never before the
    /// deadline, never after the caller observes the reply.
    #[tokio::test]
    async fn await_reply_deadline_stamps_completion() {
        let fx = fixture("127.0.0.1", Duration::from_secs(1));
        let (rx, ev) = start_stub(&fx, SendOutcome::Pending);
        let deadline = Duration::from_millis(50);
        let before = Instant::now();
        let reply = await_reply(deadline, fx.requestor.inner.target_addr, rx)
            .await
            .unwrap();
        let after = Instant::now();
        assert_eq!(reply.status(), IcmpEchoStatus::TimedOut);
        assert_eq!(reply.round_trip_time(), deadline);
        assert!(
            before + deadline <= reply.completed_at() && reply.completed_at() <= after,
            "completed_at {:?} must lie within [{:?}, {after:?}]",
            reply.completed_at(),
            before + deadline
        );
        // The "driver" is still busy; signal it so the callback cleans up.
        ev.signal();
        assert!(wait_until_clean(&fx.stats, Duration::from_secs(2)).await);
    }

    // ---- real loopback ---------------------------------------------------------------

    async fn loopback_with_timeout(target: &str, timeout: Duration) {
        let fx = fixture(target, timeout);
        let reply = fx.requestor.send().await.unwrap();
        assert!(
            matches!(
                reply.status(),
                IcmpEchoStatus::TimedOut | IcmpEchoStatus::Success
            ),
            "unexpected status {:?}",
            reply.status()
        );
        assert!(wait_until_clean(&fx.stats, Duration::from_secs(2)).await);
    }

    #[tokio::test]
    async fn loopback_zero_timeout_v4() {
        loopback_with_timeout("127.0.0.1", Duration::ZERO).await;
    }

    #[tokio::test]
    async fn loopback_zero_timeout_v6() {
        loopback_with_timeout("::1", Duration::ZERO).await;
    }

    #[tokio::test]
    async fn loopback_sub_millisecond_timeout_v4() {
        loopback_with_timeout("127.0.0.1", Duration::from_micros(500)).await;
    }

    #[tokio::test]
    async fn loopback_sub_millisecond_timeout_v6() {
        loopback_with_timeout("::1", Duration::from_micros(500)).await;
    }

    #[tokio::test]
    async fn cancellation_stress_leaks_nothing() {
        let fx = fixture("127.0.0.1", Duration::from_secs(1));
        let mut survivors = Vec::new();
        for i in 0..200 {
            let requestor = fx.requestor.clone();
            if i % 2 == 0 {
                // Dropped mid-flight.
                let _ = tokio::time::timeout(Duration::from_millis(1), requestor.send()).await;
            } else {
                survivors.push(tokio::spawn(async move { requestor.send().await }));
            }
        }
        for handle in survivors {
            let reply = handle.await.unwrap().unwrap();
            assert!(matches!(
                reply.status(),
                IcmpEchoStatus::Success | IcmpEchoStatus::TimedOut
            ));
        }
        assert!(wait_until_clean(&fx.stats, Duration::from_secs(5)).await);

        let Fixture {
            requestor, stats, ..
        } = fx;
        let start = Instant::now();
        drop(requestor);
        assert!(start.elapsed() < Duration::from_millis(100));
        assert!(clean(&stats));
    }

    #[tokio::test]
    async fn requestor_drop_does_not_block_with_outstanding_request() {
        let fx = fixture("127.0.0.1", Duration::from_secs(2));
        let (rx, ev) = start_stub(&fx, SendOutcome::Pending);
        let Fixture {
            requestor,
            stats,
            weak_owner,
        } = fx;

        let start = Instant::now();
        drop(requestor);
        assert!(
            start.elapsed() < Duration::from_millis(100),
            "dropping the requestor must not wait for the outstanding request"
        );
        assert!(
            weak_owner.upgrade().is_some(),
            "the outstanding context keeps the ICMP handle open"
        );
        assert_eq!(stats.contexts_live.load(Ordering::SeqCst), 1);

        ev.signal();
        let _ = rx.await;
        assert!(wait_until_clean(&stats, Duration::from_secs(2)).await);
        assert!(
            wait_until_dead(&weak_owner, Duration::from_secs(2)).await,
            "the last completion must close the ICMP handle"
        );
    }

    /// Supplemental real-network variant against a black-hole IPv4 address; also the IPv4
    /// measurement that the driver completes an asynchronous request at its own timeout.
    #[tokio::test]
    async fn requestor_drop_with_real_pending_request_v4() {
        let fx = fixture("192.0.2.1", Duration::from_secs(2));
        let first = tokio::time::timeout(Duration::from_millis(50), fx.requestor.send()).await;
        if let Ok(Ok(reply)) = &first {
            if reply.status() != IcmpEchoStatus::TimedOut {
                println!(
                    "no route to 192.0.2.1 ({:?}); skipping timing part",
                    reply.status()
                );
                return;
            }
        }
        let Fixture {
            requestor,
            stats,
            weak_owner,
        } = fx;
        let start = Instant::now();
        drop(requestor);
        assert!(start.elapsed() < Duration::from_millis(200));
        assert!(wait_until_dead(&weak_owner, Duration::from_secs(3)).await);
        assert!(clean(&stats));
    }

    /// Measurement of the asynchronous IPv6 driver timeout: run with
    /// `PING_ASYNC_V6_BLACKHOLE_TARGET=<routed, non-responding IPv6 address>` (for example
    /// an address in the RFC 6666 discard prefix `100::/64` when a global IPv6 route exists,
    /// or a link-local address with no host such as `fe80::dead:beef`):
    ///
    /// `PING_ASYNC_V6_BLACKHOLE_TARGET=fe80::dead:beef cargo test -- --ignored ipv6_blackhole`
    ///
    /// `send()` must resolve by the Tokio deadline, and after the requestor is dropped the
    /// driver must complete the request so that every resource is released. A link-local
    /// target can also produce an early `Unreachable` (neighbour discovery failure); that is
    /// a driver completion too, so the test retries a few times to obtain a `TimedOut`
    /// sample — the measurement this test exists for.
    ///
    /// Measured on Windows 11 22631: the IPv6 driver completes with `IP_REQ_TIMED_OUT` at
    /// roughly 1.5 s for a 2 s timeout (its own coarse timer), i.e. it does honour the
    /// `Timeout` of an asynchronous request despite the MS Learn wording.
    #[tokio::test]
    #[ignore]
    async fn ipv6_blackhole_driver_completes_and_cleans() {
        let target = std::env::var("PING_ASYNC_V6_BLACKHOLE_TARGET")
            .expect("set PING_ASYNC_V6_BLACKHOLE_TARGET to a routed, non-responding IPv6 address");
        let timeout = Duration::from_secs(2);
        let fx = fixture(&target, timeout);

        let mut got_timed_out = false;
        for attempt in 1..=3 {
            let start = Instant::now();
            let reply = fx.requestor.send().await.unwrap();
            let elapsed = start.elapsed();
            println!("attempt {attempt}: {reply:?} after {elapsed:?}");
            assert!(
                elapsed < timeout + Duration::from_millis(500),
                "took {elapsed:?}"
            );
            match reply.status() {
                IcmpEchoStatus::TimedOut => {
                    got_timed_out = true;
                    break;
                }
                // Early driver completion (neighbour discovery failed); try again.
                IcmpEchoStatus::Unreachable => {
                    assert!(wait_until_clean(&fx.stats, Duration::from_secs(2)).await);
                }
                other => panic!("unexpected status {other:?} for a black-hole target"),
            }
        }
        assert!(got_timed_out, "never observed TimedOut for {target}");

        let Fixture {
            requestor,
            stats,
            weak_owner,
        } = fx;
        drop(requestor);
        assert!(
            wait_until_clean(&stats, timeout + Duration::from_secs(5)).await,
            "IPv6 driver did not complete the request: {:?}",
            snapshot(&stats)
        );
        assert!(wait_until_dead(&weak_owner, Duration::from_secs(1)).await);
    }
}
