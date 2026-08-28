// platform/windows.rs

use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV6};
use std::ptr;
use std::sync::atomic::{AtomicI64, AtomicPtr, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
    IP_DEST_PROT_UNREACHABLE, IP_DEST_UNREACHABLE, IP_REQ_TIMED_OUT, IP_SUCCESS, IP_TIME_EXCEEDED,
    IP_TTL_EXPIRED_REASSEM, IP_TTL_EXPIRED_TRANSIT,
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
    IcmpEchoReply, IcmpEchoStatus, PING_DEFAULT_REQUEST_DATA_LENGTH, PING_DEFAULT_TIMEOUT,
    PING_DEFAULT_TTL,
};

const REPLY_BUFFER_SIZE: usize = 100;

// we don't provide request data, so no need of allocating space for it
const_assert!(
    size_of::<ICMP_ECHO_REPLY>()
        + PING_DEFAULT_REQUEST_DATA_LENGTH
        + 8
        + size_of::<IO_STATUS_BLOCK>()
        <= REPLY_BUFFER_SIZE
);
const_assert!(
    size_of::<ICMPV6_ECHO_REPLY>()
        + PING_DEFAULT_REQUEST_DATA_LENGTH
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
/// `Arc::into_raw` and reclaimed there with `Arc::from_raw`. The callback is the single
/// completion path: only it parses the buffer, delivers the reply and unregisters the wait.
struct RequestContext {
    /// Keeps the ICMP handle open until this context is dropped (never read).
    _icmp: Arc<IcmpHandleOwner>,
    #[cfg(test)]
    stats: Arc<RequestStats>,
    event: HANDLE,
    /// Wait handle from `RegisterWaitForSingleObject`; published before any I/O starts.
    wait_object: AtomicPtr<c_void>,
    /// `-1` = none; otherwise the error code of an immediately failed send, folded into
    /// the callback path by signalling the event by hand.
    immediate_error: AtomicI64,
    /// Written by the driver while a request is in flight; only ever accessed through raw
    /// pointers, never through a Rust reference.
    buffer: Box<UnsafeCell<ReplyBuffer>>,
    target_addr: IpAddr,
    timeout: Duration,
    sender: Mutex<Option<oneshot::Sender<IcmpEchoReply>>>,
}

// SAFETY: the raw handles are only used with thread-safe Win32 functions, and the
// driver-written buffer is never touched through a reference while a request is in flight
// (see `buffer` above).
unsafe impl Send for RequestContext {}
unsafe impl Sync for RequestContext {}

impl RequestContext {
    fn new(params: &RequestParams, event: HANDLE, sender: oneshot::Sender<IcmpEchoReply>) -> Self {
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
            immediate_error: AtomicI64::new(-1),
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

    /// Builds the reply for a completed request. Called from the wait callback only, after
    /// the driver (or our own `SetEvent`) signalled the event. Must not panic.
    ///
    /// # Safety
    ///
    /// The driver must no longer be writing to the buffer (the event has been signalled).
    unsafe fn completion_reply(&self) -> IcmpEchoReply {
        let immediate = self.immediate_error.load(Ordering::Acquire);
        if immediate >= 0 {
            // The send API failed before any I/O started; nothing in the buffer.
            let status = failed_request_status(immediate as u32, 0);
            return IcmpEchoReply::new(self.target_addr, status, Duration::ZERO);
        }

        let buf = self.buffer_ptr().cast::<c_void>();
        let len = self.buffer_len();

        match self.target_addr {
            IpAddr::V4(_) => {
                let parsed = IcmpParseReplies(buf, len);
                let last_error = GetLastError().0;
                let header: ICMP_ECHO_REPLY = ptr::read_unaligned(buf.cast::<ICMP_ECHO_REPLY>());

                if parsed != 0 {
                    let addr = IpAddr::V4(u32::from_be(header.Address).into());
                    IcmpEchoReply::new(
                        addr,
                        ip_error_to_icmp_status(header.Status),
                        Duration::from_millis(header.RoundTripTime.into()),
                    )
                } else {
                    self.failed_reply(failed_request_status(header.Status, last_error))
                }
            }
            IpAddr::V6(_) => {
                let parsed = Icmp6ParseReplies(buf, len);
                let last_error = GetLastError().0;
                let header: ICMPV6_ECHO_REPLY =
                    ptr::read_unaligned(buf.cast::<ICMPV6_ECHO_REPLY>());

                if parsed != 0 {
                    let mut addr_raw = IN6_ADDR::default();
                    addr_raw.u.Word = header.Address.sin6_addr;
                    let addr = IpAddr::V6(addr_raw.into());
                    IcmpEchoReply::new(
                        addr,
                        ip_error_to_icmp_status(header.Status),
                        Duration::from_millis(header.RoundTripTime.into()),
                    )
                } else {
                    self.failed_reply(failed_request_status(header.Status, last_error))
                }
            }
        }
    }

    fn failed_reply(&self, status: IcmpEchoStatus) -> IcmpEchoReply {
        let rtt = if status == IcmpEchoStatus::TimedOut {
            self.timeout
        } else {
            Duration::ZERO
        };
        IcmpEchoReply::new(self.target_addr, status, rtt)
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

/// Status of a request that did not produce a parsed reply.
///
/// Precedence: the reply header's `Status` if non-zero (the buffer is zero-initialised by
/// us, so non-zero is meaningful), then `GetLastError()` if non-zero, else `Unknown`. A
/// failed request is never reported as `Success`.
fn failed_request_status(header_status: u32, last_error: u32) -> IcmpEchoStatus {
    let code = if header_status != 0 {
        header_status
    } else {
        last_error
    };
    if code == 0 {
        return IcmpEchoStatus::Unknown;
    }
    match ip_error_to_icmp_status(code) {
        IcmpEchoStatus::Success => IcmpEchoStatus::Unknown,
        status => status,
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
                #[cfg(test)]
                stats: Arc::new(RequestStats::default()),
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
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The underlying Windows API call fails
    /// - Internal communication channels fail unexpectedly
    ///
    /// Note that timeout and unreachable conditions are returned as successful
    /// `IcmpEchoReply` with appropriate status values, not as errors.
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

        match tokio::time::timeout(self.inner.timeout, reply_rx).await {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(_canceled)) => Err(io::Error::other("reply channel closed unexpectedly")),
            Err(_elapsed) => Ok(IcmpEchoReply::new(
                self.inner.target_addr,
                IcmpEchoStatus::TimedOut,
                self.inner.timeout,
            )),
        }
    }

    fn handle_send(&self, reply_tx: oneshot::Sender<IcmpEchoReply>) -> io::Result<()> {
        let inner = Arc::clone(&self.inner);
        start_request(
            &self.inner.request_params(),
            reply_tx,
            move |event, buffer, len| inner.do_send(event, buffer, len),
        )
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

        let req_data = [0u8; PING_DEFAULT_REQUEST_DATA_LENGTH];
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
                    req_data.as_ptr() as *const _,
                    req_data.len() as u16,
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
                    req_data.as_ptr() as *const _,
                    req_data.len() as u16,
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
/// never reclaims it. Synchronous completion and immediate failure are folded into the
/// callback path by signalling the event by hand.
fn start_request(
    params: &RequestParams,
    reply_tx: oneshot::Sender<IcmpEchoReply>,
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

    match start_io(event, context.buffer_ptr(), context.buffer_len()) {
        SendOutcome::Pending => {}
        SendOutcome::Completed => {
            // The reply is already in the buffer; drive the normal completion path. If the
            // driver also signalled the event, the second signal is harmless: the wait fires
            // once and the event is only closed by the last owner of the context.
            let _ = unsafe { SetEvent(event) };
        }
        SendOutcome::Failed(code) => {
            context
                .immediate_error
                .store(i64::from(code), Ordering::Release);
            let _ = unsafe { SetEvent(event) };
        }
    }
    // SetEvent cannot fail on a valid event we created and have not closed; if it ever did,
    // the request resolves through the caller's deadline and the context is leaked — it is
    // never freed twice, because the callback's reference is not reclaimed here.

    Ok(())
}

fn ip_error_to_icmp_status(code: u32) -> IcmpEchoStatus {
    match code {
        IP_SUCCESS => IcmpEchoStatus::Success,
        IP_REQ_TIMED_OUT | IP_TIME_EXCEEDED | IP_TTL_EXPIRED_REASSEM | IP_TTL_EXPIRED_TRANSIT => {
            IcmpEchoStatus::TimedOut
        }
        IP_DEST_HOST_UNREACHABLE
        | IP_DEST_NET_UNREACHABLE
        | IP_DEST_PORT_UNREACHABLE
        | IP_DEST_PROT_UNREACHABLE
        | IP_DEST_UNREACHABLE => IcmpEchoStatus::Unreachable,
        code if code == ERROR_NETWORK_UNREACHABLE.0
            || code == ERROR_HOST_UNREACHABLE.0
            || code == ERROR_PROTOCOL_UNREACHABLE.0
            || code == ERROR_PORT_UNREACHABLE.0 =>
        {
            IcmpEchoStatus::Unreachable
        }
        _ => IcmpEchoStatus::Unknown,
    }
}

/// Completion callback: the single completion path for a request.
///
/// Runs on a thread-pool wait thread once the event is signalled. It must not panic (a
/// panic in an `extern "system"` function aborts the process) and must not block.
unsafe extern "system" fn wait_callback(ptr: *mut c_void, _timer_fired: bool) {
    // SAFETY: `ptr` is the reference leaked with Arc::into_raw in start_request; the
    // callback runs at most once (WT_EXECUTEONLYONCE), so it is reclaimed exactly once.
    let context = Arc::from_raw(ptr as *const RequestContext);

    let reply = context.completion_reply();

    let sender = context
        .sender
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    if let Some(sender) = sender {
        // The receiver may already be gone (deadline elapsed or future dropped).
        let _ = sender.send(reply);
    }

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
    use std::time::Instant;

    use windows::Win32::NetworkManagement::IpHelper::{
        IP_DEST_HOST_UNREACHABLE, IP_REQ_TIMED_OUT, IP_SUCCESS,
    };

    fn clean(stats: &RequestStats) -> bool {
        stats.contexts_live.load(Ordering::SeqCst) == 0
            && stats.waits_registered.load(Ordering::SeqCst) == 0
            && stats.events_open.load(Ordering::SeqCst) == 0
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
    fn start_stub(
        fx: &Fixture,
        outcome: SendOutcome,
    ) -> (oneshot::Receiver<IcmpEchoReply>, CapturedEvent) {
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
        let (rx, _ev) = start_stub(&fx, SendOutcome::Failed(IP_REQ_TIMED_OUT));
        let reply = rx.await.unwrap();
        assert_eq!(reply.status(), IcmpEchoStatus::TimedOut);
        assert!(wait_until_clean(&fx.stats, Duration::from_secs(2)).await);
    }

    #[tokio::test]
    async fn stub_failed_unreachable_maps_and_cleans() {
        let fx = fixture("127.0.0.1", Duration::from_secs(1));
        let (rx, _ev) = start_stub(&fx, SendOutcome::Failed(IP_DEST_HOST_UNREACHABLE));
        let reply = rx.await.unwrap();
        assert_eq!(reply.status(), IcmpEchoStatus::Unreachable);
        assert!(wait_until_clean(&fx.stats, Duration::from_secs(2)).await);
    }

    #[tokio::test]
    async fn stub_pending_hand_signalled_completes_once() {
        let fx = fixture("127.0.0.1", Duration::from_secs(1));
        let (rx, ev) = start_stub(&fx, SendOutcome::Pending);
        assert_eq!(snapshot(&fx.stats), (1, 1, 1));
        ev.signal();
        let reply = rx.await.unwrap();
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
        let (rx, _ev) = start_stub(&fx, SendOutcome::Completed);
        let result = tokio::time::timeout(Duration::from_secs(1), rx).await;
        let reply = result
            .expect("manual SetEvent must complete the request before the deadline")
            .unwrap();
        assert_ne!(reply.status(), IcmpEchoStatus::Success);
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
