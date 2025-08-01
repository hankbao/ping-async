// platform/windows.rs

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

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
    CreateEventW, RegisterWaitForSingleObject, UnregisterWaitEx, INFINITE, WT_EXECUTEINWAITTHREAD,
    WT_EXECUTEONLYONCE,
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

struct RequestContext {
    wait_object: HANDLE,
    event: HANDLE,
    buffer: Box<[u8]>,
    target_addr: IpAddr,
    timeout: Duration,
    sender: oneshot::Sender<IcmpEchoReply>,
}

impl RequestContext {
    fn new(
        event: HANDLE,
        target_addr: IpAddr,
        timeout: Duration,
        sender: oneshot::Sender<IcmpEchoReply>,
    ) -> Self {
        RequestContext {
            wait_object: HANDLE::default(),
            event,
            buffer: vec![0u8; REPLY_BUFFER_SIZE].into_boxed_slice(),
            target_addr,
            timeout,
            sender,
        }
    }

    fn buffer_ptr(&mut self) -> *mut u8 {
        self.buffer.as_mut_ptr()
    }

    fn buffer_size(&self) -> usize {
        self.buffer.len()
    }
}

/// Requestor for sending ICMP Echo Requests (ping) and receiving replies on Windows.
///
/// This implementation uses Windows-specific APIs (`IcmpSendEcho2Ex` and `Icmp6SendEcho2`)
/// that provide unprivileged ICMP functionality without requiring administrator rights.
/// The requestor is safe to clone and use across multiple threads and async tasks.
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
    icmp_handle: HANDLE,
    target_addr: IpAddr,
    source_addr: IpAddr,
    ttl: u8,
    timeout: Duration,
}

// Windows HANDLEs are safe to send/sync when used properly
unsafe impl Send for RequestorInner {}
unsafe impl Sync for RequestorInner {}

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
                icmp_handle,
                target_addr,
                source_addr,
                ttl,
                timeout,
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

        reply_rx
            .await
            .map_err(|_| io::Error::other("reply channel closed unexpectedly"))
    }

    fn handle_send(&self, reply_tx: oneshot::Sender<IcmpEchoReply>) -> io::Result<()> {
        // Event for the wait callback when ICMP reply is ready
        let event = unsafe { CreateEventW(None, false, false, None)? };

        // Create context for this specific request
        let context_raw = Box::into_raw(Box::new(RequestContext::new(
            event,
            self.inner.target_addr,
            self.inner.timeout,
            reply_tx,
        )));

        // Send ICMP request first
        match self.do_send(context_raw, event) {
            Ok(()) => {
                // ICMP request is pending, now register wait callback
                unsafe {
                    match RegisterWaitForSingleObject(
                        &mut (*context_raw).wait_object,
                        event,
                        Some(wait_callback),
                        Some(context_raw as *const _),
                        INFINITE,
                        WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE,
                    ) {
                        Ok(()) => Ok(()),
                        Err(e) => {
                            // Registration failed, wait_callback will not be called
                            // We have to clean up resources here
                            let _ = CloseHandle(event);
                            drop(Box::from_raw(context_raw));

                            Err(e.into())
                        }
                    }
                }
            }
            Err(e) => {
                // ICMP send failed immediately, handle error and cleanup
                let status = ip_error_to_icmp_status(e);
                let reply = IcmpEchoReply::new(self.inner.target_addr, status, Duration::ZERO);

                unsafe {
                    // Send the reply back through the channel, then clean up
                    let ctx = Box::from_raw(context_raw);
                    let _ = ctx.sender.send(reply);

                    // No need to unregister wait, as it was never registered

                    // Close the event handle
                    if !ctx.event.is_invalid() {
                        let _ = CloseHandle(ctx.event);
                    }

                    // Context drops automatically here
                }

                // Since we have sent an error reply, no error is returned
                Ok(())
            }
        }
    }

    fn do_send(&self, context: *mut RequestContext, event: HANDLE) -> Result<(), u32> {
        let ip_option = IP_OPTION_INFORMATION {
            Ttl: self.inner.ttl,
            ..Default::default()
        };

        let req_data = [0u8; PING_DEFAULT_REQUEST_DATA_LENGTH];

        let error = match self.inner.target_addr {
            IpAddr::V4(taddr) => {
                let saddr = if let IpAddr::V4(saddr) = self.inner.source_addr {
                    saddr
                } else {
                    unreachable!("source address must be IPv4 for IPv4 target");
                };

                unsafe {
                    let ctx = context.as_mut().unwrap();

                    IcmpSendEcho2Ex(
                        self.inner.icmp_handle,
                        Some(event),
                        None,
                        None,
                        u32::from(saddr).to_be(),
                        u32::from(taddr).to_be(),
                        req_data.as_ptr() as *const _,
                        req_data.len() as u16,
                        Some(&ip_option as *const _ as *const _),
                        ctx.buffer_ptr() as *mut _,
                        ctx.buffer_size() as u32,
                        self.inner.timeout.as_millis() as u32,
                    )
                }
            }
            IpAddr::V6(taddr) => {
                let saddr = if let IpAddr::V6(saddr) = self.inner.source_addr {
                    saddr
                } else {
                    unreachable!("source address must be IPv6 for IPv6 target");
                };

                unsafe {
                    let ctx = context.as_mut().unwrap();

                    let src_saddr: SOCKADDR_IN6 = SocketAddrV6::new(saddr, 0, 0, 0).into();
                    let dst_saddr: SOCKADDR_IN6 = SocketAddrV6::new(taddr, 0, 0, 0).into();

                    Icmp6SendEcho2(
                        self.inner.icmp_handle,
                        Some(event),
                        None,
                        None,
                        &src_saddr,
                        &dst_saddr,
                        req_data.as_ptr() as *const _,
                        req_data.len() as u16,
                        Some(&ip_option as *const _ as *const _),
                        ctx.buffer_ptr() as *mut _,
                        ctx.buffer_size() as u32,
                        self.inner.timeout.as_millis() as u32,
                    )
                }
            }
        };

        if error == ERROR_IO_PENDING.0 {
            Ok(())
        } else {
            let code = unsafe { GetLastError() };
            if code == ERROR_IO_PENDING {
                Ok(())
            } else {
                Err(code.0)
            }
        }
    }
}

impl Drop for RequestorInner {
    fn drop(&mut self) {
        unsafe {
            if !self.icmp_handle.is_invalid() {
                let _ = IcmpCloseHandle(self.icmp_handle);
            }
        }
    }
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

unsafe extern "system" fn wait_callback(ptr: *mut c_void, timer_fired: bool) {
    debug_assert!(!timer_fired, "Timer should not be fired here");

    // Take ownership of the context pointer. It drops at the end of this function.
    let context = Box::from_raw(ptr as *mut RequestContext);

    let reply = match context.target_addr {
        IpAddr::V4(_) => {
            let ret = unsafe {
                IcmpParseReplies(
                    context.buffer.as_ptr() as *mut _,
                    context.buffer.len() as u32,
                )
            };

            if ret == 0 {
                // IcmpParseReplies failed
                let error = unsafe { GetLastError() };
                if error.0 == IP_REQ_TIMED_OUT {
                    // ICMP timeout, not a system error
                    IcmpEchoReply::new(
                        context.target_addr,
                        IcmpEchoStatus::TimedOut,
                        context.timeout,
                    )
                } else {
                    // Unknown error
                    IcmpEchoReply::new(context.target_addr, IcmpEchoStatus::Unknown, Duration::ZERO)
                }
            } else {
                debug_assert_eq!(ret, 1);

                let resp = (context.buffer.as_ptr() as *const ICMP_ECHO_REPLY)
                    .as_ref()
                    .unwrap();
                let addr = IpAddr::V4(u32::from_be(resp.Address).into());

                IcmpEchoReply::new(
                    addr,
                    ip_error_to_icmp_status(resp.Status),
                    Duration::from_millis(resp.RoundTripTime.into()),
                )
            }
        }
        IpAddr::V6(_) => {
            let ret = unsafe {
                Icmp6ParseReplies(
                    context.buffer.as_ptr() as *mut _,
                    context.buffer.len() as u32,
                )
            };

            if ret == 0 {
                // Icmp6ParseReplies failed
                let error = unsafe { GetLastError() };
                if error.0 == IP_REQ_TIMED_OUT {
                    // ICMP timeout, not a system error
                    IcmpEchoReply::new(
                        context.target_addr,
                        IcmpEchoStatus::TimedOut,
                        context.timeout,
                    )
                } else {
                    // Unknown error
                    IcmpEchoReply::new(context.target_addr, IcmpEchoStatus::Unknown, Duration::ZERO)
                }
            } else {
                debug_assert_eq!(ret, 1);

                let resp = (context.buffer.as_ptr() as *const ICMPV6_ECHO_REPLY)
                    .as_ref()
                    .unwrap();
                let mut addr_raw = IN6_ADDR::default();
                addr_raw.u.Word = resp.Address.sin6_addr;
                let addr = IpAddr::V6(addr_raw.into());

                IcmpEchoReply::new(
                    addr,
                    ip_error_to_icmp_status(resp.Status),
                    Duration::from_millis(resp.RoundTripTime.into()),
                )
            }
        }
    };

    let _ = context.sender.send(reply);

    // Clean up
    if !context.wait_object.is_invalid() {
        // We can't blocking unregister the wait handle here, otherwise it causes deadlock.
        let _ = UnregisterWaitEx(context.wait_object, None);
    }
    if !context.event.is_invalid() {
        let _ = CloseHandle(context.event);
    }
    // Context drops automatically here
}
