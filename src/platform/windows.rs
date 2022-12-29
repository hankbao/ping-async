// platform/windows.rs
#![cfg(target_os = "windows")]

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV6};
use std::ptr::NonNull;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::channel::mpsc::UnboundedSender;
use static_assertions::const_assert;

use windows::Win32::Foundation::{
    CloseHandle, BOOLEAN, ERROR_IO_PENDING, HANDLE, INVALID_HANDLE_VALUE,
};
use windows::Win32::NetworkManagement::IpHelper::{
    Icmp6CreateFile, Icmp6ParseReplies, Icmp6SendEcho2, IcmpCloseHandle, IcmpCreateFile,
    IcmpHandle, IcmpParseReplies, IcmpSendEcho2Ex, ICMPV6_ECHO_REPLY_LH as ICMPV6_ECHO_REPLY,
    IP_DEST_HOST_UNREACHABLE, IP_DEST_NET_UNREACHABLE, IP_DEST_PORT_UNREACHABLE,
    IP_DEST_PROT_UNREACHABLE, IP_DEST_UNREACHABLE, IP_REQ_TIMED_OUT, IP_SUCCESS, IP_TIME_EXCEEDED,
    IP_TTL_EXPIRED_REASSEM, IP_TTL_EXPIRED_TRANSIT,
};
use windows::Win32::Networking::WinSock::{IN6_ADDR, SOCKADDR_IN6};
use windows::Win32::System::Threading::{
    CreateEventW, RegisterWaitForSingleObject, UnregisterWaitEx, WT_EXECUTEINWAITTHREAD,
};
use windows::Win32::System::WindowsProgramming::{INFINITE, IO_STATUS_BLOCK};

#[cfg(target_pointer_width = "32")]
use windows::Win32::NetworkManagement::IpHelper::ICMP_ECHO_REPLY;
#[cfg(target_pointer_width = "64")]
use windows::Win32::NetworkManagement::IpHelper::ICMP_ECHO_REPLY32 as ICMP_ECHO_REPLY;
#[cfg(target_pointer_width = "32")]
use windows::Win32::NetworkManagement::IpHelper::IP_OPTION_INFORMATION;
#[cfg(target_pointer_width = "64")]
use windows::Win32::NetworkManagement::IpHelper::IP_OPTION_INFORMATION32 as IP_OPTION_INFORMATION;

use crate::{
    IcmpEchoReply, IcmpEchoStatus, PING_DEFAULT_TIMEOUT, PING_DEFAULT_TTL,
    PING_DEFFAULT_REQUEST_DATA_LENGTH,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplyBufferState {
    Empty,
    Icmp4,
    Icmp6,
}

const REPLY_BUFFER_SIZE: usize = size_of::<ICMP_ECHO_REPLY>()
    + PING_DEFFAULT_REQUEST_DATA_LENGTH
    + 8
    + size_of::<IP_OPTION_INFORMATION>();

// we don't provide request data, so we don't need to allocate space for it
const_assert!(
    size_of::<ICMP_ECHO_REPLY>()
        + PING_DEFFAULT_REQUEST_DATA_LENGTH
        + 8
        + size_of::<IO_STATUS_BLOCK>()
        <= REPLY_BUFFER_SIZE
);
const_assert!(
    size_of::<ICMPV6_ECHO_REPLY>()
        + PING_DEFFAULT_REQUEST_DATA_LENGTH
        + 8
        + size_of::<IO_STATUS_BLOCK>()
        <= REPLY_BUFFER_SIZE
);

struct ReplyContext {
    state: ReplyBufferState,
    buffer: Box<[u8]>,
    sender: UnboundedSender<IcmpEchoReply>,
}

impl ReplyContext {
    fn new(sender: UnboundedSender<IcmpEchoReply>) -> Self {
        ReplyContext {
            state: ReplyBufferState::Empty,
            buffer: vec![0u8; REPLY_BUFFER_SIZE].into_boxed_slice(),
            sender,
        }
    }

    fn buffer_state(&self) -> ReplyBufferState {
        self.state
    }

    fn buffer_ptr(&mut self) -> *mut u8 {
        self.buffer.as_mut_ptr() as *mut u8
    }

    fn buffer_size(&self) -> usize {
        self.buffer.len()
    }
}

pub struct IcmpEchoSender {
    handle: IcmpHandle,
    event: HANDLE,
    wait_object: HANDLE,
    target_addr: IpAddr,
    source_addr: Option<IpAddr>,
    ttl: u8,
    timeout: Duration,
    reply_context: NonNull<Arc<Mutex<ReplyContext>>>,
}

impl IcmpEchoSender {
    pub fn new(
        reply_tx: UnboundedSender<IcmpEchoReply>,
        target_addr: IpAddr,
        source_addr: Option<IpAddr>,
        ttl: Option<u8>,
        timeout: Option<Duration>,
    ) -> io::Result<Self> {
        let handle = match target_addr {
            IpAddr::V4(_) => unsafe { IcmpCreateFile()? },
            IpAddr::V6(_) => unsafe { Icmp6CreateFile()? },
        };
        assert!(!handle.is_invalid());

        let event = match unsafe { CreateEventW(None, false, false, None) } {
            Ok(event) => event,
            Err(e) => {
                unsafe { IcmpCloseHandle(handle) };
                return Err(e.into());
            }
        };

        let reply_context = NonNull::new(Box::into_raw(Box::new(Arc::new(Mutex::new(
            ReplyContext::new(reply_tx),
        )))))
        .expect("Box::into_raw returned null");

        let mut new_handle = HANDLE::default();
        let wait_object = match unsafe {
            RegisterWaitForSingleObject(
                &mut new_handle as *mut _,
                event,
                Some(wait_callback),
                Some(reply_context.as_ptr() as *const _),
                INFINITE,
                WT_EXECUTEINWAITTHREAD,
            )
            .ok()
        } {
            Ok(()) => new_handle,
            Err(e) => {
                unsafe { CloseHandle(event) };
                unsafe { IcmpCloseHandle(handle) };
                return Err(e.into());
            }
        };

        Ok(IcmpEchoSender {
            handle,
            event,
            wait_object,
            target_addr,
            source_addr,
            ttl: ttl.unwrap_or(PING_DEFAULT_TTL),
            timeout: timeout.unwrap_or(PING_DEFAULT_TIMEOUT),
            reply_context,
        })
    }

    pub fn send(&self) -> io::Result<()> {
        let mut ip_option = IP_OPTION_INFORMATION::default();
        ip_option.Ttl = self.ttl;

        let req_data = [0u8; PING_DEFFAULT_REQUEST_DATA_LENGTH];

        let error = match self.target_addr {
            IpAddr::V4(taddr) => {
                let saddr = if let Some(saddr) = self.source_addr {
                    if let IpAddr::V4(s) = saddr {
                        s
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "source address must be an IPv4 address",
                        ));
                    }
                } else {
                    Ipv4Addr::UNSPECIFIED
                };

                unsafe {
                    let mut ctx = self.reply_context.as_ref().lock().unwrap();
                    assert!(ctx.buffer_state() == ReplyBufferState::Empty);
                    ctx.state = ReplyBufferState::Icmp4;

                    IcmpSendEcho2Ex(
                        self.handle,
                        self.event,
                        None,
                        None,
                        u32::from(saddr).to_be(),
                        u32::from(taddr).to_be(),
                        req_data.as_ptr() as *const _,
                        req_data.len() as u16,
                        Some(&ip_option as *const _ as *const _),
                        ctx.buffer_ptr() as *mut _,
                        ctx.buffer_size() as u32,
                        self.timeout.as_millis() as u32,
                    )
                }
            }
            IpAddr::V6(taddr) => {
                let saddr = if let Some(saddr) = self.source_addr {
                    if let IpAddr::V6(s) = saddr {
                        s
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "source address must be an IPv6 address",
                        ));
                    }
                } else {
                    Ipv6Addr::UNSPECIFIED
                };

                unsafe {
                    let mut ctx = self.reply_context.as_ref().lock().unwrap();
                    assert!(ctx.buffer_state() == ReplyBufferState::Empty);
                    ctx.state = ReplyBufferState::Icmp6;

                    let src_saddr: SOCKADDR_IN6 = SocketAddrV6::new(saddr, 0, 0, 0).into();
                    let dst_saddr: SOCKADDR_IN6 = SocketAddrV6::new(taddr, 0, 0, 0).into();

                    Icmp6SendEcho2(
                        self.handle,
                        self.event,
                        None,
                        None,
                        &src_saddr,
                        &dst_saddr,
                        req_data.as_ptr() as *const _,
                        req_data.len() as u16,
                        Some(&ip_option as *const _ as *const _),
                        ctx.buffer_ptr() as *mut _,
                        ctx.buffer_size() as u32,
                        self.timeout.as_millis() as u32,
                    )
                }
            }
        };

        if error == 0 {
            Err(io::Error::last_os_error())
        } else {
            assert!(error == ERROR_IO_PENDING.0);
            Ok(())
        }
    }
}

impl Drop for IcmpEchoSender {
    fn drop(&mut self) {
        unsafe {
            if !self.wait_object.is_invalid() {
                UnregisterWaitEx(self.wait_object, INVALID_HANDLE_VALUE)
                    .expect("failed to UnregisterWaitEx");
            }
            if !self.event.is_invalid() {
                CloseHandle(self.event).expect("failed to CloseHandle");
            }
            if !self.handle.is_invalid() {
                IcmpCloseHandle(self.handle).expect("failed to IcmpCloseHandle");
            }

            drop(Box::from_raw(self.reply_context.as_ptr()));
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
        _ => IcmpEchoStatus::Unknown,
    }
}

unsafe extern "system" fn wait_callback(ptr: *mut c_void, _timer_fired: BOOLEAN) {
    let mut reply_context = (ptr as *mut Arc<Mutex<ReplyContext>>)
        .as_ref()
        .unwrap()
        .lock()
        .unwrap();

    let resp = match reply_context.state {
        ReplyBufferState::Empty => {
            log::warn!("event signalled with invalid empty state");
            return;
        }
        ReplyBufferState::Icmp4 => unsafe {
            let ret = IcmpParseReplies(
                reply_context.buffer_ptr() as *mut _,
                reply_context.buffer_size() as u32,
            );
            if ret == 0 {
                log::warn!("IcmpParseReplies failed: {}", io::Error::last_os_error());
                return;
            } else {
                debug_assert!(ret == 1);

                let resp = *(reply_context.buffer_ptr() as *const ICMP_ECHO_REPLY);
                let addr = IpAddr::V4(u32::from_be(resp.Address).into());

                IcmpEchoReply::new(
                    addr,
                    ip_error_to_icmp_status(resp.Status),
                    Duration::from_millis(resp.RoundTripTime.into()),
                )
            }
        },
        ReplyBufferState::Icmp6 => {
            let ret = unsafe {
                Icmp6ParseReplies(
                    reply_context.buffer_ptr() as *mut _,
                    reply_context.buffer_size() as u32,
                )
            };
            if ret == 0 {
                log::warn!("Icmp6ParseReplies failed: {}", io::Error::last_os_error());
                return;
            } else {
                debug_assert!(ret == 1);

                let resp = *(reply_context.buffer_ptr() as *const ICMPV6_ECHO_REPLY);
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

    if let Err(e) = reply_context.sender.unbounded_send(resp) {
        log::warn!("failed to send reply: {}", e);
    }
}
