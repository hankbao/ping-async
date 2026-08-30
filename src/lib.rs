//! Unprivileged Async Ping
//!
//! This crate provides asynchronous ICMP echo request (ping) functionality that works
//! without requiring elevated privileges on Windows, macOS, and Linux platforms.
//!
//! ## Platform Support
//!
//! - **Windows**: Uses Windows APIs (`IcmpSendEcho2Ex` and `Icmp6SendEcho2`) that provide
//!   unprivileged ICMP functionality without requiring administrator rights.
//! - **macOS/Linux**: Uses ICMP sockets with Tokio for async operations. On Linux, requires
//!   the `net.ipv4.ping_group_range` sysctl parameter to allow unprivileged ICMP sockets.
//!
//! On every platform [`IcmpEchoRequestor::send`] must be polled inside a Tokio runtime with
//! the time driver enabled (the default for `#[tokio::main]`): the configured timeout is
//! enforced by Tokio, independently of the operating system's own timers.
//!
//! ## Basic Usage
//!
//! ```rust,no_run
//! use ping_async::IcmpEchoRequestor;
//! use std::net::IpAddr;
//!
//! #[tokio::main]
//! async fn main() -> std::io::Result<()> {
//!     let target = "8.8.8.8".parse::<IpAddr>().unwrap();
//!     let pinger = IcmpEchoRequestor::new(target, None, None, None)?;
//!
//!     let reply = pinger.send().await?;
//!     println!("Reply from {}: {:?} in {:?}",
//!         reply.destination(),
//!         reply.status(),
//!         reply.round_trip_time()
//!     );
//!
//!     Ok(())
//! }
//! ```

#[cfg(not(target_os = "windows"))]
mod icmp;

mod platform;
pub use platform::IcmpEchoRequestor;

use std::net::IpAddr;
use std::time::Duration;

/// Default Time-To-Live (TTL) value for ICMP packets.
/// This matches the default TTL used by most ping implementations.
pub const PING_DEFAULT_TTL: u8 = 128;

/// Default timeout duration for ICMP echo requests.
/// Requests that don't receive a reply within this time will be marked as timed out.
///
/// Two seconds, as in the 0.1.x releases. Releases 1.0.0 through 1.0.2 shipped with one
/// second by mistake; callers that relied on that value should pass an explicit `timeout`
/// to [`IcmpEchoRequestor::new`].
pub const PING_DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

/// Default length of the data payload in ICMP echo request packets.
/// This matches the default payload size used by most ping implementations.
pub const PING_DEFAULT_REQUEST_DATA_LENGTH: usize = 32;

/// Status of an ICMP echo request/reply exchange.
///
/// This enum represents the different outcomes that can occur when sending
/// an ICMP echo request and waiting for a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpEchoStatus {
    /// The echo request was successful and a reply was received.
    Success,
    /// The echo request timed out - no reply was received within the timeout period.
    TimedOut,
    /// The destination was unreachable (network, host, port, or protocol unreachable).
    Unreachable,
    /// An unknown error occurred during the ping operation.
    Unknown,
}

impl IcmpEchoStatus {
    /// Converts the status to a `Result`, returning `Ok(())` for success or an error message for failures.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ping_async::IcmpEchoStatus;
    ///
    /// let status = IcmpEchoStatus::Success;
    /// assert!(status.ok().is_ok());
    ///
    /// let status = IcmpEchoStatus::TimedOut;
    /// assert!(status.ok().is_err());
    /// ```
    pub fn ok(self) -> Result<(), String> {
        match self {
            Self::Success => Ok(()),
            Self::TimedOut => Err("Timed out".to_string()),
            Self::Unreachable => Err("Destination unreachable".to_string()),
            Self::Unknown => Err("Unknown error".to_string()),
        }
    }
}

/// Reply received from an ICMP echo request.
///
/// Contains the destination IP address, status of the ping operation,
/// and the measured round-trip time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpEchoReply {
    destination: IpAddr,
    status: IcmpEchoStatus,
    round_trip_time: Duration,
}

impl IcmpEchoReply {
    /// Creates a new ICMP echo reply.
    ///
    /// # Arguments
    ///
    /// * `destination` - The IP address that was pinged
    /// * `status` - The status of the ping operation
    /// * `round_trip_time` - The measured round-trip time
    pub fn new(destination: IpAddr, status: IcmpEchoStatus, round_trip_time: Duration) -> Self {
        Self {
            destination,
            status,
            round_trip_time,
        }
    }

    /// Returns the destination IP address that was pinged.
    pub fn destination(&self) -> IpAddr {
        self.destination
    }

    /// Returns the status of the ping operation.
    pub fn status(&self) -> IcmpEchoStatus {
        self.status
    }

    /// Returns the measured round-trip time.
    ///
    /// For successful pings, this represents the time between sending the echo request
    /// and receiving the echo reply. For failed pings, this may be zero or represent
    /// the time until the failure was detected.
    pub fn round_trip_time(&self) -> Duration {
        self.round_trip_time
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The public defaults are part of the crate's contract: a change here is a
    /// behavioural change for every caller passing `None`, so it must be deliberate (the
    /// timeout silently became one second in 1.0.0–1.0.2 and had to be restored).
    #[test]
    fn public_defaults_are_stable() {
        assert_eq!(PING_DEFAULT_TIMEOUT, Duration::from_secs(2));
        assert_eq!(PING_DEFAULT_TTL, 128);
        assert_eq!(PING_DEFAULT_REQUEST_DATA_LENGTH, 32);
    }

    /// A loopback echo must come back as `Success`: a timeout or any other status here
    /// means replies are not being delivered, which `send()` reports as `Ok`, not `Err`.
    fn assert_loopback_success(reply: &IcmpEchoReply, expected: &str) {
        assert_eq!(reply.destination(), expected.parse::<IpAddr>().unwrap());
        assert_eq!(
            reply.status(),
            IcmpEchoStatus::Success,
            "loopback echo to {expected} did not succeed: {reply:?}"
        );
    }

    #[tokio::test]
    async fn ping_localhost_v4() -> std::io::Result<()> {
        let pinger = IcmpEchoRequestor::new("127.0.0.1".parse().unwrap(), None, None, None)?;
        let reply = pinger.send().await?;

        assert_loopback_success(&reply, "127.0.0.1");
        println!("IPv4 ping result: {reply:?}");

        Ok(())
    }

    #[tokio::test]
    async fn ping_localhost_v6() -> std::io::Result<()> {
        let pinger = IcmpEchoRequestor::new("::1".parse().unwrap(), None, None, None)?;
        let reply = pinger.send().await?;

        assert_loopback_success(&reply, "::1");
        println!("IPv6 ping result: {reply:?}");

        Ok(())
    }

    #[tokio::test]
    async fn test_thread_safety() -> std::io::Result<()> {
        let pinger = IcmpEchoRequestor::new("127.0.0.1".parse().unwrap(), None, None, None)?;

        // Test that we can clone and use across threads
        let pinger_clone = pinger.clone();
        let handle = tokio::spawn(async move { pinger_clone.send().await });

        let reply = handle.await.unwrap()?;
        assert_loopback_success(&reply, "127.0.0.1");

        Ok(())
    }

    #[test]
    fn test_send_sync_traits() {
        // Compile-time verification that IcmpEchoRequestor implements Send + Sync
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<IcmpEchoRequestor>();
        assert_sync::<IcmpEchoRequestor>();
        assert_send::<IcmpEchoReply>();
        assert_sync::<IcmpEchoReply>();
        assert_send::<IcmpEchoStatus>();
        assert_sync::<IcmpEchoStatus>();
    }

    #[tokio::test]
    async fn test_concurrent_pings() -> std::io::Result<()> {
        let pinger = IcmpEchoRequestor::new("127.0.0.1".parse().unwrap(), None, None, None)?;

        // Spawn multiple concurrent ping tasks
        let mut handles = Vec::new();
        for _ in 0..5 {
            let pinger_clone = pinger.clone();
            let handle = tokio::spawn(async move { pinger_clone.send().await });
            handles.push(handle);
        }

        // Wait for all pings to complete
        for handle in handles {
            let reply = handle.await.unwrap()?;
            assert_loopback_success(&reply, "127.0.0.1");
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_requestors_independent_routers() -> std::io::Result<()> {
        // Create multiple requestors - each should have its own router when used
        let pinger1 = IcmpEchoRequestor::new("127.0.0.1".parse().unwrap(), None, None, None)?;
        let pinger2 = IcmpEchoRequestor::new("::1".parse().unwrap(), None, None, None)?;

        // Both should work independently
        let reply1 = pinger1.send().await?;
        let reply2 = pinger2.send().await?;

        assert_loopback_success(&reply1, "127.0.0.1");
        assert_loopback_success(&reply2, "::1");

        Ok(())
    }
}
