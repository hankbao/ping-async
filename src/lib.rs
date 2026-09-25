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
use std::time::{Duration, Instant};

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

/// Minimum exact payload length accepted by [`IcmpEchoRequestor::with_payload_len`].
pub const PING_MIN_REQUEST_DATA_LENGTH: usize = 0;

/// Maximum exact payload length accepted by [`IcmpEchoRequestor::with_payload_len`].
pub const PING_MAX_REQUEST_DATA_LENGTH: usize = 1024;

/// Status of an ICMP echo request/reply exchange.
///
/// This enum represents the different outcomes that can occur when sending
/// an ICMP echo request and waiting for a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpEchoStatus {
    /// The echo request was successful and a reply was received.
    Success,
    /// The local request deadline elapsed before a reply was received.
    TimedOut,
    /// A received ICMP error made the destination or an intermediate router unreachable.
    Unreachable,
    /// An unknown error occurred during the ping operation.
    Unknown,
}

impl IcmpEchoStatus {
    pub fn from_outcome(outcome: IcmpOutcome) -> Self {
        outcome.coarse()
    }

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

/// Fine-grained outcome of an ICMP echo request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpOutcome {
    /// An Echo Reply matched the request.
    EchoReply,
    /// The local request deadline elapsed.
    LocalTimeout,
    /// A received ICMP Time Exceeded matched the request.
    TimeExceeded,
    /// A received Destination Unreachable did not expose a narrower subtype.
    DestinationUnreachable,
    /// IPv6 Destination Unreachable, code 0.
    NoRoute,
    /// IPv4 Destination Unreachable, code 0.
    NetworkUnreachable,
    /// IPv4 Destination Unreachable, code 1.
    HostUnreachable,
    /// Destination Unreachable port subtype.
    PortUnreachable,
    /// Destination Unreachable protocol subtype.
    ProtocolUnreachable,
    /// A recognized error without a narrower public subtype.
    Other,
}

impl IcmpOutcome {
    /// Projects this outcome onto the legacy coarse status.
    pub fn coarse(self) -> IcmpEchoStatus {
        match self {
            Self::EchoReply => IcmpEchoStatus::Success,
            Self::LocalTimeout => IcmpEchoStatus::TimedOut,
            Self::TimeExceeded
            | Self::DestinationUnreachable
            | Self::NoRoute
            | Self::NetworkUnreachable
            | Self::HostUnreachable
            | Self::PortUnreachable
            | Self::ProtocolUnreachable => IcmpEchoStatus::Unreachable,
            Self::Other => IcmpEchoStatus::Unknown,
        }
    }

    /// Reconstructs an outcome from a legacy coarse status.
    pub fn from_status(status: IcmpEchoStatus) -> Self {
        match status {
            IcmpEchoStatus::Success => Self::EchoReply,
            IcmpEchoStatus::TimedOut => Self::LocalTimeout,
            IcmpEchoStatus::Unreachable => Self::DestinationUnreachable,
            IcmpEchoStatus::Unknown => Self::Other,
        }
    }
}

impl From<IcmpEchoStatus> for IcmpOutcome {
    fn from(status: IcmpEchoStatus) -> Self {
        Self::from_status(status)
    }
}

impl From<IcmpOutcome> for IcmpEchoStatus {
    fn from(outcome: IcmpOutcome) -> Self {
        outcome.coarse()
    }
}

/// Reply received from an ICMP echo request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpEchoReply {
    destination: IpAddr,
    status: IcmpEchoStatus,
    outcome: IcmpOutcome,
    responder: Option<IpAddr>,
    sequence: Option<u16>,
    round_trip_time: Duration,
    completed_at: Instant,
}

impl IcmpEchoReply {
    /// Creates a new ICMP echo reply, recording the current instant as its
    /// completion time.
    ///
    /// The reply's [`completed_at`](Self::completed_at) is stamped with
    /// [`Instant::now()`] when this constructor runs. Because `PartialEq`
    /// includes that instant, two replies built by `new` from identical
    /// arguments generally compare unequal (though a coarse clock may return
    /// the same instant twice). Use
    /// [`with_completed_at`](Self::with_completed_at) when a deterministic
    /// completion instant is needed, for example in tests.
    ///
    /// # Arguments
    ///
    /// * `destination` - The IP address that was pinged
    /// * `status` - The status of the ping operation
    /// * `round_trip_time` - The measured round-trip time
    pub fn new(destination: IpAddr, status: IcmpEchoStatus, round_trip_time: Duration) -> Self {
        Self::with_completed_at(destination, status, round_trip_time, Instant::now())
    }

    /// Creates a new ICMP echo reply with an explicit completion instant.
    ///
    /// All four values are stored verbatim. The crate makes no claim about a
    /// caller-supplied `completed_at`; the guarantees documented on
    /// [`completed_at`](Self::completed_at) apply to replies returned by
    /// [`IcmpEchoRequestor::send`].
    ///
    /// # Arguments
    ///
    /// * `destination` - The IP address that was pinged
    /// * `status` - The status of the ping operation
    /// * `round_trip_time` - The measured round-trip time
    /// * `completed_at` - The instant at which the outcome was determined
    pub fn with_completed_at(
        destination: IpAddr,
        status: IcmpEchoStatus,
        round_trip_time: Duration,
        completed_at: Instant,
    ) -> Self {
        Self::with_evidence(
            destination,
            status,
            IcmpOutcome::from_status(status),
            None,
            None,
            round_trip_time,
            completed_at,
        )
    }

    pub fn with_responder_and_outcome(
        destination: IpAddr,
        status: IcmpEchoStatus,
        outcome: IcmpOutcome,
        responder: Option<IpAddr>,
        round_trip_time: Duration,
        completed_at: Instant,
    ) -> Self {
        Self::with_evidence(
            destination,
            status,
            outcome,
            responder,
            None,
            round_trip_time,
            completed_at,
        )
    }

    /// Creates a reply with all observation fields specified.
    pub fn with_evidence(
        destination: IpAddr,
        status: IcmpEchoStatus,
        outcome: IcmpOutcome,
        responder: Option<IpAddr>,
        sequence: Option<u16>,
        round_trip_time: Duration,
        completed_at: Instant,
    ) -> Self {
        Self {
            destination,
            status,
            outcome,
            responder,
            sequence,
            round_trip_time,
            completed_at,
        }
    }

    /// Returns the destination IP address that was pinged.
    pub fn destination(&self) -> IpAddr {
        self.destination
    }

    /// Returns the coarse status of the ping operation.
    pub fn status(&self) -> IcmpEchoStatus {
        self.status
    }

    /// Returns the fine-grained outcome.
    pub fn outcome(&self) -> IcmpOutcome {
        self.outcome
    }

    /// Returns the observed source address, when the platform exposed it.
    pub fn responder(&self) -> Option<IpAddr> {
        self.responder
    }

    /// Returns the ICMP sequence number, when the backend exposed it.
    pub fn sequence(&self) -> Option<u16> {
        self.sequence
    }

    /// Returns the measured round-trip time.
    ///
    /// For successful pings, this represents the time between sending the echo request
    /// and receiving the echo reply. For failed pings, this may be zero or represent
    /// the time until the failure was detected; use
    /// [`completed_at`](Self::completed_at) to place such a reply in time.
    pub fn round_trip_time(&self) -> Duration {
        self.round_trip_time
    }

    /// Returns the instant at which the outcome of the request was determined.
    ///
    /// The value is a monotonic [`std::time::Instant`], stamped with
    /// [`Instant::now()`] at the site that decides the outcome; it is never
    /// derived from the round-trip time or from the configured timeout. For a
    /// reply returned by [`IcmpEchoRequestor::send`]:
    ///
    /// - [`Success`](IcmpEchoStatus::Success): when the echo reply was received and
    ///   matched to the request.
    /// - [`Unreachable`](IcmpEchoStatus::Unreachable) for a received ICMP error.
    /// - [`TimedOut`](IcmpEchoStatus::TimedOut) only for the local request deadline.
    ///   On Windows the driver may report its own timeout before the Tokio deadline; that
    ///   reply is a received driver outcome and is not represented as a local deadline.
    ///
    /// In every case the instant is taken once the reply's status is established and
    /// before the round-trip time is computed or the reply is delivered. It is never
    /// earlier than the `send()` call that produced the reply and never later than the
    /// caller observing the resolved future. Unlike
    /// [`round_trip_time`](Self::round_trip_time), which is zero for ICMP errors, it is
    /// meaningful for every status, so a caller can place a late-observed error on its
    /// own timeline:
    ///
    /// ```rust,no_run
    /// use ping_async::IcmpEchoRequestor;
    /// use std::time::Instant;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> std::io::Result<()> {
    /// let pinger = IcmpEchoRequestor::new("8.8.8.8".parse().unwrap(), None, None, None)?;
    /// let issued = Instant::now();
    /// let reply = pinger.send().await?;
    /// let offset = reply.completed_at().duration_since(issued);
    /// println!("{:?} decided {:?} after the request was issued", reply.status(), offset);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// For a reply built with [`new`](Self::new) this is the instant of construction;
    /// for one built with [`with_completed_at`](Self::with_completed_at) or
    /// [`with_evidence`](Self::with_evidence) or
    /// [`with_responder_and_outcome`](Self::with_responder_and_outcome) it is whatever the
    /// caller supplied.
    pub fn completed_at(&self) -> Instant {
        self.completed_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Asserts that the reply's completion instant lies between `before` (taken before
    /// the `send()` that produced it) and now.
    fn assert_completed_between(reply: &IcmpEchoReply, before: Instant) {
        let now = Instant::now();
        assert!(
            before <= reply.completed_at() && reply.completed_at() <= now,
            "completed_at {:?} must lie within [{before:?}, {now:?}]",
            reply.completed_at()
        );
    }

    #[test]
    fn outcome_projection_is_stable() {
        let cases = [
            (IcmpOutcome::EchoReply, IcmpEchoStatus::Success),
            (IcmpOutcome::LocalTimeout, IcmpEchoStatus::TimedOut),
            (IcmpOutcome::TimeExceeded, IcmpEchoStatus::Unreachable),
            (
                IcmpOutcome::DestinationUnreachable,
                IcmpEchoStatus::Unreachable,
            ),
            (IcmpOutcome::NoRoute, IcmpEchoStatus::Unreachable),
            (IcmpOutcome::NetworkUnreachable, IcmpEchoStatus::Unreachable),
            (IcmpOutcome::HostUnreachable, IcmpEchoStatus::Unreachable),
            (IcmpOutcome::PortUnreachable, IcmpEchoStatus::Unreachable),
            (
                IcmpOutcome::ProtocolUnreachable,
                IcmpEchoStatus::Unreachable,
            ),
            (IcmpOutcome::Other, IcmpEchoStatus::Unknown),
        ];
        for (outcome, status) in cases {
            assert_eq!(outcome.coarse(), status);
        }
        assert_eq!(
            IcmpOutcome::from(IcmpEchoStatus::TimedOut),
            IcmpOutcome::LocalTimeout
        );
    }

    #[test]
    fn evidence_constructor_preserves_all_observation_fields() {
        let target = "127.0.0.1".parse().unwrap();
        let responder = "127.0.0.2".parse().unwrap();
        let reply = IcmpEchoReply::with_responder_and_outcome(
            target,
            IcmpEchoStatus::Unreachable,
            IcmpOutcome::HostUnreachable,
            Some(responder),
            Duration::ZERO,
            Instant::now(),
        );
        assert_eq!(reply.destination(), target);
        assert_eq!(reply.outcome(), IcmpOutcome::HostUnreachable);
        assert_eq!(reply.responder(), Some(responder));
        assert_eq!(
            IcmpEchoStatus::from_outcome(IcmpOutcome::TimeExceeded),
            IcmpEchoStatus::Unreachable
        );
    }

    #[test]
    fn with_completed_at_stores_instant_and_stays_copy() {
        let completed_at = Instant::now();
        let reply = IcmpEchoReply::with_completed_at(
            "127.0.0.1".parse().unwrap(),
            IcmpEchoStatus::Unreachable,
            Duration::ZERO,
            completed_at,
        );
        assert_eq!(reply.completed_at(), completed_at);
        // The reply stays `Copy` and comparable with the added field.
        let copy = reply;
        assert_eq!(copy, reply);
    }

    #[test]
    fn new_stamps_construction_instant() {
        let before = Instant::now();
        let reply = IcmpEchoReply::new(
            "127.0.0.1".parse().unwrap(),
            IcmpEchoStatus::TimedOut,
            Duration::ZERO,
        );
        let after = Instant::now();
        assert!(before <= reply.completed_at() && reply.completed_at() <= after);
    }

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
        let before = Instant::now();
        let reply = pinger.send().await?;

        assert_loopback_success(&reply, "127.0.0.1");
        assert_completed_between(&reply, before);
        println!("IPv4 ping result: {reply:?}");

        Ok(())
    }

    #[tokio::test]
    async fn ping_localhost_v6() -> std::io::Result<()> {
        let pinger = IcmpEchoRequestor::new("::1".parse().unwrap(), None, None, None)?;
        let before = Instant::now();
        let reply = pinger.send().await?;

        assert_loopback_success(&reply, "::1");
        assert_completed_between(&reply, before);
        println!("IPv6 ping result: {reply:?}");

        Ok(())
    }

    #[tokio::test]
    async fn test_thread_safety() -> std::io::Result<()> {
        let pinger = IcmpEchoRequestor::new("127.0.0.1".parse().unwrap(), None, None, None)?;

        // Test that we can clone and use across threads
        let pinger_clone = pinger.clone();
        let before = Instant::now();
        let handle = tokio::spawn(async move { pinger_clone.send().await });

        let reply = handle.await.unwrap()?;
        assert_loopback_success(&reply, "127.0.0.1");
        assert_completed_between(&reply, before);

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
        let before = Instant::now();
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
            assert_completed_between(&reply, before);
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_requestors_independent_routers() -> std::io::Result<()> {
        // Create multiple requestors - each should have its own router when used
        let pinger1 = IcmpEchoRequestor::new("127.0.0.1".parse().unwrap(), None, None, None)?;
        let pinger2 = IcmpEchoRequestor::new("::1".parse().unwrap(), None, None, None)?;

        // Both should work independently
        let before = Instant::now();
        let reply1 = pinger1.send().await?;
        let reply2 = pinger2.send().await?;

        assert_loopback_success(&reply1, "127.0.0.1");
        assert_loopback_success(&reply2, "::1");
        assert_completed_between(&reply1, before);
        assert_completed_between(&reply2, before);

        Ok(())
    }
}
