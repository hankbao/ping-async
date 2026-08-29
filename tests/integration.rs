//! Integration tests for ICMP ping functionality

use std::io;
use std::net::IpAddr;
use std::time::Duration;

use ping_async::{IcmpEchoReply, IcmpEchoRequestor, IcmpEchoStatus};

/// A loopback echo must come back as `Success`. `send()` reports a timeout or any other
/// remote outcome as `Ok(reply)`, so checking `is_ok()` alone would not notice a backend
/// that never delivers a reply.
fn assert_loopback_success(reply: &IcmpEchoReply, what: &str) {
    assert_eq!(reply.destination(), "127.0.0.1".parse::<IpAddr>().unwrap());
    assert_eq!(
        reply.status(),
        IcmpEchoStatus::Success,
        "{what}: loopback echo did not succeed: {reply:?}"
    );
}

/// Test that multiple IcmpEchoRequestor instances can target the same IP
#[tokio::test]
async fn test_multiple_requestors_same_target() {
    let req1 = IcmpEchoRequestor::new("127.0.0.1".parse().unwrap(), None, None, None).unwrap();
    let req2 = IcmpEchoRequestor::new("127.0.0.1".parse().unwrap(), None, None, None).unwrap();

    // Both should work concurrently without interfering
    let (result1, result2) = tokio::join!(req1.send(), req2.send());

    let reply1 = result1.expect("first requestor");
    let reply2 = result2.expect("second requestor");

    assert_loopback_success(&reply1, "first requestor");
    assert_loopback_success(&reply2, "second requestor");
}

#[tokio::test]
async fn test_high_concurrency() {
    let req = IcmpEchoRequestor::new("127.0.0.1".parse().unwrap(), None, None, None).unwrap();

    // Create 50 concurrent requests to stress the system
    let futures: Vec<_> = (0..50).map(|_| req.send()).collect();
    let results = futures::future::join_all(futures).await;

    // All should complete without panics, handle leaks or local errors
    assert_eq!(results.len(), 50);
    let replies: Vec<IcmpEchoReply> = results
        .into_iter()
        .enumerate()
        .map(|(i, r)| r.unwrap_or_else(|e| panic!("request {i} failed locally: {e}")))
        .collect();
    for reply in &replies {
        assert_eq!(reply.destination(), "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    // Nearly all must be answered. The small tolerance is only a guard against unrelated
    // ICMP traffic on the host: on macOS every ICMP datagram socket receives every echo
    // reply on the machine, so a burst from another process can still overflow a socket's
    // receive buffer and drop some of this test's replies.
    let success_count = replies
        .iter()
        .filter(|reply| reply.status() == IcmpEchoStatus::Success)
        .count();
    assert!(
        success_count > 40,
        "Most loopback pings should succeed, got {success_count}/50: {replies:?}"
    );
}

/// Test rapid-fire requests
#[tokio::test]
async fn test_rapid_firing() {
    let req = IcmpEchoRequestor::new("127.0.0.1".parse().unwrap(), None, None, None).unwrap();

    // Rapid fire requests to stress callback unregistration
    for i in 0..20 {
        let reply = req.send().await.expect("send must not fail locally");
        assert_loopback_success(&reply, &format!("request {i}"));
    }
}

/// Test error conditions and status mapping
#[tokio::test]
async fn test_error_mapping() {
    // Test invalid source/target IP version combination
    let invalid_req = IcmpEchoRequestor::new(
        "8.8.8.8".parse().unwrap(),   // IPv4 target
        Some("::1".parse().unwrap()), // IPv6 source
        None,
        None,
    );

    match invalid_req {
        Err(error) => {
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains("does not match"));
        }
        Ok(_) => panic!("IPv4 target with IPv6 source should fail"),
    }
}

/// Test ICMP timeout behavior
#[tokio::test]
async fn test_timeout_behavior() {
    // Use a non-routable address that should timeout
    let req = IcmpEchoRequestor::new(
        "192.0.2.1".parse().unwrap(), // RFC 5737 test network
        None,
        None,
        Some(Duration::from_millis(1000)), // Short timeout
    )
    .unwrap();

    let start = std::time::Instant::now();
    let result = req.send().await.unwrap();
    let elapsed = start.elapsed();

    match result.status() {
        // No reply at all: the local timeout must fire, and within reasonable time.
        IcmpEchoStatus::TimedOut => {
            assert!(
                elapsed >= Duration::from_millis(500),
                "Should wait at least 500ms"
            );
            assert!(
                elapsed < Duration::from_millis(1500),
                "Should timeout within 1s"
            );
        }
        // A gateway that rejects the documentation prefix answers with an ICMP error,
        // which is delivered as Unreachable — before the local timeout, on every platform.
        IcmpEchoStatus::Unreachable => {
            assert!(
                elapsed < Duration::from_millis(1500),
                "ICMP error must arrive before the local timeout"
            );
        }
        other => panic!("unexpected status {other:?} for a black-hole address"),
    }
}

/// Test behavior when creating requestor (checks for permission issues)
#[tokio::test]
async fn test_icmp_creation() {
    // Test IPv4 ICMP creation
    let ipv4_req = IcmpEchoRequestor::new("8.8.8.8".parse().unwrap(), None, None, None);

    // Test IPv6 ICMP creation
    let ipv6_req =
        IcmpEchoRequestor::new("2001:4860:4860::8888".parse().unwrap(), None, None, None);

    match (ipv4_req, ipv6_req) {
        (Ok(_), Ok(_)) => {
            // Both work - has proper permissions
            println!("Both IPv4 and IPv6 ICMP creation successful");
        }
        (Err(e), _) | (_, Err(e)) => {
            // Might not have permissions
            println!("ICMP creation failed (may need elevation): {e}");
            // Don't fail the test - this is informational
        }
    }
}
