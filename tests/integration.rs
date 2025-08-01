//! Integration tests for ICMP ping functionality

use std::io;
use std::net::IpAddr;
use std::time::Duration;

use ping_async::{IcmpEchoRequestor, IcmpEchoStatus};

/// Test that multiple IcmpEchoRequestor instances can target the same IP
#[tokio::test]
async fn test_multiple_requestors_same_target() {
    let req1 = IcmpEchoRequestor::new("127.0.0.1".parse().unwrap(), None, None, None).unwrap();
    let req2 = IcmpEchoRequestor::new("127.0.0.1".parse().unwrap(), None, None, None).unwrap();

    // Both should work concurrently without interfering
    let (result1, result2) = tokio::join!(req1.send(), req2.send());

    assert!(result1.is_ok(), "First requestor should succeed");
    assert!(result2.is_ok(), "Second requestor should succeed");

    let reply1 = result1.unwrap();
    let reply2 = result2.unwrap();

    assert_eq!(reply1.destination(), "127.0.0.1".parse::<IpAddr>().unwrap());
    assert_eq!(reply2.destination(), "127.0.0.1".parse::<IpAddr>().unwrap());
}

#[tokio::test]
async fn test_high_concurrency() {
    let req = IcmpEchoRequestor::new("127.0.0.1".parse().unwrap(), None, None, None).unwrap();

    // Create 50 concurrent requests to stress the system
    let futures: Vec<_> = (0..50).map(|_| req.send()).collect();
    let results = futures::future::join_all(futures).await;

    // All should complete without panics or handle leaks
    assert_eq!(results.len(), 50);

    // Most should succeed (loopback should be reliable)
    let success_count = results.iter().filter(|r| r.is_ok()).count();
    assert!(
        success_count > 40,
        "Most loopback pings should succeed, got {}/50",
        success_count
    );
}

/// Test rapid-fire requests
#[tokio::test]
async fn test_rapid_firing() {
    let req = IcmpEchoRequestor::new("127.0.0.1".parse().unwrap(), None, None, None).unwrap();

    // Rapid fire requests to stress callback unregistration
    for i in 0..20 {
        let result = req.send().await;
        assert!(result.is_ok(), "Request {} should succeed", i);
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

    // Should timeout within reasonable time
    assert_eq!(result.status(), IcmpEchoStatus::TimedOut);
    assert!(
        elapsed >= Duration::from_millis(500),
        "Should wait at least 500ms"
    );
    assert!(
        elapsed < Duration::from_millis(1500),
        "Should timeout within 1s"
    );
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
            println!("ICMP creation failed (may need elevation): {}", e);
            // Don't fail the test - this is informational
        }
    }
}
