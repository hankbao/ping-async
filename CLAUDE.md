# ping-async — notes for contributors and coding agents

## Lessons that are not obvious from the code

1. **Windows icmpapi behaviour must be measured, not read.** MS Learn says the `Timeout` of
   an asynchronous `Icmp6SendEcho2` is ignored; on Windows 11 22631 the driver completes the
   request with `IP_REQ_TIMED_OUT` at roughly its own timeout anyway (measured ~1.5–1.75 s for
   a 2 s timeout). The IPv4 driver rounds timeouts to ~500 ms ticks and may complete a request
   slightly *before* the configured timeout. `IcmpCloseHandle` blocks for the remaining driver
   timeout of every in-flight request, which is why the handle is owned by an `Arc` shared
   with each request context and closed only by the last completion. The configured timeout
   is therefore enforced with `tokio::time::timeout` on top of the driver, and the
   `#[ignore]` test `ipv6_blackhole_driver_completes_and_cleans` (env
   `PING_ASYNC_V6_BLACKHOLE_TARGET`, e.g. a link-local no-host address such as
   `fe80::dead:beef`) is the measurement to re-run when touching `src/platform/windows.rs`.
   Synchronous completion (a non-zero reply count from the send API) is common on loopback
   and must be folded into the normal completion path.
2. **macOS "random timeouts" under load are receive-buffer overflow, not throttling.** Every
   ICMP `SOCK_DGRAM` socket on macOS receives every echo reply on the host; the default 8 KiB
   `SO_RCVBUF` overflows under bursts and the socket's own replies are dropped. The socket
   asks for a 1 MiB buffer; keep loopback test tolerances only as a guard against unrelated
   ping traffic.
3. **Linux ping sockets only deliver ICMP errors through the error queue.** Without
   `IP_RECVERR`/`IPV6_RECVERR` the kernel drops Destination Unreachable / Time Exceeded for an
   unconnected ping socket; with it the message goes to `MSG_ERRQUEUE` and `sk_err` is set.
   `sk_err` is one-shot and can be consumed by a concurrent `sendmsg`
   (`sock_alloc_send_pskb`), so the router drains the error queue on *every* non-datagram
   wake and `send()` drains and retries once after a failed `send_to`. Tokio reports
   `EPOLLERR` as `Ready::ERROR`, not read readiness, so the router waits on
   `READABLE | ERROR`; and `try_io` only understands a single interest, so the `ERROR` bit
   is cleared separately on `WouldBlock` (otherwise the router spins). When testing with an
   unresolvable on-link address, keep the rate low: the kernel's global ICMP rate limiter
   (`net.ipv4.icmp_msgs_burst`, default 50) drops Host Unreachables beyond a burst of ~50 per
   ARP cycle before they reach any socket; `ttl=1` to a remote host gives one Time Exceeded
   per packet at any rate.

## Verification commands used for this crate

- Windows (native): `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features
  -- -D warnings`, `cargo build --verbose`, `cargo test --verbose`, plus
  `PING_ASYNC_V6_BLACKHOLE_TARGET=fe80::dead:beef cargo test -- --ignored ipv6_blackhole`.
- Linux (WSL2 works; put the target dir on the Linux filesystem):
  `net.ipv4.ping_group_range` must allow the test user (`sysctl -w
  net.ipv4.ping_group_range="0 65535"` as root; persist it via `[boot] command` in
  `/etc/wsl.conf`), then the same four commands and
  `PING_ASYNC_UNREACHABLE_TARGET=<unused on-link IPv4> PING_ASYNC_TTL1_TARGET=<remote host>
  cargo test -- --ignored`.
- macOS from another host: `cargo check --target aarch64-apple-darwin --all-targets
  --all-features` and `cargo clippy --target aarch64-apple-darwin --all-targets --all-features
  -- -D warnings` type-check the Unix code; runtime coverage is the `macos-latest` CI job.
