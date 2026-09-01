# ping-async

[![Rust](https://github.com/hankbao/ping-async/actions/workflows/rust.yml/badge.svg)](https://github.com/hankbao/ping-async/actions/workflows/rust.yml)

This crate can send unprivileged ICMP echo requests and receive echo replies asynchronously on Windows, macOS and Linux. It is built on `std::future` and Tokio 1.x.

On Windows, it uses the `IcmpSendEcho2Ex` and `Icmp6SendEcho2` Win32 APIs. On macOS and Linux, it uses ICMP datagram sockets driven by `tokio`; replies are matched to requests by a background task, so timing accuracy can be affected by the system's load. On Linux, unprivileged use requires the `net.ipv4.ping_group_range` sysctl to include the caller's group, for example:

```bash
sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
```

## Usage

`send()` must be polled inside a Tokio runtime with the time driver enabled (the default for `#[tokio::main]`): the configured timeout is enforced by `tokio::time`, so a request resolves within the timeout even when the operating system keeps it pending longer. Every `send()` resolves exactly once to an `IcmpEchoReply` whose status is `Success`, `TimedOut`, `Unreachable` or `Unknown`; a requestor is `Clone + Send + Sync`, so any number of pings can be in flight at the same time.

```rust
use ping_async::IcmpEchoRequestor;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let pinger = IcmpEchoRequestor::new("1.1.1.1".parse().unwrap(), None, None, None)?;

    let reply = pinger.send().await?;
    println!(
        "Reply from {}: status = {:?}, time = {:?}",
        reply.destination(),
        reply.status(),
        reply.round_trip_time()
    );

    Ok(())
}
```

The three optional arguments of `new()` are the source address, the TTL (default 128) and the per-request timeout (default 2 seconds).

## Example

```bash
$ cargo run --example ping 1.1.1.1
Reply from 1.1.1.1: status = Success, time = 8.133ms
Reply from 1.1.1.1: status = Success, time = 8.92ms
Reply from 1.1.1.1: status = Success, time = 10.653ms
Reply from 1.1.1.1: status = Success, time = 8.456ms

$ cargo run --example ping 2606:4700:4700::1111
Reply from 2606:4700:4700::1111: status = Success, time = 8.454ms
Reply from 2606:4700:4700::1111: status = Success, time = 9.307ms
Reply from 2606:4700:4700::1111: status = Success, time = 9.056ms
Reply from 2606:4700:4700::1111: status = Success, time = 9.408ms

$ cargo run --example concurrent_ping 1.1.1.1
Ping 1: reply from 1.1.1.1, status = Success, time = 14ms
Ping 2: reply from 1.1.1.1, status = Success, time = 19ms
Ping 4: reply from 1.1.1.1, status = Success, time = 19ms
Ping 3: reply from 1.1.1.1, status = Success, time = 19ms
...
```

## Development

CI runs `cargo fmt --check`, `cargo clippy -D warnings`, a build and the test suite on Ubuntu, macOS and Windows on stable Rust, plus a `cargo audit` pass.

The tests send real ICMP echo requests to the loopback address, so they need the same permissions as the library (see above for Linux). See [`CLAUDE.md`](CLAUDE.md) for the platform-specific behaviour notes and the full set of verification commands.
