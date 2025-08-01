# ping-async

[![Rust](https://github.com/hankbao/ping-async/actions/workflows/rust.yml/badge.svg)](https://github.com/hankbao/ping-async/actions/workflows/rust.yml)

This crate can send unprivileged ICMP echo requests and receive echo replies asynchronously on both Windows and macOS. On Linux, it requires the `net.ipv4.ping_group_range` `sysctl` parameters to allow unprivileged users to create the ICMP sockets.

On Windows, it uses the `IcmpSendEcho2Ex` and `Icmp6SendEcho2` win32 API. On macOS and Linux, it uses the ICMP sockets with the help of `tokio`. Due to the latter's asynchronous nature, the time accuracy could be affected by the system's load.

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
```
