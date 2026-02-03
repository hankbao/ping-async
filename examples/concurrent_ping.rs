// examples/concurrent_ping.rs

use std::io;
use std::net::IpAddr;

use ping_async::IcmpEchoRequestor;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: concurrent_ping <destination>");
        std::process::exit(1);
    }

    let destination: IpAddr = args[1].parse().unwrap();
    if let Err(e) = concurrent_ping(destination, 10).await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn concurrent_ping(dest: IpAddr, count: usize) -> io::Result<()> {
    let pinger = IcmpEchoRequestor::new(dest, None, None, None)?;

    let mut handles = Vec::with_capacity(count);
    for i in 0..count {
        let p = pinger.clone();
        handles.push(tokio::spawn(async move {
            match p.send().await {
                Ok(reply) => println!(
                    "Ping {i}: reply from {}, status = {:?}, time = {:?}",
                    reply.destination(),
                    reply.status(),
                    reply.round_trip_time()
                ),
                Err(e) => eprintln!("Ping {i}: error: {e}"),
            }
        }));
    }

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}
