// examples/ping.rs

use std::io;
use std::net::IpAddr;
use std::time::Duration;

use ping_async::IcmpEchoRequestor;
use tokio::time;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: ping <destination>");
        std::process::exit(1);
    }

    let destination = args[1].parse().unwrap();
    let _ = ping(destination, 4).await;
}

async fn ping(dest: IpAddr, times: usize) -> io::Result<()> {
    let pinger = match IcmpEchoRequestor::new(dest, None, None, None) {
        Ok(req) => req,
        Err(e) => {
            eprintln!("Error creating pinger: {}", e);
            return Err(e);
        }
    };

    let mut interval = time::interval(Duration::from_secs(1));

    for _ in 0..times {
        interval.tick().await;

        match pinger.send().await {
            Ok(reply) => println!(
                "Reply from {}: status = {:?}, time = {:?}",
                reply.destination(),
                reply.status(),
                reply.round_trip_time()
            ),
            Err(e) => {
                eprintln!("Error sending ping: {}", e);
                return Err(e);
            }
        }
    }

    Ok(())
}
