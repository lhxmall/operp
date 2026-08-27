use std::sync::mpsc::channel;
use std::time::{Duration, Instant};

fn main() {
    // isolate: pure channel throughput, 4 senders -> 1 receiver
    let (tx, rx) = channel::<u64>();
    let mut handles = Vec::new();
    for g in 0..4usize {
        let tx = tx.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..2_000_000usize {
                if tx.send((g as u64) * 1_000_000 + i as u64).is_err() {
                    return;
                }
            }
        }));
    }
    drop(tx);
    let t0 = Instant::now();
    let mut n = 0usize;
    while n < 8_000_000 {
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(_) => n += 1,
            Err(_) => break,
        }
    }
    for h in handles {
        let _ = h.join();
    }
    let dt = t0.elapsed().as_secs_f64();
    println!(
        "channel: {} msgs in {:.2}s => {:.0} msg/s",
        n,
        dt,
        n as f64 / dt
    );
}
