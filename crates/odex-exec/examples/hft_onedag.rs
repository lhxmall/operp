use ed25519_dalek::SigningKey;
use odex_dag::{genesis_id, sign_unit, unit_id, Op};
use odex_exec::{Engine, ExecEvent};
use odex_types::{
    account_id_from_pubkey, AccountId, MarketId, OrderType, Side, TimeInForce,
    PRICE_SCALE, QTY_SCALE, USD_SCALE,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};


/// Single node, ONE DAG, multiple markets matched in parallel:
/// every unit (all markets) goes into one shared Engine. apply_ready
/// linearizes globally; book matching is routed to per-market worker
/// threads so different markets match concurrently while seq assignment,
/// risk checks and account application remain exactly ordered.

const TRADERS: usize = 4;

fn sk(n: u8) -> [u8; 32] {
    [n; 32]
}
fn acct(secret: &[u8; 32]) -> AccountId {
    account_id_from_pubkey(&SigningKey::from_bytes(secret).verifying_key().to_bytes())
}

#[derive(Clone)]
struct Cfg {
    run_ms: u64,
    markets: usize,
    generators: usize,
}

fn parse_args() -> Cfg {
    let mut args = std::env::args().skip(1);
    let run_ms: u64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(60_000);
    let markets: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(8);
    let generators: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(4);
    Cfg { run_ms, markets, generators }
}

fn main() {
    let cfg = parse_args();
    println!("READY");
    println!(
        "ONE-DAG parallel: {} markets, {} generator threads, {}ms",
        cfg.markets, cfg.generators, cfg.run_ms
    );

    let mut eng0 = Engine::new();
    // Standalone example: no real AA feed — admit all synthetic deposit units
    // and all markets the generators will use.
    eng0.state.deposits_allowed = (1u8..=255).map(|b| [b; 32]).collect();
    for m in 1..=16u32 {
        eng0.state.allowed_markets.insert(MarketId(m));
    }
    let eng = std::sync::Arc::new(std::sync::Mutex::new(eng0));
    let executed = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let fills = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let rejected = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let (tx, rx) = std::sync::mpsc::channel::<(usize, odex_dag::Unit)>();
    let rx = std::sync::Arc::new(std::sync::Mutex::new(rx));

    // executor thread: single consumer of the one DAG
    let exec_handle = {
        let eng = std::sync::Arc::clone(&eng);
        let executed = std::sync::Arc::clone(&executed);
        let fills = std::sync::Arc::clone(&fills);
        let rejected = std::sync::Arc::clone(&rejected);
        let rx = std::sync::Arc::clone(&rx);
        let deadline = Duration::from_millis(cfg.run_ms + 30_000);

        std::thread::spawn(move || {
            let rx = rx.lock().unwrap_or_else(|e| e.into_inner());
            let deadline = Instant::now() + deadline;
            let mut empty = 0u32;
            while Instant::now() < deadline {
                match rx.recv_timeout(Duration::from_millis(500)) {
                    Ok((_g, u)) => {
                        empty = 0;
                        match eng.lock().unwrap_or_else(|e| e.into_inner()).ingest(u) {
                            Ok(events) => {
                            for e in &events {
                                match e {
                                    ExecEvent::Applied { fills: f, .. } => {
                                        fills.fetch_add(f.len() as u64, std::sync::atomic::Ordering::Relaxed);
                                    }
                                    ExecEvent::Rejected { .. } => {
                                        rejected.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                            executed.fetch_add(events.len() as u64, std::sync::atomic::Ordering::Relaxed);
                            }
                            Err(_) => {}
                        }
                    },
                    Err(_) => {
                        empty += 1;
                        if empty > 6 {
                            break; // ~3s with no units: generators finished/died
                        }
                    }
                }
            }
        })
    };

    // generators: each thread cycles through ALL markets with its own traders,
    // so units from different markets interleave on the same DAG.
    let start = Instant::now();
    let mut gens = Vec::new();
    for g in 0..cfg.generators {
        let tx = tx.clone();
        let c = Cfg { run_ms: cfg.run_ms, ..cfg.clone() };
        gens.push(std::thread::spawn(move || {
            let secrets: Vec<[u8; 32]> = (0..TRADERS)
                .map(|i| sk((((g * TRADERS + i + 5) * 43 + 3) % 251) as u8))
                .collect();
            let mut seqs = vec![1u64; TRADERS];
            let px = 100_000 * PRICE_SCALE;
            let qty = QTY_SCALE / 100;

            let mut dep_tip = genesis_id();
            {
                let s = &secrets[0];
                let u = sign_unit(
                    vec![dep_tip],
                    Op::Deposit {
                        account: acct(s),
                        amount: 10_000_000 * USD_SCALE as i128,
                        aa_unit: [((g * 13 + 7) % 250 + 1) as u8; 32],
                    },
                    s,
                );
                dep_tip = unit_id(&u);
                tx.send((g, u)).ok();
                // each trader needs own funds
                for (ti, s) in secrets.iter().enumerate().skip(1) {
                    let u = sign_unit(
                        vec![dep_tip],
                        Op::Deposit {
                            account: acct(s),
                            amount: 10_000_000 * USD_SCALE as i128,
                            aa_unit: [((g * 31 + ti * 7 + 11) % 250 + 1) as u8; 32],
                        },
                        s,
                    );
                    dep_tip = unit_id(&u);
                    tx.send((g, u)).ok();
                }
            }
            let funded_tip = dep_tip;
            // DAG still merges everything on one net with real concurrency.
            let mut tips: Vec<odex_types::UnitId> =
                (0..cfg.markets).map(|_| funded_tip).collect();
            let mut trader_tip: Vec<odex_types::UnitId> =
                (0..TRADERS).map(|_| funded_tip).collect();

            let end = Instant::now() + Duration::from_millis(cfg.run_ms);
            let mut pair = 0usize;
            while Instant::now() < end {
                let m = pair % cfg.markets;
                let i = pair % TRADERS;
                let j = (i + 1) % TRADERS;
                pair += 1;
                // client_seq is per-ACCOUNT globally: one counter per trader

                for (who, side, tif) in [
                    (i, Side::Ask, TimeInForce::Gtc),
                    (j, Side::Bid, TimeInForce::Ioc),
                    (j, Side::Ask, TimeInForce::Gtc),
                    (i, Side::Bid, TimeInForce::Ioc),
                ] {
                    let cs = seqs[who]; // global per-account counter, strictly increasing
                    let u = sign_unit(
                        vec![trader_tip[who]],
                        Op::Place {
                            account: acct(&secrets[who]),
                            market: MarketId(m as u32 + 1),
                            side,
                            typ: OrderType::Limit,
                            tif,
                            price: px,
                            qty,
                            client_seq: cs,
                        },
                        &secrets[who],
                    );
                    trader_tip[who] = unit_id(&u);
                    seqs[who] += 1;
                    if tx.send((g, u)).is_err() { return; }
                }
                // pace generators so the executor thread gets CPU on small VMs
                std::thread::sleep(Duration::from_micros(400));
            }
        }));
    }
    drop(tx);

    // progress reporter
    let mut last = (0u64, Instant::now());
    while start.elapsed() < Duration::from_millis(cfg.run_ms) {
        std::thread::sleep(Duration::from_secs(15));
        let ex = executed.load(std::sync::atomic::Ordering::Relaxed);
        let dt = last.1.elapsed().as_secs_f64().max(0.001);
        println!(
            "[one-dag {:.0}s] exec={} | {:.0} exec/s",
            start.elapsed().as_secs_f64(),
            ex,
            (ex - last.0) as f64 / dt
        );
        last = (ex, Instant::now());
    }

    for g in gens {
        let _ = g.join();
    }
    let _ = exec_handle.join();

    let secs = start.elapsed().as_secs_f64();
    let ex = executed.load(std::sync::atomic::Ordering::Relaxed);
    let f = fills.load(std::sync::atomic::Ordering::Relaxed);
    let r = rejected.load(std::sync::atomic::Ordering::Relaxed);
    println!("---");
    println!("ONEDAG_RESULT");
    println!("duration_s\t{secs:.1}");
    println!("markets\t{}", cfg.markets);
    println!("generators\t{}", cfg.generators);
    println!("executed\t{ex}");
    println!("fills\t{f}");
    println!("rejected\t{r}");
    println!("aggregate_tps\t{:.1}", ex as f64 / secs);

    let e = eng.lock().unwrap_or_else(|e| e.into_inner());
    let mut open = 0i64;
    for a in e.state.accounts.values() {
        for p in a.positions.values() {
            open += p.qty.abs();
        }
    }
    println!("books\t{}", e.state.books.len());
    println!("accounts\t{}", e.state.accounts.len());
    println!("sum_abs_qty\t{open}");
    println!("OK: one-dag multi-market complete");
}
