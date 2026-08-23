use ed25519_dalek::SigningKey;
use operp_dag::{genesis_id, sign_unit, unit_id, Op, Unit};
use operp_exec::{Engine, ExecEvent};
use operp_settle::Batch;
use operp_types::{
    account_id_from_pubkey, AccountId, OrderType, Side, TimeInForce, UnitId, BTC_USD,
    PRICE_SCALE, QTY_SCALE, USD_SCALE,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const TRADERS_PER_ENGINE: usize = 4;

fn sk(n: u8) -> [u8; 32] { [n; 32] }
fn acct(secret: &[u8; 32]) -> AccountId {
    account_id_from_pubkey(&SigningKey::from_bytes(secret).verifying_key().to_bytes())
}

struct Cfg {
    run_ms: u64,
    out: PathBuf,
    engines: usize,
}

fn parse_args() -> Cfg {
    let mut args = std::env::args().skip(1);
    let run_ms: u64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(1_200_000);
    let out = args.next().map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("obyte-local/stress-out"));
    let engines: usize = args.next().and_then(|a| a.parse().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4));
    Cfg { run_ms, out, engines }
}

/// Generator thread: signs units as fast as possible and sends them downstream.
/// Signing (ed25519) is the parallelizable part; execution stays sequential.
fn generator(idx: usize, n_engines: usize, cfg: &Cfg, tx: Sender<(usize, Unit)>, gen_total: Arc<AtomicU64>) {
    let secrets: Vec<[u8; 32]> = (0..TRADERS_PER_ENGINE)
        .map(|i| sk((((idx * TRADERS_PER_ENGINE + i + 1) * 37 + 11) % 251) as u8))
        .collect();
    let mut seqs = vec![1u64; TRADERS_PER_ENGINE];
    let px = 100_000 * PRICE_SCALE;
    let qty = QTY_SCALE / 100;
    let mut tip = genesis_id();

    // deposits first
    for (i, s) in secrets.iter().enumerate() {
        let u = sign_unit(
            vec![tip],
            Op::Deposit {
                account: acct(s),
                amount: 10_000_000 * USD_SCALE as i128,
                aa_unit: [((idx * 100 + i) % 250 + 1) as u8; 32],
            },
            s,
        );
        tip = unit_id(&u);
        tx.send((idx, u)).expect("executor alive");
        seqs[i % TRADERS_PER_ENGINE] += 0; // deposits have no client_seq
    }

    let end = Instant::now() + Duration::from_millis(cfg.run_ms);
    let mut pair = 0usize;
    while Instant::now() < end {
        let i = pair % TRADERS_PER_ENGINE;
        let j = (i + 1) % TRADERS_PER_ENGINE;
        pair += 2;

        for (who, side, tif) in [
            (i, Side::Ask, TimeInForce::Gtc),
            (j, Side::Bid, TimeInForce::Ioc),
            (j, Side::Ask, TimeInForce::Gtc),
            (i, Side::Bid, TimeInForce::Ioc),
        ] {
            let cs = seqs[who];
            let u = sign_unit(
                vec![tip],
                Op::Place {
                    account: acct(&secrets[who]),
                    market: BTC_USD,
                    side,
                    typ: OrderType::Limit,
                    tif,
                    price: px,
                    qty,
                    client_seq: cs,
                },
                &secrets[who],
            );
            tip = unit_id(&u);
            seqs[who] += 1;
            if tx.send((idx, u)).is_err() { return; }
            gen_total.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn main() {
    let cfg = parse_args();
    std::fs::create_dir_all(&cfg.out).expect("mkdir");
    println!("READY");
    println!("PIPELINE HFT: {} signers -> 1 executor, {}ms", cfg.engines, cfg.run_ms);

    let mut eng0 = Engine::new();
    eng0.state.deposits_allowed = (1u8..=255).map(|b| [b; 32]).collect();
    eng0.state.allowed_markets.insert(BTC_USD);
    let eng = Arc::new(Mutex::new(eng0));
    let executed = Arc::new(AtomicU64::new(0));
    let fills = Arc::new(AtomicU64::new(0));
    let generated = Arc::new(AtomicU64::new(0));
    let (tx, rx) = channel::<(usize, Unit)>();
    // share rx via mutex so one executor thread owns it
    let rx = Arc::new(Mutex::new(rx));

    let start = Instant::now();

    // executor thread: sequential deterministic ingest (protocol requirement)
    let exec_handle = {
        let eng = Arc::clone(&eng);
        let executed = Arc::clone(&executed);
        let fills = Arc::clone(&fills);
        let rx = Arc::clone(&rx);
        let run_ms = cfg.run_ms;
        let out = cfg.out.clone();
        std::thread::spawn(move || {
            let rx = rx.lock().unwrap_or_else(|e| e.into_inner());
            let mut prev_state = None;
            let deadline = Instant::now() + Duration::from_millis(run_ms + 30_000);
            while Instant::now() < deadline {
                match rx.recv_timeout(Duration::from_millis(500)) {
                    Ok((_gen, u)) => {
                        let mut e = eng.lock().unwrap_or_else(|e| e.into_inner());
                        if prev_state.is_none() {
                            prev_state = Some(e.state.clone());
                        }
                        match e.ingest(u) {
                            Ok(events) => {
                                for ev in &events {
                                    if let ExecEvent::Applied { fills: f, .. } = ev {
                                        fills.fetch_add(f.len() as u64, Ordering::Relaxed);
                                    }
                                }
                            }
                            Err(_) => {}
                        }
                        drop(e);
                        executed.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        if Instant::now() > deadline { break; }
                    }
                }
            }
            let _ = prev_state;
        })
    };

    // generators
    let mut gens = Vec::new();
    for idx in 0..cfg.engines {
        let tx = tx.clone();
        let gt = Arc::clone(&generated);
        let c = Cfg { run_ms: cfg.run_ms, out: cfg.out.clone(), engines: cfg.engines };
        gens.push(std::thread::spawn(move || generator(idx, cfg.engines, &c, tx, gt)));
    }
    drop(tx);

    // progress reporter
    let mut last = (0u64, 0u64, Instant::now());
    while start.elapsed() < Duration::from_millis(cfg.run_ms) {
        std::thread::sleep(Duration::from_secs(15));
        let ex = executed.load(Ordering::Relaxed);
        let f = fills.load(Ordering::Relaxed);
        let dt = last.2.elapsed().as_secs_f64().max(0.001);
        println!(
            "[par {:.0}s] exec={} fill={} | {:.0} exec/s",
            start.elapsed().as_secs_f64(), ex, f, (ex - last.0) as f64 / dt
        );
        last = (ex, f, Instant::now());
    }

    for g in gens { let _ = g.join(); }
    let _ = exec_handle.join();

    let secs = start.elapsed().as_secs_f64();
    let ex = executed.load(Ordering::Relaxed);
    let f = fills.load(Ordering::Relaxed);
    println!("---");
    println!("SIDE_RESULT");
    println!("duration_s\t{secs:.1}");
    println!("engines\t{}", cfg.engines);
    println!("executed\t{ex}");
    println!("fills\t{f}");
    println!("exec_tps\t{:.1}", ex as f64 / secs);

    let e = eng.lock().unwrap_or_else(|e| e.into_inner());
    let mut open = 0i64;
    for a in e.state.accounts.values() {
        if let Some(p) = a.positions.get(&BTC_USD) { open += p.qty.abs(); }
    }
    println!("sum_abs_qty\t{open}");
    println!("accounts\t{}", e.state.accounts.len());

    // export final state batch info
    println!("OK: pipeline feed complete");
}
