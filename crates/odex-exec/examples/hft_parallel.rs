use ed25519_dalek::SigningKey;
use odex_dag::{genesis_id, sign_unit, unit_id, Op};
use odex_exec::{Engine, ExecEvent};
use odex_settle::Batch;
use odex_types::{
    account_id_from_pubkey, AccountId, OrderType, Qty, Side, TimeInForce, UnitId, BTC_USD,
    PRICE_SCALE, QTY_SCALE, USD_SCALE,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const TRADERS_PER_ENGINE: usize = 4;

fn sk(n: u8) -> [u8; 32] {
    [n; 32]
}
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
    let out = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("obyte-local/stress-out"));
    let engines: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or_else(|| num_cpus());
    Cfg { run_ms, out, engines }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
}

/// One generator thread: builds its own DAG branch from genesis with its own traders.
/// Units from all branches merge into the shared engine; ready_linearized orders them
/// deterministically by unit_id (the concurrent-DAG path the protocol is built on).
fn run_engine(
    eng: Arc<Mutex<Engine>>,
    engine_idx: usize,
    n_engines: usize,
    cfg: &Cfg,
    totals: Arc<AtomicU64>,
    fill_total: Arc<AtomicU64>,
) -> u64 {
    // deterministic per-engine trader secrets, disjoint across engines
    let secrets: Vec<[u8; 32]> = (0..TRADERS_PER_ENGINE)
        .map(|i| sk(((engine_idx * TRADERS_PER_ENGINE + i + 1) * 17 % 251) as u8))
        .collect();
    let mut seqs = vec![1u64; TRADERS_PER_ENGINE];
    let px = 100_000 * PRICE_SCALE;
    let qty = QTY_SCALE / 100;

    // deposits on own branch
    let mut tip = genesis_id();
    {
        let mut e = eng.lock().unwrap_or_else(|e| e.into_inner());
        for (i, s) in secrets.iter().enumerate() {
            let uid_salt = (engine_idx * 100 + i) as u8;
            let u = sign_unit(
                vec![tip],
                Op::Deposit {
                    account: acct(s),
                    amount: 10_000_000 * USD_SCALE as i128,
                    aa_unit: [uid_salt; 32],
                },
                s,
            );
            tip = unit_id(&u);
            e.ingest(u).expect("deposit");
        }
    }

    let start = Instant::now();
    let end = start + Duration::from_millis(cfg.run_ms);
    let mut prev_state = eng.lock().unwrap_or_else(|e| e.into_inner()).state.clone();
    let mut pending_units: Vec<UnitId> = Vec::new();
    let mut height: u64 = 0;
    let mut local_ops = 0u64;
    let mut pair = 0usize;
    // each engine sleeps a distinct tiny offset to avoid lock-step contention
    let jitter = Duration::from_micros(((engine_idx * 137) % 1000) as u64);

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
            let my_tip = tip;
            let u = sign_unit(
                vec![my_tip],
                Op::Place {
                    account: acct(&secrets[who]),
                    market: BTC_USD,
                    side,
                    typ: OrderType::Limit,
                    tif,
                    price: px,
                    qty,
                    client_seq: seqs[who],
                },
                &secrets[who],
            );
            let id = unit_id(&u);
            let evs = {
                let mut e = eng.lock().unwrap_or_else(|e| e.into_inner());
                e.ingest(u)
            };
            match evs {
                Ok(events) => {
                    seqs[who] += 1;
                    pending_units.push(id);
                    local_ops += 1;
                    for ev in &events {
                        if let ExecEvent::Applied { fills, .. } = ev {
                            fill_total.fetch_add(fills.len() as u64, Ordering::Relaxed);
                        }
                    }
                    // advance own branch tip only sometimes: creates concurrency across engines
                    if local_ops % 3 != 0 || n_engines == 1 {
                        tip = id;
                    } else {
                        // branch off an older point: other engines' units interleave
                        tip = my_tip;
                    }
                }
                Err(_) => { /* duplicate client_seq etc: skip */ }
            }
            totals.fetch_add(1, Ordering::Relaxed);
        }
        std::thread::sleep(jitter);

        if pending_units.len() >= 512 {
            height += 1;
            let units = std::mem::take(&mut pending_units);
            let e = eng.lock().unwrap_or_else(|e| e.into_inner());
            match Batch::from_applied(&prev_state, &e, &units) {
                Ok(batch) => {
                    let payload = batch.temp_data_payload();
                    let text = serde_json::to_string(&payload.data).unwrap();
                    let f = cfg.out.join(format!("batch-e{}.json", engine_idx));
                    let tmp = cfg.out.join(format!("batch-e{}.tmp", engine_idx));
                    let _ = std::fs::write(&tmp, &text);
                    let _ = std::fs::rename(&tmp, &f);
                }
                Err(_) => {}
            }
            drop(e);
            prev_state = eng.lock().unwrap_or_else(|e| e.into_inner()).state.clone();
        }
    }

    // final flush
    if !pending_units.is_empty() {
        let units = std::mem::take(&mut pending_units);
        let e = eng.lock().unwrap_or_else(|e| e.into_inner());
        if let Ok(batch) = Batch::from_applied(&prev_state, &e, &units) {
            let payload = batch.temp_data_payload();
            if let Ok(text) = serde_json::to_string(&payload.data) {
                let _ = std::fs::write(cfg.out.join(format!("batch-e{}-final.json", engine_idx)), &text);
            }
        }
    }
    height
}

fn main() {
    let cfg = parse_args();
    std::fs::create_dir_all(&cfg.out).expect("mkdir");

    println!("READY");
    println!(
        "PARALLEL HFT feed: {} engines x {} traders, {}ms",
        cfg.engines, TRADERS_PER_ENGINE, cfg.run_ms
    );

    let eng = Arc::new(Mutex::new(Engine::new()));
    let totals = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let fills = Arc::new(std::sync::atomic::AtomicU64::new(0));

    let start = Instant::now();
    let mut handles = Vec::new();
    for idx in 0..cfg.engines {
        let eng = Arc::clone(&eng);
        let totals = Arc::clone(&totals);
        let fills = Arc::clone(&fills);
        let cfg_ref = Cfg {
            run_ms: cfg.run_ms,
            out: cfg.out.clone(),
            engines: cfg.engines,
        };
        handles.push(std::thread::spawn(move || {
            run_engine(eng, idx, cfg.engines, &cfg_ref, totals, fills)
        }));
    }

    // progress reporter on main thread
    let mut last = (0u64, 0u64, Instant::now());
    while start.elapsed() < Duration::from_millis(cfg.run_ms) {
        std::thread::sleep(Duration::from_secs(15));
        let t = totals.load(Ordering::Relaxed);
        let f = fills.load(Ordering::Relaxed);
        let dt = last.2.elapsed().as_secs_f64();
        let el = start.elapsed().as_secs_f64();
        println!(
            "[par {:.0}s] ops={} fill={} | {:.0} op/s {:.0} ord/s",
            el,
            t,
            f,
            (t - last.0) as f64 / dt,
            (t - last.0) as f64 / dt,
        );
        last = (t, f, Instant::now());
    }

    for h in handles {
        let _ = h.join();
    }

    let secs = start.elapsed().as_secs_f64();
    let t = totals.load(Ordering::Relaxed);
    let f = fills.load(Ordering::Relaxed);
    println!("---");
    println!("SIDE_RESULT");
    println!("duration_s\t{secs:.1}");
    println!("engines\t{}", cfg.engines);
    println!("ops\t{t}");
    println!("fills\t{f}");
    println!("op_tps\t{:.1}", t as f64 / secs);

    // final state sanity: total open interest across all accounts
    let e = eng.lock().unwrap_or_else(|e| e.into_inner());
    let mut open = 0i64;
    for a in e.state.accounts.values() {
        if let Some(p) = a.positions.get(&BTC_USD) {
            open += p.qty.abs();
        }
    }
    println!("sum_abs_qty\t{open}");
    println!("accounts\t{}", e.state.accounts.len());
    println!("OK: parallel feed complete");
}
