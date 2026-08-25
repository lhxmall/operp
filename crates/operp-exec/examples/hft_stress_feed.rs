use ed25519_dalek::SigningKey;
use operp_dag::{genesis_id, sign_unit, unit_id, Op};
use operp_exec::{Engine, ExecEvent};
use operp_settle::Batch;
use operp_types::{
    account_id_from_pubkey, AccountId, OrderType, Qty, Side, TimeInForce, UnitId, Usd, BTC_USD,
    PRICE_SCALE, QTY_SCALE, USD_SCALE,
};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const N: usize = 8;

fn sk(n: u8) -> [u8; 32] {
    [n; 32]
}
fn acct(secret: &[u8; 32]) -> AccountId {
    account_id_from_pubkey(&SigningKey::from_bytes(secret).verifying_key().to_bytes())
}

struct Cfg {
    run_ms: u64,
    out: PathBuf,
}

fn parse_args() -> Cfg {
    let mut args = std::env::args().skip(1);
    let run_ms: u64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(1_200_000);
    let out = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("obyte-local/stress-out"));
    Cfg { run_ms, out }
}

fn main() {
    let cfg = parse_args();
    std::fs::create_dir_all(&cfg.out).expect("mkdir");

    let mut eng = Engine::new();
    eng.state.deposits_allowed = (1u8..=255).flat_map(|b| [([b; 32], false), ([b; 32], true)]).collect();
    eng.state.markets.insert(BTC_USD, operp_types::genesis_params());
    let secrets: Vec<[u8; 32]> = (1..=N as u8).map(sk).collect();
    let mut seqs = vec![1u64; N];
    let px = 100_000 * PRICE_SCALE;
    let qty = QTY_SCALE / 100; // 0.01 BTC
    let mut tip = genesis_id();

    for (i, s) in secrets.iter().enumerate() {
        let u = sign_unit(
            vec![tip],
            Op::Deposit { account: acct(s), addr: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(), amount: 10_000_000 * USD_SCALE as i128, aa_unit: [i as u8 + 1; 32] },
            s,
        );
        tip = unit_id(&u);
        eng.ingest(u).expect("deposit");
    }

    println!("READY");
    println!("HFT sidechain feed: {N} traders, {}ms, open/close 0.01 BTC @ {}", cfg.run_ms, px);

    let start = Instant::now();
    let end = start + Duration::from_millis(cfg.run_ms);

    // batch export state: collect applied units since last checkpoint
    let mut prev_state = eng.state.clone();
    let mut pending_units: Vec<UnitId> = Vec::new();
    let mut height: u64 = 0;

    let mut orders = 0u64;
    let mut fills = 0u64;
    let mut rejected = 0u64;
    let mut applied_total = 0u64;
    let mut pair = 0usize;
    let mut last_report = Instant::now();
    let mut last_orders = 0u64;
    let mut last_fills = 0u64;
    let report_secs: u64 = 30;

    while Instant::now() < end {
        let i = pair % N;
        let j = (i + 1) % N;
        pair += 2;

        // burst of 4 units per iteration (open x2, close x2), single chain tip
        for (who, side, tif) in [
            (i, Side::Ask, TimeInForce::Gtc),
            (j, Side::Bid, TimeInForce::Ioc),
            (j, Side::Ask, TimeInForce::Gtc),
            (i, Side::Bid, TimeInForce::Ioc),
        ] {
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
                    client_seq: seqs[who],
                },
                &secrets[who],
            );
            tip = unit_id(&u);
            seqs[who] += 1;
            match eng.ingest(u) {
                Ok(evs) => {
                    pending_units.push(tip);
                    orders += evs.len() as u64;
                    for e in &evs {
                        if let ExecEvent::Applied { fills: f, .. } = e {
                            fills += f.len() as u64;
                        }
                        if matches!(e, ExecEvent::Rejected { .. }) {
                            rejected += 1;
                        }
                    }
                    applied_total += 1;
                }
                Err(_) => rejected += 1,
            }
        }

        // cut a batch every 512 units
        if pending_units.len() >= 512 {
            height += 1;
            let units = std::mem::take(&mut pending_units);
            let mut settled: Vec<UnitId> = Vec::new();
            let batch_ok = match Batch::from_applied(&prev_state, &mut eng, &units) {
                Ok(batch) => {
                    settled = units.clone();
                    let payload = batch.temp_data_payload();
                    let text = serde_json::to_string(&payload.data).unwrap();
                    let f = cfg.out.join("batch.json");
                    let tmp = cfg.out.join("batch.json.tmp");
                    std::fs::write(&tmp, &text).expect("write tmp");
                    std::fs::rename(&tmp, &f).expect("rename");
                    println!(
                        "BATCH height={} units={} fills={} root={}",
                        height,
                        units.len(),
                        batch.checkpoint.fill_count,
                        hex::encode(&batch.checkpoint.state_root[..8])
                    );
                    true
                }
                Err(e) => {
                    eprintln!("batch err: {e}");
                    false
                }
            };
            // prune log entries already settled into the batch (bounded log)
            if batch_ok {
                eng.prune_below(&settled);
            }
            prev_state = eng.state.clone();
        }

        if last_report.elapsed().as_secs() >= report_secs {
            let dt = last_report.elapsed().as_secs_f64();
            let el = start.elapsed().as_secs_f64();
            println!(
                "[side {:.0}s] ops={applied_total} ord={orders} fill={fills} rej={rejected} | {:.0} op/s {:.0} ord/s",
                el,
                applied_total as f64 / dt,
                (orders - last_orders) as f64 / dt,
            );
            last_report = Instant::now();
            last_orders = orders;
            last_fills = fills;
        }
    }

    // flush remaining as final batch
    if !pending_units.is_empty() {
        height += 1;
        let units = std::mem::take(&mut pending_units);
        if let Ok(batch) = Batch::from_applied(&prev_state, &mut eng, &units) {
            let payload = batch.temp_data_payload();
            let text = serde_json::to_string(&payload.data).unwrap();
            let _ = std::fs::write(cfg.out.join("batch.json"), &text);
            println!(
                "BATCH_FINAL height={} units={} fills={}",
                height,
                units.len(),
                batch.checkpoint.fill_count
            );
            eng.prune_below(&units);
        }
    }

    let secs = start.elapsed().as_secs_f64();
    println!("---");
    println!("SIDE_RESULT");
    println!("duration_s\t{secs:.1}");
    println!("ops\t{applied_total}");
    println!("orders\t{orders}");
    println!("fills\t{fills}");
    println!("rejected\t{rejected}");
    println!("op_tps\t{:.1}", applied_total as f64 / secs);
    println!("order_tps\t{:.1}", orders as f64 / secs);
    println!("batches\t{height}");

    let mut open = 0i64;
    for s in &secrets {
        if let Some(p) = eng.state.accounts.get(&acct(s)).and_then(|a| a.positions.get(&BTC_USD)) {
            open += p.qty.abs();
        }
    }
    println!("sum_abs_qty\t{open}");
    println!("OK: hft_stress_feed complete");
}
