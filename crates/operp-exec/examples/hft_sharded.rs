use ed25519_dalek::SigningKey;
use operp_dag::{genesis_id, sign_unit, unit_id, Op};
use operp_exec::Engine;
use operp_types::{
    account_id_from_pubkey, AccountId, MarketId, OrderType, Qty, Side, TimeInForce, UnitId,
    PRICE_SCALE, QTY_SCALE, USD_SCALE,
};
use std::time::{Duration, Instant};

/// Sharded parallel matching: one Engine per market, one thread per shard.
/// Markets share nothing - books, accounts (per-shard isolated margin for the
/// benchmark), marks. Cross-margin unification happens at settlement; matching
/// itself is 100% market-local so shards scale linearly.

const TRADERS: usize = 4;

fn sk(n: u8) -> [u8; 32] {
    [n; 32]
}
fn acct(secret: &[u8; 32]) -> AccountId {
    account_id_from_pubkey(&SigningKey::from_bytes(secret).verifying_key().to_bytes())
}

struct Cfg {
    run_ms: u64,
    shards: usize,
}

fn parse_args() -> Cfg {
    let mut args = std::env::args().skip(1);
    let run_ms: u64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(300_000);
    let shards: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    });
    Cfg { run_ms, shards }
}

fn run_shard(shard_idx: usize, cfg: &Cfg) -> (u64, u64, u64) {
    let market = MarketId(shard_idx as u32 + 1);
    let mut eng = Engine::new();
    eng.state.deposits_allowed = (1u8..=255)
        .flat_map(|b| [([b; 32], false), ([b; 32], true)])
        .collect();
    eng.state
        .markets
        .insert(market, operp_types::genesis_params());

    // seed mark for this market via first trade: place resting ask before bids.
    // ChainState::new() only seeds BTC_USD mark; other markets get mark from
    // their first fill (apply_fill_pair inserts it), which is all we need here:
    // risk check uses limit price for Limit orders, so trading works pre-mark.
    let secrets: Vec<[u8; 32]> = (0..TRADERS)
        .map(|i| sk((((shard_idx * TRADERS + i + 3) * 41 + 7) % 251) as u8))
        .collect();
    let mut seqs = vec![1u64; TRADERS];
    let px = 100_000 * PRICE_SCALE;
    let qty = QTY_SCALE / 100;
    let mut tip = genesis_id();

    for (i, s) in secrets.iter().enumerate() {
        let u = sign_unit(
            vec![tip],
            Op::Deposit {
                account: acct(s),
                addr: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                amount: 10_000_000 * USD_SCALE as i128,
                aa_unit: [((shard_idx * TRADERS + i) % 250 + 1) as u8; 32],
            },
            s,
        );
        tip = unit_id(&u);
        eng.ingest(u).expect("deposit");
    }

    let start = Instant::now();
    let end = start + Duration::from_millis(cfg.run_ms);
    let mut ops = 0u64;
    let mut fills_total = 0u64;
    let mut rejected = 0u64;
    let mut pair = 0usize;

    while Instant::now() < end {
        let i = pair % TRADERS;
        let j = (i + 1) % TRADERS;
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
                    market,
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
            match eng.ingest(u) {
                Ok(evs) => {
                    ops += evs.len() as u64;
                    for e in &evs {
                        if let operp_exec::ExecEvent::Applied { fills, .. } = e {
                            fills_total += fills.len() as u64;
                        }
                        if matches!(e, operp_exec::ExecEvent::Rejected { .. }) {
                            rejected += 1;
                        }
                    }
                }
                Err(_) => rejected += 1,
            }
        }

        if eng.log.len() > 16_384 {
            eng.log.clear();
        }
    }

    (ops, fills_total, rejected)
}

fn main() {
    let cfg = parse_args();
    println!("READY");
    println!(
        "SHARDED matching: {} markets x {} traders, {}ms",
        cfg.shards, TRADERS, cfg.run_ms
    );

    let start = Instant::now();
    let mut handles = Vec::new();
    for idx in 0..cfg.shards {
        let c = Cfg {
            run_ms: cfg.run_ms,
            shards: cfg.shards,
        };
        handles.push(std::thread::spawn(move || run_shard(idx, &c)));
    }

    // live aggregate reporter
    let report_at = start + Duration::from_millis(cfg.run_ms);
    while Instant::now() < report_at {
        std::thread::sleep(Duration::from_secs(15));
        // threads own their counters; final report prints totals
    }

    let mut tot_ops = 0u64;
    let mut tot_fills = 0u64;
    let mut tot_rej = 0u64;
    for h in handles {
        let (o, f, r) = h.join().expect("shard thread");
        tot_ops += o;
        tot_fills += f;
        tot_rej += r;
    }

    let secs = start.elapsed().as_secs_f64();
    println!("---");
    println!("SHARD_RESULT");
    println!("duration_s\t{secs:.1}");
    println!("markets\t{}", cfg.shards);
    println!("ops\t{tot_ops}");
    println!("fills\t{tot_fills}");
    println!("rejected\t{tot_rej}");
    println!("aggregate_tps\t{:.1}", tot_ops as f64 / secs);
    println!(
        "per_market_tps\t{:.1}",
        tot_ops as f64 / secs / cfg.shards as f64
    );
    println!("OK: sharded feed complete");
}
