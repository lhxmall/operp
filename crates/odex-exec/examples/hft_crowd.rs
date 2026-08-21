use ed25519_dalek::SigningKey;
use odex_dag::{genesis_id, sign_unit, unit_id, Op};
use odex_exec::{Engine, ExecEvent};
use odex_types::{
    account_id_from_pubkey, AccountId, OrderType, Qty, Side, TimeInForce, UnitId, Usd, BTC_USD,
    PRICE_SCALE, QTY_SCALE, USD_SCALE,
};
use std::time::{Duration, Instant};

const N: usize = 16;
const RUN_SECS: u64 = 600;
const REPORT_SECS: u64 = 30;

fn sk(n: u8) -> [u8; 32] {
    [n; 32]
}
fn acct(secret: &[u8; 32]) -> AccountId {
    account_id_from_pubkey(&SigningKey::from_bytes(secret).verifying_key().to_bytes())
}

fn ingest_place(
    eng: &mut Engine,
    tip: UnitId,
    secret: &[u8; 32],
    side: Side,
    tif: TimeInForce,
    price: u64,
    qty: Qty,
    client_seq: u64,
) -> (UnitId, Vec<ExecEvent>) {
    let u = sign_unit(
        vec![tip],
        Op::Place {
            account: acct(secret),
            market: BTC_USD,
            side,
            typ: OrderType::Limit,
            tif,
            price,
            qty,
            client_seq,
        },
        secret,
    );
    let id = unit_id(&u);
    let evs = eng.ingest(u).expect("ingest");
    (id, evs)
}

fn main() {
    let mut eng = Engine::new();
    let mut secrets: Vec<[u8; 32]> = (1..=N as u8).map(sk).collect();
    let mut seqs = vec![1u64; N];
    let px = 100_000 * PRICE_SCALE;
    let qty = QTY_SCALE / 100;
    let mut tip = genesis_id();

    for (i, s) in secrets.iter().enumerate() {
        let u = sign_unit(
            vec![tip],
            Op::Deposit {
                account: acct(s),
                amount: 1_000_000 * USD_SCALE as i128,
                aa_unit: [i as u8 + 1; 32],
            },
            s,
        );
        tip = unit_id(&u);
        eng.ingest(u).expect("deposit");
    }

    let mut orders = 0u64;
    let mut fills = 0u64;
    let mut applied = 0u64;
    let mut rejected = 0u64;
    let mut last_report = Instant::now();
    let mut last_orders = 0u64;
    let mut last_fills = 0u64;
    let start = Instant::now();
    let end = start + Duration::from_secs(RUN_SECS);
    println!(
        "HFT crowd: {N} traders open/close 0.01 BTC, {RUN_SECS}s"
    );
    println!("elapsed_s\torders\tfills\trejects\tord/s\tfill/s");

    let mut pair = 0usize;
    while Instant::now() < end {
        let i = pair % N;
        let j = (i + 1) % N;
        pair += 2;

        // open: i ask, j bid
        let (id, evs) = ingest_place(
            &mut eng,
            tip,
            &secrets[i],
            Side::Ask,
            TimeInForce::Gtc,
            px,
            qty,
            seqs[i],
        );
        tip = id;
        bump(&evs, i, &mut seqs, &mut orders, &mut fills, &mut applied, &mut rejected);
        let (id, evs) = ingest_place(
            &mut eng,
            tip,
            &secrets[j],
            Side::Bid,
            TimeInForce::Ioc,
            px,
            qty,
            seqs[j],
        );
        tip = id;
        bump(&evs, j, &mut seqs, &mut orders, &mut fills, &mut applied, &mut rejected);

        // close: j ask, i bid
        let (id, evs) = ingest_place(
            &mut eng,
            tip,
            &secrets[j],
            Side::Ask,
            TimeInForce::Gtc,
            px,
            qty,
            seqs[j],
        );
        tip = id;
        bump(&evs, j, &mut seqs, &mut orders, &mut fills, &mut applied, &mut rejected);
        let (id, evs) = ingest_place(
            &mut eng,
            tip,
            &secrets[i],
            Side::Bid,
            TimeInForce::Ioc,
            px,
            qty,
            seqs[i],
        );
        tip = id;
        bump(&evs, i, &mut seqs, &mut orders, &mut fills, &mut applied, &mut rejected);

        if eng.log.len() > 8192 {
            eng.log.clear();
        }
        if last_report.elapsed() >= Duration::from_secs(REPORT_SECS) {
            let elapsed = start.elapsed().as_secs_f64();
            let dt = last_report.elapsed().as_secs_f64();
            println!(
                "{:.0}\t{}\t{}\t{}\t{:.0}\t{:.0}",
                elapsed,
                orders,
                fills,
                rejected,
                (orders - last_orders) as f64 / dt,
                (fills - last_fills) as f64 / dt
            );
            last_report = Instant::now();
            last_orders = orders;
            last_fills = fills;
        }
    }

    let secs = start.elapsed().as_secs_f64();
    println!("---");
    println!("traders\t{N}");
    println!("duration_s\t{:.2}", secs);
    println!("orders\t{orders}");
    println!("fills\t{fills}");
    println!("applied\t{applied}");
    println!("rejected\t{rejected}");
    println!("ord/s\t{:.1}", orders as f64 / secs);
    println!("fill/s\t{:.1}", fills as f64 / secs);
    let mut open = 0i64;
    for s in &secrets {
        if let Some(p) = eng
            .state
            .accounts
            .get(&acct(s))
            .and_then(|a| a.positions.get(&BTC_USD))
        {
            open += p.qty.abs();
        }
    }
    println!("sum_abs_qty\t{open}");
    println!("OK: crowd HFT complete");
    let _ = secrets;
}

fn bump(
    evs: &[ExecEvent],
    idx: usize,
    seqs: &mut [u64],
    orders: &mut u64,
    fills: &mut u64,
    applied: &mut u64,
    rejected: &mut u64,
) {
    *orders += 1;
    let mut ok = false;
    for e in evs {
        match e {
            ExecEvent::Applied { fills: f, .. } => {
                *applied += 1;
                *fills += f.len() as u64;
                ok = true;
            }
            ExecEvent::Rejected { reason, .. } => {
                *rejected += 1;
                if *rejected == 1 {
                    eprintln!("first_reject {reason:?} trader={idx}");
                }
            }
        }
    }
    if ok {
        seqs[idx] += 1;
    }
}
