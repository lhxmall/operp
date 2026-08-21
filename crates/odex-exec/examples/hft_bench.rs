use ed25519_dalek::SigningKey;
use odex_dag::{genesis_id, sign_unit, unit_id, Op};
use odex_exec::{Engine, ExecEvent};
use odex_types::{
    account_id_from_pubkey, AccountId, OrderType, Qty, Side, TimeInForce, UnitId, Usd, BTC_USD,
    PRICE_SCALE, QTY_SCALE, USD_SCALE,
};
use std::time::{Duration, Instant};

const RUN_SECS: u64 = 1800;
const REPORT_SECS: u64 = 30;

fn sk(n: u8) -> [u8; 32] {
    [n; 32]
}

fn acct(secret: &[u8; 32]) -> AccountId {
    account_id_from_pubkey(&SigningKey::from_bytes(secret).verifying_key().to_bytes())
}

fn deposit(parents: Vec<UnitId>, secret: &[u8; 32], amount: Usd, aa: u8) -> odex_dag::Unit {
    sign_unit(
        parents,
        Op::Deposit {
            account: acct(secret),
            amount,
            aa_unit: [aa; 32],
        },
        secret,
    )
}

fn place(
    parents: Vec<UnitId>,
    secret: &[u8; 32],
    side: Side,
    tif: TimeInForce,
    price: u64,
    qty: Qty,
    client_seq: u64,
) -> odex_dag::Unit {
    sign_unit(
        parents,
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
    )
}


fn main() {
    let mut eng = Engine::new();
    let g = genesis_id();
    let alice = sk(1);
    let bob = sk(2);
    let px = 100_000 * PRICE_SCALE;
    let qty = QTY_SCALE / 100;

    let d1 = deposit(vec![g], &alice, 1_000_000 * USD_SCALE as i128, 1);
    let mut tip = unit_id(&d1);
    eng.ingest(d1).expect("alice deposit");
    let d2 = deposit(vec![tip], &bob, 1_000_000 * USD_SCALE as i128, 2);
    tip = unit_id(&d2);
    eng.ingest(d2).expect("bob deposit");

    let mut alice_seq = 1u64;
    let mut bob_seq = 1u64;
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
        "HFT bench: Engine::ingest signed Place, {}s, 0.01 BTC @ 100000",
        RUN_SECS
    );
    println!("elapsed_s\torders\tfills\trejects\tord/s\tfill/s");

    let mut round = 0u64;
    let mut first_reject: Option<String> = None;
    while Instant::now() < end {
        let maker_side = if round % 2 == 0 { Side::Ask } else { Side::Bid };
        let taker_side = if round % 2 == 0 { Side::Bid } else { Side::Ask };
        let (maker_sk, taker_sk) = if round % 2 == 0 {
            (&bob, &alice)
        } else {
            (&alice, &bob)
        };
        let maker_seq = if round % 2 == 0 { bob_seq } else { alice_seq };
        let taker_seq = if round % 2 == 0 { alice_seq } else { bob_seq };

        let mk = place(
            vec![tip],
            maker_sk,
            maker_side,
            TimeInForce::Gtc,
            px,
            qty,
            maker_seq,
        );
        tip = unit_id(&mk);
        let evs = eng.ingest(mk).expect("maker ingest");
        let maker_ok = applied_ok(&evs);
        note_reject(&evs, &mut first_reject);
        tally(&evs, &mut applied, &mut rejected, &mut fills);
        orders += 1;
        if maker_ok {
            if round % 2 == 0 {
                bob_seq += 1;
            } else {
                alice_seq += 1;
            }
        }

        let tk = place(
            vec![tip],
            taker_sk,
            taker_side,
            TimeInForce::Ioc,
            px,
            qty,
            taker_seq,
        );
        tip = unit_id(&tk);
        let evs = eng.ingest(tk).expect("taker ingest");
        let taker_ok = applied_ok(&evs);
        note_reject(&evs, &mut first_reject);
        tally(&evs, &mut applied, &mut rejected, &mut fills);
        orders += 1;
        if taker_ok {
            if round % 2 == 0 {
                alice_seq += 1;
            } else {
                bob_seq += 1;
            }
        }

        round += 1;
        if eng.log.len() > 8_192 {
            eng.log.clear();
        }

        if last_report.elapsed() >= Duration::from_secs(REPORT_SECS) {
            let elapsed = start.elapsed().as_secs_f64();
            let dt = last_report.elapsed().as_secs_f64();
            let d_ord = orders - last_orders;
            let d_fill = fills - last_fills;
            println!(
                "{:.0}\t{}\t{}\t{}\t{:.0}\t{:.0}",
                elapsed,
                orders,
                fills,
                rejected,
                d_ord as f64 / dt,
                d_fill as f64 / dt
            );
            last_report = Instant::now();
            last_orders = orders;
            last_fills = fills;
        }
    }

    let secs = start.elapsed().as_secs_f64();
    println!("---");
    println!("duration_s\t{:.2}", secs);
    println!("orders\t{}", orders);
    println!("fills\t{}", fills);
    println!("applied\t{}", applied);
    println!("rejected\t{}", rejected);
    if let Some(r) = first_reject {
        println!("first_reject\t{}", r);
    }
    println!("ord/s\t{:.1}", orders as f64 / secs);
    println!("fill/s\t{:.1}", fills as f64 / secs);
    println!("OK: 30min HFT bench complete");
}

fn tally(evs: &[ExecEvent], applied: &mut u64, rejected: &mut u64, fills: &mut u64) {
    for e in evs {
        match e {
            ExecEvent::Applied { fills: f, .. } => {
                *applied += 1;
                *fills += f.len() as u64;
            }
            ExecEvent::Rejected { .. } => *rejected += 1,
        }
    }
}

fn applied_ok(evs: &[ExecEvent]) -> bool {
    evs.iter()
        .any(|e| matches!(e, ExecEvent::Applied { .. }))
}

fn note_reject(evs: &[ExecEvent], first: &mut Option<String>) {
    if first.is_some() {
        return;
    }
    for e in evs {
        if let ExecEvent::Rejected { reason, .. } = e {
            *first = Some(format!("{:?}", reason));
            return;
        }
    }
}
