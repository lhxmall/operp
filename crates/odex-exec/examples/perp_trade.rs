use ed25519_dalek::SigningKey;
use odex_dag::{genesis_id, sign_unit, unit_id, Op};
use odex_exec::{Engine, ExecEvent};
use odex_types::{
    account_id_from_pubkey, AccountId, OrderType, Qty, Side, TimeInForce, UnitId, Usd, BTC_USD,
    PRICE_SCALE, QTY_SCALE, USD_SCALE,
};

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
            tif: TimeInForce::Gtc,
            price,
            qty,
            client_seq,
        },
        secret,
    )
}

fn usd(v: Usd) -> f64 {
    v as f64 / USD_SCALE as f64
}

fn main() {
    let mut eng = Engine::new();
    let g = genesis_id();
    let alice = sk(1);
    let bob = sk(2);
    let px = 100_000 * PRICE_SCALE;
    let qty = QTY_SCALE;

    let d1 = deposit(vec![g], &alice, 10_000 * USD_SCALE as i128, 1);
    let id1 = unit_id(&d1);
    eng.ingest(d1).expect("alice deposit");

    let d2 = deposit(vec![id1], &bob, 10_000 * USD_SCALE as i128, 2);
    let id2 = unit_id(&d2);
    eng.ingest(d2).expect("bob deposit");

    println!("seed mark BTC-USD = {}", 100_000);
    println!(
        "Alice deposit ${:.0}  Bob deposit ${:.0}",
        10_000.0, 10_000.0
    );

    let ask = place(vec![id2], &bob, Side::Ask, px, qty, 1);
    let id3 = unit_id(&ask);
    let ev_ask = eng.ingest(ask).expect("bob ask");
    println!("Bob Place Ask 1 BTC @ 100000 → {:?}", ev_ask[0]);

    let bid = place(vec![id3], &alice, Side::Bid, px, qty, 1);
    let ev_bid = eng.ingest(bid).expect("alice bid");
    println!("Alice Place Bid 1 BTC @ 100000 → {:?}", ev_bid[0]);

    let fills: Vec<_> = ev_bid
        .iter()
        .filter_map(|e| match e {
            ExecEvent::Applied { fills, .. } if !fills.is_empty() => Some(fills.clone()),
            _ => None,
        })
        .flatten()
        .collect();

    assert_eq!(fills.len(), 1, "expected one fill");
    let f = &fills[0];
    println!(
        "FILL qty={} price={} taker_side={:?} status=Optimistic",
        f.qty, f.price, f.taker_side
    );

    let a = acct(&alice);
    let b = acct(&bob);
    let pa = eng.state.accounts.get(&a).unwrap();
    let pb = eng.state.accounts.get(&b).unwrap();
    let qa = pa.positions[&BTC_USD].qty;
    let qb = pb.positions[&BTC_USD].qty;
    let marks = &eng.state.marks;
    let sa = pa.snapshot(marks);
    let sb = pb.snapshot(marks);

    println!(
        "Alice pos={:+} (long) equity=${:.2} mm=${:.2} liq={}",
        qa as f64 / QTY_SCALE as f64,
        usd(sa.equity),
        usd(sa.mm),
        sa.liquidatable
    );
    println!(
        "Bob   pos={:+} (short) equity=${:.2} mm=${:.2} liq={}",
        qb as f64 / QTY_SCALE as f64,
        usd(sb.equity),
        usd(sb.mm),
        sb.liquidatable
    );
    println!(
        "book bid={:?} ask={:?} mark={}",
        eng.state.books[&BTC_USD].best_bid(),
        eng.state.books[&BTC_USD].best_ask(),
        eng.state.marks[&BTC_USD] / PRICE_SCALE
    );

    assert_eq!(qa, qty as i64);
    assert_eq!(qb, -(qty as i64));
    println!("OK: perpetual trade executed");
}
