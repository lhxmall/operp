use ed25519_dalek::SigningKey;
use operp_dag::{genesis_id, sign_unit, unit_id, Op};
use operp_exec::{Engine, ExecEvent};
use operp_types::{
    account_id_from_pubkey, AccountId, OrderType, Qty, Side, TimeInForce, UnitId, Usd, BTC_USD,
    PRICE_SCALE, QTY_SCALE, USD_SCALE,
};

fn sk(n: u8) -> [u8; 32] {
    [n; 32]
}
fn acct(secret: &[u8; 32]) -> AccountId {
    account_id_from_pubkey(&SigningKey::from_bytes(secret).verifying_key().to_bytes())
}
fn deposit(parents: Vec<UnitId>, secret: &[u8; 32], amount: Usd, aa: u8) -> operp_dag::Unit {
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
) -> operp_dag::Unit {
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
    eng.state.deposits_allowed = (1u8..=255).map(|b| [b; 32]).collect();
    eng.state.allowed_markets.insert(BTC_USD);
    let g = genesis_id();
    let alice = sk(1);
    let bob = sk(2);
    let px = 100_000 * PRICE_SCALE;
    let qty = QTY_SCALE / 100;
    let d1 = deposit(vec![g], &alice, 1_000_000 * USD_SCALE as i128, 1);
    let mut tip = unit_id(&d1);
    eng.ingest(d1).unwrap();
    let d2 = deposit(vec![tip], &bob, 1_000_000 * USD_SCALE as i128, 2);
    tip = unit_id(&d2);
    eng.ingest(d2).unwrap();

    let mut alice_seq = 1u64;
    let mut bob_seq = 1u64;
    let mut fills = 0u64;
    let mut orders = 0u64;
    let a = acct(&alice);
    let b = acct(&bob);

    for round in 0u64..50_000 {
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
        let evs = eng.ingest(mk).unwrap();
        orders += 1;
        if dump_if_reject("maker", round, orders, fills, &evs, &eng, a, b) {
            return;
        }
        if applied(&evs) {
            if round % 2 == 0 {
                bob_seq += 1;
            } else {
                alice_seq += 1;
            }
        }
        fills += fill_n(&evs);

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
        let evs = eng.ingest(tk).unwrap();
        orders += 1;
        if dump_if_reject("taker", round, orders, fills, &evs, &eng, a, b) {
            return;
        }
        if applied(&evs) {
            if round % 2 == 0 {
                alice_seq += 1;
            } else {
                bob_seq += 1;
            }
        }
        fills += fill_n(&evs);
        if eng.log.len() > 1024 {
            eng.log.clear();
        }
    }
    println!("no reject in 50000 rounds fills={fills}");
}

fn applied(evs: &[ExecEvent]) -> bool {
    evs.iter().any(|e| matches!(e, ExecEvent::Applied { .. }))
}
fn fill_n(evs: &[ExecEvent]) -> u64 {
    evs.iter()
        .map(|e| match e {
            ExecEvent::Applied { fills, .. } => fills.len() as u64,
            _ => 0,
        })
        .sum()
}
fn dump_if_reject(
    who: &str,
    round: u64,
    orders: u64,
    fills: u64,
    evs: &[ExecEvent],
    eng: &Engine,
    a: AccountId,
    b: AccountId,
) -> bool {
    let rej = evs.iter().find_map(|e| match e {
        ExecEvent::Rejected { reason, .. } => Some(format!("{reason:?}")),
        _ => None,
    });
    let Some(reason) = rej else { return false };
    let sa = eng.state.accounts.get(&a).unwrap();
    let sb = eng.state.accounts.get(&b).unwrap();
    let na = sa.snapshot(&eng.state.marks);
    let nb = sb.snapshot(&eng.state.marks);
    let pa = sa.positions.get(&BTC_USD);
    let pb = sb.positions.get(&BTC_USD);
    let book = &eng.state.books[&BTC_USD];
    println!("REJECT who={who} round={round} orders={orders} fills={fills}");
    println!("reason={reason}");
    println!(
        "alice pos={:?} coll={} rpnl={} eq={} im={} mm={} liq={} ro={}",
        pa.map(|p| (p.qty, p.entry_price)),
        sa.collateral,
        sa.realized_pnl,
        na.equity,
        na.im,
        na.mm,
        na.liquidatable,
        na.reduce_only
    );
    println!(
        "bob   pos={:?} coll={} rpnl={} eq={} im={} mm={} liq={} ro={}",
        pb.map(|p| (p.qty, p.entry_price)),
        sb.collateral,
        sb.realized_pnl,
        nb.equity,
        nb.im,
        nb.mm,
        nb.liquidatable,
        nb.reduce_only
    );
    println!(
        "book bid={:?} ask={:?} orders={} last_seq={} alice_seen={:?} bob_seen={:?}",
        book.best_bid(),
        book.best_ask(),
        book.order_count(),
        eng.state.seq,
        eng.state.seen_client_seq.get(&a),
        eng.state.seen_client_seq.get(&b)
    );
    true
}
