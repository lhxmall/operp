use ed25519_dalek::{Signer, SigningKey};
use operp_dag::{genesis_id, sign_unit, unit_id, Op, Unit};
use operp_exec::{Engine, ExecEvent};
use operp_types::{
    account_id_from_pubkey, AccountId, MarketId, OrderType, Side, TimeInForce,
    PRICE_SCALE, QTY_SCALE, USD_SCALE,
};
use std::time::Instant;

fn sk(n: u8) -> [u8; 32] { [n; 32] }

fn main() {
    let mut eng = Engine::new();
    eng.state.deposits_allowed = (1u8..=255).flat_map(|b| [([b; 32], false), ([b; 32], true)]).collect();
    eng.state.markets.insert(MarketId(1), operp_types::genesis_params());
    // Operator keys are loaded once at startup in production; mirroring that
    // here keeps the bench measuring engine throughput rather than per-op
    // seed expansion.
    let keys: Vec<SigningKey> = (1..=4).map(|n| SigningKey::from_bytes(&sk(n))).collect();
    let accts: Vec<AccountId> = keys
        .iter()
        .map(|k| account_id_from_pubkey(&k.verifying_key().to_bytes()))
        .collect();
    let mut tip = genesis_id();
    for (i, k) in keys.iter().enumerate() {
        let u = sign_unit(vec![tip], Op::Deposit { account: accts[i], addr: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(), amount: 10_000_000 * USD_SCALE as i128, aa_unit: [i as u8 + 1; 32] }, &sk(i as u8 + 1));
        tip = unit_id(&u);
        eng.ingest(u).unwrap();
    }
    let px = 100_000 * PRICE_SCALE;
    let qty = QTY_SCALE / 100;
    let seqs = std::cell::RefCell::new([1u64; 4]);
    // single-threaded open/close pairs on one market, direct ingest
    let n = 20_000;
    let t0 = Instant::now();
    let mut fills = 0u64;
    for k in 0..n {
        let i = k % 4; let j = (i + 1) % 4;
        for (who, side, tif) in [
            (i, Side::Ask, operp_types::TimeInForce::Gtc),
            (j, Side::Bid, operp_types::TimeInForce::Ioc),
        ] {
            let cs = { let s = seqs.borrow_mut(); s[who] };
            let mut u = Unit {
                parents: vec![tip],
                op: Op::Place {
                    account: accts[who], market: MarketId(1), side,
                    typ: OrderType::Limit, tif, price: px, qty, client_seq: cs,
                },
                pubkey: keys[who].verifying_key().to_bytes(),
                sig: [0u8; 64],
            };
            let id = unit_id(&u);
            u.sig = keys[who].sign(&id.0).to_bytes();
            tip = id;
            seqs.borrow_mut()[who] += 1;
            let evs = eng.ingest(u).unwrap();
            for e in &evs { if let ExecEvent::Applied { fills: f, .. } = e { fills += f.len() as u64; } }
        }
        if eng.log.len() > 8192 { eng.log.clear(); }
    }
    let dt = t0.elapsed().as_secs_f64();
    println!("raw_single: {} ops in {:.2}s => {:.0} ops/s, fills {}", n*2, dt, (n*2) as f64/dt, fills);
}
