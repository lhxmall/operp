use ed25519_dalek::SigningKey;
use operp_dag::{genesis_id, sign_unit, unit_id, Op};
use operp_exec::Engine;
use operp_settle::Batch;
use operp_types::{
    account_id_from_pubkey, AccountId, OrderType, Qty, Side, TimeInForce, UnitId, Usd, BTC_USD,
    PRICE_SCALE, QTY_SCALE, USD_SCALE,
};
use std::path::PathBuf;

fn sk(n: u8) -> [u8; 32] {
    [n; 32]
}
fn acct(secret: &[u8; 32]) -> AccountId {
    account_id_from_pubkey(&SigningKey::from_bytes(secret).verifying_key().to_bytes())
}

fn main() {
    let mut eng = Engine::new();
    eng.state.deposits_allowed = (1u8..=255).map(|b| [b; 32]).collect();
    eng.state.allowed_markets.insert(BTC_USD);
    let prev = eng.state.clone();
    let g = genesis_id();
    let alice = sk(1);
    let bob = sk(2);
    let mut applied = Vec::new();
    let mut tip = g;

    let d1 = sign_unit(
        vec![tip],
        Op::Deposit {
            account: acct(&alice),
            amount: 10_000 * USD_SCALE as i128,
            aa_unit: [1; 32],
        },
        &alice,
    );
    tip = unit_id(&d1);
    applied.push(tip);
    eng.ingest(d1).unwrap();

    let d2 = sign_unit(
        vec![tip],
        Op::Deposit {
            account: acct(&bob),
            amount: 10_000 * USD_SCALE as i128,
            aa_unit: [2; 32],
        },
        &bob,
    );
    tip = unit_id(&d2);
    applied.push(tip);
    eng.ingest(d2).unwrap();

    let px = 100_000 * PRICE_SCALE;
    let qty = QTY_SCALE;
    let ask = sign_unit(
        vec![tip],
        Op::Place {
            account: acct(&bob),
            market: BTC_USD,
            side: Side::Ask,
            typ: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: px,
            qty,
            client_seq: 1,
        },
        &bob,
    );
    tip = unit_id(&ask);
    applied.push(tip);
    eng.ingest(ask).unwrap();

    let bid = sign_unit(
        vec![tip],
        Op::Place {
            account: acct(&alice),
            market: BTC_USD,
            side: Side::Bid,
            typ: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: px,
            qty,
            client_seq: 1,
        },
        &alice,
    );
    tip = unit_id(&bid);
    applied.push(tip);
    eng.ingest(bid).unwrap();
    let _ = tip;

    let batch = Batch::from_applied(&prev, &mut eng, &applied).expect("batch");
    let payload = batch.temp_data_payload();
    let out: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../obyte-local/batch.json")
        .canonicalize()
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../obyte-local/batch.json")
        });
    if let Some(dir) = out.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let text = serde_json::to_string_pretty(&payload.data).unwrap();
    std::fs::write(&out, &text).expect("write batch.json");
    println!("wrote {}", out.display());
    println!("height {}", batch.checkpoint.height);
    println!("fill_count {}", batch.checkpoint.fill_count);
    println!("state_root {}", hex::encode(batch.checkpoint.state_root));
    println!("prev_state_hash {}", hex::encode(batch.checkpoint.prev_state_hash));
    println!("units {}", batch.checkpoint.unit_ids.len());
    assert_eq!(batch.checkpoint.fill_count, 1);
    println!("OK: real engine batch exported");
}
