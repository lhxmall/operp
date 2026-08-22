//! Generates a vault-AA withdrawal claim (JSON) from the current engine state.
//!
//! Output JSON shape consumed by obyte-local/test_vault_aa.js:
//! {
//!   "height": <last_finalized height>,
//!   "leaf_account": "<hex account id>",
//!   "collateral": "<decimal collateral string>",
//!   "aa_root": "<hex root committed to the AA>",
//!   "proof": [ { "hash": "<hex>", "right": true|false }, ... ]
//! }
//!
//! Usage: cargo run --release -p odex-settle --example gen_withdraw_proof
use ed25519_dalek::SigningKey;
use odex_dag::{genesis_id, sign_unit, unit_id, Op};
use odex_exec::Engine;
use odex_state::{aa_proof_for, aa_root_of};
use odex_types::{
    account_id_from_pubkey, OrderType, Side, TimeInForce, BTC_USD, PRICE_SCALE, QTY_SCALE,
    USD_SCALE,
};
use std::path::PathBuf;

fn sk(n: u8) -> [u8; 32] {
    [n; 32]
}
fn acct(secret: &[u8; 32]) -> odex_types::AccountId {
    account_id_from_pubkey(&SigningKey::from_bytes(secret).verifying_key().to_bytes())
}

fn main() {
    // Build a deterministic state: two funded accounts trade once.
    let mut eng = Engine::new();
    eng.state.deposits_allowed = (1u8..=255).map(|b| [b; 32]).collect();
    eng.state.allowed_markets.insert(BTC_USD);
    let g = genesis_id();
    let alice = sk(1);
    let bob = sk(2);

    let d1 = sign_unit(
        vec![g],
        Op::Deposit {
            account: acct(&alice),
            amount: 10_000 * USD_SCALE as i128,
            aa_unit: [1; 32],
        },
        &alice,
    );
    let id1 = unit_id(&d1);
    eng.ingest(d1).unwrap();
    let d2 = sign_unit(
        vec![id1],
        Op::Deposit {
            account: acct(&bob),
            amount: 10_000 * USD_SCALE as i128,
            aa_unit: [2; 32],
        },
        &bob,
    );
    let id2 = unit_id(&d2);
    eng.ingest(d2).unwrap();
    let px = 100_000 * PRICE_SCALE;
    let ask = sign_unit(
        vec![id2],
        Op::Place {
            account: acct(&bob),
            market: BTC_USD,
            side: Side::Ask,
            typ: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: px,
            qty: QTY_SCALE / 1000,
            client_seq: 1,
        },
        &bob,
    );
    eng.ingest(ask).unwrap();

    let who = std::env::args()
        .nth(1)
        .map(|s| if s == "bob" { bob } else { alice })
        .unwrap_or(alice);
    let account = acct(&who);

    let (siblings, root) = aa_proof_for(&eng.state, &account)
        .unwrap_or_else(|| panic!("no proof for {}", hex::encode(account.0)));
    assert_eq!(root, aa_root_of(&eng.state), "proof must reach aa_root");

    let collateral = eng
        .state
        .accounts
        .get(&account)
        .map(|a| a.collateral)
        .unwrap_or(0);
    let proof_json = serde_json::json!({
        "height": 1,
        "leaf_account": hex::encode(account.0),
        "collateral": collateral.to_string(),
        "aa_root": root,
        "proof": siblings
            .iter()
            .map(|(hash, right)| serde_json::json!({ "hash": hash, "right": right }))
            .collect::<Vec<_>>(),
    });
    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../obyte-local/withdraw_claim.json");
    std::fs::write(&out, serde_json::to_string_pretty(&proof_json).unwrap()).expect("write");
    println!("wrote {}", out.display());
    println!("{}", serde_json::to_string_pretty(&proof_json).unwrap());
}
