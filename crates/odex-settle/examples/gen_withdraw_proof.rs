//! Generates a vault-AA withdrawal claim (JSON) for a target account.
//!
//! Output JSON shape consumed by obyte-local/test_vault_aa.js:
//! {
//!   "height": <finalized height>,
//!   "leaf_account": "<hex account id>",
//!   "collateral": "<decimal collateral string>",
//!   "aa_root": "<hex root committed to the AA>",
//!   "proof": [ { "hash": "<hex>", "right": true|false }, ... ]
//! }
//!
//! Usage: cargo run -p odex-settle --example gen_withdraw_proof -- <account_hex> [collateral]
use odex_state::{aa_proof_for, aa_root_of};
use std::path::PathBuf;

fn main() {
    // The AA verifies leaf_account == trigger.address (an Obyte address string),
    // so the claim tree is keyed by the withdrawal address itself.
    let addr = std::env::args().nth(1).expect("usage: gen_withdraw_proof <obyte_address> [collateral]");
    let collateral: i128 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000 * 1_000_000);

    // The AA verifies leaf_account == trigger.address (an Obyte address string),
    // so the claim tree is keyed by the withdrawal address itself.
    let pairs = vec![
        (addr.clone(), collateral),
        ("5B7BJSCMFQYUOLDLJHROMOKC5QCLPZLK3UEE4O25".to_string(), 500i128), // decoy peer
    ];
    let (siblings, root) = odex_state::aa_proof_for(&pairs, &addr)
        .unwrap_or_else(|| panic!("no proof for {}", addr));
    assert_eq!(root, odex_state::aa_root_of(&pairs), "proof must reach aa_root");
    let proof_json = serde_json::json!({
        "height": 1,
        "leaf_account": addr,
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
}
