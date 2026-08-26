//! Generates a vault-AA withdrawal claim (JSON) for a target account.
//!
//! Output JSON shape consumed by obyte-local/test_vault_aa.js (Phase 5.2
//! sharded forest wire format):
//! {
//!   "height": <finalized height>,
//!   "leaf_account": "<hex account id>",
//!   "collateral": "<decimal collateral string>",
//!   "perp": "<decimal PERP balance string>",
//!   "withdrawn": "<decimal cumulative-withdrawn string>",
//!   "shard": <shard index 0..15 of leaf_account>,
//!   "aa_root": "<64-hex forest hash over the concatenated shard roots>",
//!   "aa_forest": "<1024-hex concat of the 16 shard roots>",
//!   "proof": [ { "hash": "<hex>", "right": true|false }, ... ]
//! }
//!
//! The proof is a sibling path WITHIN the target's shard tree; the AA folds
//! it and compares against substring(aa_forest, shard*64, 64).
//!
//! NOTE on bucket padding: ocore fatals on EMPTY arrays in trigger data, so a
//! singleton shard bucket (whose proof would be `[]`) must never reach the
//! chain. We keep every emitted claim's shard bucket at >=2 accounts by
//! appending deterministic decoy peers until one lands in the target's shard
//! (chosen over re-bucketing because the AA trusts the claimed `shard` tag;
//! decoys are inert leaves that nobody can prove ownership of).
//!
//! Usage: cargo run -p operp-settle --example gen_withdraw_proof -- <obyte_address> [collateral] [perp] [withdrawn]
use std::path::PathBuf;

fn main() {
    // The AA verifies leaf_account == trigger.address (an Obyte address string),
    // so the claim tree is keyed by the withdrawal address itself.
    let addr = std::env::args()
        .nth(1)
        .expect("usage: gen_withdraw_proof <obyte_address> [collateral] [perp] [withdrawn]");
    let collateral: i128 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000 * 1_000_000);
    let perp: u128 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    // Cumulative sidechain-signed withdrawals (W): the AA enforces
    // "this claim + prior claims <= W" against replay.
    let withdrawn: i128 = std::env::args()
        .nth(4)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // The AA verifies leaf_account == trigger.address (an Obyte address string),
    // so the claim tree is keyed by the withdrawal address itself.
    let shard = operp_state::aa_shard_of(&addr);
    let mut pairs = vec![
        (addr.clone(), collateral, perp, withdrawn),
        (
            "5B7BJSCMFQYUOLDLJHROMOKC5QCLPZLK3UEE4O25".to_string(),
            500i128,
            0u128,
            0i128,
        ), // decoy peer
    ];
    // Keep the target's shard bucket >=2 accounts: a singleton bucket would
    // need an EMPTY proof array and ocore fatally rejects empty arrays in
    // trigger data. Deterministic PAD addresses fill whichever shard lacks a
    // second member; see the module note above.
    let mut pad = 0u32;
    while !pairs
        .iter()
        .any(|(a, ..)| a != &addr && operp_state::aa_shard_of(a) == shard)
    {
        pad += 1;
        pairs.push((format!("{:0<32}", format!("PAD{}", pad)), 500, 0, 0));
    }

    let (shard, siblings, shard_root) =
        operp_state::aa_sharded_proof_for(&pairs, &addr)
            .unwrap_or_else(|| {
                panic!(
                    "no sharded proof for {addr}: register PAD decoy bindings for its shard first \
                     (see the bucket-padding note above)"
                )
            });
    let roots = operp_state::aa_sharded_roots_of(&pairs);
    assert_eq!(roots[shard as usize], shard_root, "proof must reach its shard root");
    let forest = roots.concat();
    assert_eq!(forest.len(), 1024, "forest is 16 x 64 hex");
    let proof_json = serde_json::json!({
        "height": 1,
        "leaf_account": addr,
        "collateral": collateral.to_string(),
        "perp": perp.to_string(),
        "withdrawn": withdrawn.to_string(),
        "shard": shard,
        "aa_root": operp_state::aa_forest_hash(&roots),
        "aa_forest": forest,
        "proof": siblings
            .iter()
            .map(|(hash, right)| serde_json::json!({ "hash": hash, "right": right }))
            .collect::<Vec<_>>(),
    });
    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../obyte-local/withdraw_claim.json");
    std::fs::write(&out, serde_json::to_string_pretty(&proof_json).unwrap()).expect("write");
    println!("wrote {} (shard {})", out.display(), shard);
}
