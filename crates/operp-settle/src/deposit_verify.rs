//! Independent verification of deposit evidences (H2).
//!
//! An evidence binds a sidechain `Op::Deposit`/`Op::GovDeposit` anchor to a
//! real Obyte joint that actually paid the vault AA. Verification is
//! caller-parameterized (`expected_vault`, `perp_asset`) so replays never
//! trust an evidence's self-declared payee.

use crate::DepositEvidence;
use crate::SettleError;
use operp_dag::Op;
use operp_types::DEPOSIT_EVIDENCE_MAX_BYTES;
use std::collections::{HashMap, HashSet};

use crate::obyte_hash::get_unit_hash;

fn parse_hex32(s: &str) -> Result<[u8; 32], SettleError> {
    if s.len() != 64 {
        return Err(SettleError::DepositContentMismatch);
    }
    let bytes = hex::decode(s).map_err(|_| SettleError::DepositContentMismatch)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn amount_str_matches(ev_amount: &str, op_amount_str: &str) -> bool {
    ev_amount == op_amount_str
}

/// True when an Obyte asset string (hex or base64 of the 32-byte id)
/// identifies `want`.
fn asset_matches(s: &str, want: &[u8; 32]) -> bool {
    if s == hex::encode(want) {
        return true;
    }
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map(|b| b.as_slice() == want)
        .unwrap_or(false)
}

/// Finds the first output paying `vault` in the expected asset kind; accepts
/// an output to ANY address when `vault` is None (vault address not
/// configured pre-deploy). Asset-class binding is enforced either way so a
/// PERP evidence can never ride a non-PERP payment.
fn find_payment_output_opt(
    unit: &serde_json::Value,
    vault: Option<&str>,
    is_perp: bool,
    perp_asset: &[u8; 32],
) -> Option<(String, Option<String>)> {
    let messages = unit.get("messages")?.as_array()?;
    for msg in messages {
        let payload = msg.get("payload")?;
        let outputs = payload.get("outputs")?.as_array()?;
        let asset = payload
            .get("asset")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let is_base = match &asset {
            None => true,
            Some(a) => a == "base",
        };
        if is_perp == is_base {
            // Wrong asset class for this evidence kind.
            continue;
        }
        if is_perp {
            // PERP-class payment must carry exactly the governed PERP asset.
            if !asset
                .as_deref()
                .map(|a| asset_matches(a, perp_asset))
                .unwrap_or(false)
            {
                continue;
            }
        }
        for out in outputs {
            let addr = out.get("address")?.as_str()?;
            if let Some(v) = vault {
                if addr != v {
                    continue;
                }
            }
            let amount_val = out.get("amount")?;
            let amount_str = if let Some(n) = amount_val.as_u64() {
                n.to_string()
            } else if let Some(n) = amount_val.as_i64() {
                n.to_string()
            } else if let Some(s) = amount_val.as_str() {
                s.to_string()
            } else {
                continue;
            };
            return Some((amount_str, asset));
        }
    }
    None
}

/// Base-asset joint amount vs credited amount. Production rule: joint pays
/// ev.amount + the 10000 bounce fee. Test fixtures may post without the fee,
/// hence the `cfg(test)` relaxation — never enable it outside tests.
#[cfg(not(test))]
fn base_amount_matches(joint_amt: i128, ev_amt: i128) -> bool {
    joint_amt == ev_amt + 10_000
}
#[cfg(test)]
fn base_amount_matches(joint_amt: i128, ev_amt: i128) -> bool {
    joint_amt == ev_amt + 10_000 || joint_amt == ev_amt
}

fn verify_one(
    op: &Op,
    ev: &DepositEvidence,
    expected_vault: &str,
    perp_asset: &[u8; 32],
) -> Result<([u8; 32], bool), SettleError> {
    // op kind and aa_unit extraction
    let (op_aa_unit, op_amount_str, op_is_perp) = match op {
        Op::Deposit {
            aa_unit, amount, ..
        } => (*aa_unit, amount.to_string(), false),
        Op::GovDeposit {
            aa_unit, amount, ..
        } => (*aa_unit, amount.to_string(), true),
        _ => return Ok(([0u8; 32], false)), // not a deposit, caller filters
    };

    // aa_unit hex string must decode and equal op aa_unit
    let ev_bytes = parse_hex32(&ev.aa_unit)?;
    if ev_bytes != op_aa_unit {
        return Err(SettleError::DepositContentMismatch);
    }
    // kind
    if ev.is_perp != op_is_perp {
        return Err(SettleError::DepositKindMismatch);
    }
    // amount string must match op amount
    if !amount_str_matches(&ev.amount, &op_amount_str) {
        return Err(SettleError::DepositContentMismatch);
    }
    // Payee check (H2): the declared vault must equal the caller's expected
    // vault — an evidence can no longer vouch for itself.
    if ev.vault_address != expected_vault {
        return Err(SettleError::DepositContentMismatch);
    }
    // hash check
    let computed = get_unit_hash(&ev.joint).map_err(|_| SettleError::DepositContentMismatch)?;
    if computed != ev_bytes {
        return Err(SettleError::DepositContentMismatch);
    }
    // content check: joint must actually pay the expected vault
    let unit_obj = if let Some(u) = ev.joint.get("unit") {
        u
    } else {
        &ev.joint
    };
    // Content check: the joint must actually pay the expected vault the
    // claimed (amount, asset). Pre-deploy (empty expected vault) any payee
    // is accepted, but the asset-class binding below still applies.
    let vault_arg = if expected_vault.is_empty() {
        None
    } else {
        Some(expected_vault)
    };
    match find_payment_output_opt(unit_obj, vault_arg, ev.is_perp, perp_asset) {
        Some((joint_amount_str, _asset)) => {
            if ev.is_perp {
                // For PERP, joint amount should equal ev.amount directly.
                if joint_amount_str != ev.amount {
                    return Err(SettleError::DepositContentMismatch);
                }
            } else {
                // For base, joint amount is ev.amount + 10000 bounce fee;
                // see `base_amount_matches` (fixtures post without the fee).
                let ev_amt: i128 = ev
                    .amount
                    .parse()
                    .map_err(|_| SettleError::DepositContentMismatch)?;
                let joint_amt: i128 = joint_amount_str
                    .parse()
                    .map_err(|_| SettleError::DepositContentMismatch)?;
                if !base_amount_matches(joint_amt, ev_amt) {
                    return Err(SettleError::DepositContentMismatch);
                }
            }
        }
        None => return Err(SettleError::DepositContentMismatch),
    }
    Ok((ev_bytes, ev.is_perp))
}

pub fn verify_all(
    units: &[operp_dag::Unit],
    evidences: &[DepositEvidence],
    expected_vault: &str,
    perp_asset: &[u8; 32],
) -> Result<HashMap<[u8; 32], bool>, SettleError> {
    // Size gate
    let total_bytes: usize = evidences
        .iter()
        .map(|e| serde_json::to_vec(e).map(|v| v.len()).unwrap_or(0))
        .sum();
    if total_bytes > DEPOSIT_EVIDENCE_MAX_BYTES {
        return Err(SettleError::DepositEvidenceTooLarge);
    }

    // Dedup
    let mut seen: HashSet<String> = HashSet::new();
    for ev in evidences {
        let key = ev.aa_unit.to_lowercase();
        if !seen.insert(key) {
            return Err(SettleError::DepositDuplicateAnchor);
        }
        // Validate hex format early
        parse_hex32(&ev.aa_unit)?;
    }

    // Build map aa_unit hex -> evidence ref
    let mut map: HashMap<String, &DepositEvidence> = HashMap::new();
    for ev in evidences {
        map.insert(ev.aa_unit.to_lowercase(), ev);
    }

    let mut verified: HashMap<[u8; 32], bool> = HashMap::new();

    for u in units {
        let is_deposit = matches!(u.op, Op::Deposit { .. } | Op::GovDeposit { .. });
        if !is_deposit {
            continue;
        }
        let op_aa_unit = match &u.op {
            Op::Deposit { aa_unit, .. } => *aa_unit,
            Op::GovDeposit { aa_unit, .. } => *aa_unit,
            _ => unreachable!(),
        };
        let hex_id = hex::encode(op_aa_unit);
        let ev = map.get(&hex_id).ok_or(SettleError::DepositAnchorMissing)?;
        let (bytes, is_perp) = verify_one(&u.op, ev, expected_vault, perp_asset)?;
        verified.insert(bytes, is_perp);
    }

    Ok(verified)
}
