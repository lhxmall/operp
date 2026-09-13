//! Watcher fraud-proof builder: locates the first divergence between a
//! posted batch and a local replay, then emits the `proof.json` payload the
//! dispute AAs verify one-shot on-chain.
//!
//! The builder never talks to the network. The caller supplies the posted
//! [`Batch`] (already rebuilt from temp_data DA), a replay [`Engine`] at the
//! batch's prev state, and the inbox pairs `(unit_id_hex, force_ts)` with the
//! rollup's `submitted_at` for staleness comparison.

use operp_exec::Engine;
use operp_settle::{fills_element, ops_element, Batch};
use operp_state::obyte_merkle;

/// A fraud proof ready for `post_challenge.js --pred PRED --proof PATH`.
#[derive(Clone, Debug)]
pub struct BuiltProof {
    /// Dispute predicate name (`deposit`, `withdraw`, `omit`, `fill_math`,
    /// `ghost`, `skip`, `clamp`).
    pub pred: String,
    /// True → post to the fill dispute AA (`--fill`); false → main dispute AA.
    pub fill_aa: bool,
    /// True → post to the clamp dispute AA (`--clamp`); takes precedence
    /// over `fill_aa` when both are set (never both in practice).
    pub clamp_aa: bool,
    /// Exact `trigger.data` supplement (merged with `height`/`pred` by the
    /// poster): `k`, `op`, proofs, leaves, roots the AA stale-checks.
    pub data: serde_json::Value,
}

fn proof_json(elements: &[String], index: usize) -> serde_json::Value {
    let p = obyte_merkle::proof(elements, index);
    serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
}

fn index_of(elements: &[String], needle: &str) -> Option<usize> {
    elements.iter().position(|e| e == needle)
}
/// Locate the first divergence and build the on-chain proof.
///
/// Returns `None` when the batch replays cleanly (honest) or when the
/// divergence is not predicate-expressible (watcher stays print-only).
///
/// `vault_receipt` answers the vault AA receipt for a deposit anchor:
/// `Ok(Some(amount))` = receipt present, `Ok(None)` = absent (fictitious
/// anchor), `Err` = transport failure (skip receipt checks, never
/// mis-challenge). `None` callback = receipt checks disabled (unit tests).
pub fn build_proof(
    batch: &Batch,
    replay: &mut Engine,
    inbox: &[(String, u64)],
    submit_ts: u64,
    vault_receipt: Option<&dyn Fn(&str, bool) -> Result<Option<i128>, String>>,
) -> Option<BuiltProof> {
    let n = batch.units.len();
    if n == 0 || batch.checkpoint.unit_ids.len() != n || batch.ops.len() != n {
        return None;
    }
    let unit_hexes: Vec<String> = batch
        .checkpoint
        .unit_ids
        .iter()
        .map(|id| hex::encode(id.0))
        .collect();
    // 1. P-omit: forced id older than the submit but missing from the batch.
    for (id, ts) in inbox {
        if *ts < submit_ts && !unit_hexes.iter().any(|u| u == id) {
            return omit_proof(batch, &unit_hexes, id);
        }
    }
    // 2+. Walk units: ingest one at a time, compare wit root + ops string.
    for k in 0..n {
        let pre_leaves = operp_state::wit_leaves(&replay.state);
        let pre_wit = obyte_merkle::root(&pre_leaves);
        let expected_op = ops_element(&unit_hexes[k], &batch.units[k].op);
        let op_ok = batch.ops.get(k).map(|o| o == &expected_op).unwrap_or(false);
        let wit_ok = batch.trace.get(k).map(|t| t == &pre_wit).unwrap_or(false);
        if !op_ok || !wit_ok {
            // Poster committed something unreplayable at k; the pre-state
            // leaves are still honest replay output — fall through to the
            // per-op proofs against the POSTED commitments below.
        }
        if replay.ingest(batch.units[k].clone()).is_err() {
            return None;
        }
        let post_leaves = operp_state::wit_leaves(&replay.state);
        let op = batch.ops.get(k)?.clone();
        if op.starts_with("d:") || op.starts_with("D:") {
            if let Some(p) = deposit_proof(batch, k, &op, &pre_leaves, &post_leaves, true, vault_receipt) {
                return Some(p);
            }
        } else if op.starts_with("w:") || op.starts_with("W:") {
            if let Some(p) = deposit_proof(batch, k, &op, &pre_leaves, &post_leaves, false, vault_receipt) {
                return Some(p);
            }
        } else {
            // Fill-bearing unit: check fills of this unit against post state.
            if let Some(p) = fill_proof(batch, k, &unit_hexes[k], &pre_leaves, &post_leaves) {
                return Some(p);
            }
        }
    }
    None
}

fn trace_roots(batch: &Batch) -> serde_json::Value {
    serde_json::json!({
        "trace_root": batch.checkpoint.trace_root,
        "ops_root": batch.checkpoint.ops_root,
        "units_root": batch.checkpoint.units_root,
        "units_set_root": batch.checkpoint.units_set_root,
        "fills_root": batch.checkpoint.fills_root,
    })
}

fn pre_wit_fields(batch: &Batch, k: usize, pre_leaves: &[String]) -> serde_json::Value {
    let pre_wit = obyte_merkle::root(pre_leaves);
    if k == 0 {
        serde_json::json!({"pre_wit": pre_wit})
    } else {
        let pre_proof = proof_json(&batch.trace, k - 1);
        serde_json::json!({"pre_wit": pre_wit, "pre_proof": pre_proof})
    }
}
fn deposit_proof(
    batch: &Batch,
    k: usize,
    op: &str,
    pre_leaves: &[String],
    post_leaves: &[String],
    is_deposit: bool,
    vault_receipt: Option<&dyn Fn(&str, bool) -> Result<Option<i128>, String>>,
) -> Option<BuiltProof> {
    // Parse op: d:{acct}:{amount}:{anchor44} (4 parts) or
    // w:{acct}:{amount}:{nonce}. Gov variants D:/W: mirror the shapes.
    let parts: Vec<&str> = op.split(':').collect();
    if parts.len() < 3 {
        return None;
    }
    // Receipt check first (doc 12 §2.3): a deposit anchor with no (or a
    // mismatched) vault receipt is dep_evidence fraud regardless of the
    // bookkeeping legs. Transport failure or disabled callback skips the
    // check — never mis-challenge on a flaky read.
    if is_deposit {
        if parts.len() >= 4 && parts[3].len() == 44 {
            let is_perp = parts[0] == "D";
            let amount: i128 = parts[2].parse().ok()?;
            if let Some(rec) = vault_receipt {
                match rec(parts[3], is_perp) {
                    Ok(got) => {
                        if got != Some(amount) {
                            return dep_evidence_proof(batch, k, op);
                        }
                    }
                    Err(_) => {}
                }
            }
        }
    }
    let acct_hex = parts[1].to_string();
    let amount: i128 = parts[2].parse().ok()?;
    // pre_absent non-membership geometry over the sorted pre leaves.
    let pre_hit = pre_leaves
        .iter()
        .find(|l| l.starts_with(&format!("acct:{}:", acct_hex)))
        .cloned();
    let (pre_col, pre_absent_fields): (i128, serde_json::Value) = match pre_hit.clone() {
        Some(pre_leaf) => {
            let c: i128 = pre_leaf.split(':').nth(2)?.parse().ok()?;
            (c, serde_json::json!({}))
        }
        None => {
            let mut sorted = pre_leaves.to_vec();
            sorted.sort();
            let ghost_key = format!("acct:{}:", acct_hex);
            let pos = sorted
                .iter()
                .position(|s| s.as_str() > ghost_key.as_str())
                .unwrap_or(sorted.len());
            let mut f = serde_json::json!({"pre_absent": true});
            let obj = f.as_object_mut()?;
            if pos > 0 && pos < sorted.len() {
                obj.insert("left".into(), sorted[pos - 1].clone().into());
                obj.insert("left_proof".into(), {
                    let p = obyte_merkle::proof(&sorted, pos - 1);
                    serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                });
                obj.insert("right".into(), sorted[pos].clone().into());
                obj.insert("right_proof".into(), {
                    let p = obyte_merkle::proof(&sorted, pos);
                    serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                });
            } else if !sorted.is_empty() {
                let i = if pos == 0 { 0 } else { sorted.len() - 1 };
                obj.insert("left".into(), sorted[i].clone().into());
                obj.insert("left_proof".into(), {
                    let p = obyte_merkle::proof(&sorted, i);
                    serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                });
            } else {
                return None;
            }
            (0, f)
        }
    };
    let expected = if is_deposit {
        pre_col + amount
    } else {
        pre_col - amount
    };
    let posted_post: Vec<String> = batch.leaf_trace.get(k)?.clone();
    let liar_leaf = posted_post
        .iter()
        .find(|l| l.starts_with(&format!("acct:{}:", acct_hex)))?
        .clone();
    let liar_col: i128 = liar_leaf.split(':').nth(2)?.parse().ok()?;
    if liar_col == expected {
        return None; // honest leg — keep scanning
    }
    let mut roots = trace_roots(batch);
    let pre_fields = pre_wit_fields(batch, k, pre_leaves);
    let post_wit = batch.trace.get(k)?.clone();
    let ops_proof = proof_json(&batch.ops, k);
    let post_proof = proof_json(&batch.trace, k);
    let post_idx = index_of(&posted_post, &liar_leaf)?;
    let post_leaf_proof = {
        let p = obyte_merkle::proof(&posted_post, post_idx);
        serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
    };
    roots
        .as_object_mut()?
        .extend(pre_fields.as_object()?.clone());
    roots
        .as_object_mut()?
        .extend(pre_absent_fields.as_object()?.clone());
    let mut data = roots;
    let obj = data.as_object_mut()?;
    obj.insert("k".into(), k.into());
    obj.insert("op".into(), op.into());
    obj.insert("ops_proof".into(), ops_proof);
    obj.insert("post_wit".into(), post_wit.into());
    obj.insert("post_proof".into(), post_proof);
    obj.insert("post_leaf".into(), liar_leaf.into());
    obj.insert("post_leaf_proof".into(), post_leaf_proof);
    if let Some(pre_leaf) = pre_hit {
        let pre_idx = index_of(pre_leaves, &pre_leaf)?;
        obj.insert("pre_leaf".into(), pre_leaf.into());
        obj.insert("pre_leaf_proof".into(), {
            let p = obyte_merkle::proof(pre_leaves, pre_idx);
            serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
        });
    }
    Some(BuiltProof {
        pred: if is_deposit {
            "deposit".into()
        } else {
            "withdraw".into()
        },
        fill_aa: false,
        clamp_aa: false,
        data,
    })
}
/// dep_evidence proof (doc 12 §2.3): the deposit op's vault-unit anchor has
/// no (or a mismatched) receipt in the vault AA. Only the op + ops_proof +
/// roots travel — the dispute AA reads the vault receipt cross-AA on-chain.
fn dep_evidence_proof(batch: &Batch, k: usize, op: &str) -> Option<BuiltProof> {
    let mut data = trace_roots(batch);
    let obj = data.as_object_mut()?;
    obj.insert("k".into(), k.into());
    obj.insert("op".into(), op.into());
    obj.insert("ops_proof".into(), proof_json(&batch.ops, k));
    Some(BuiltProof {
        pred: "dep_evidence".into(),
        fill_aa: false,
        clamp_aa: false,
        data,
    })
}

fn omit_proof(batch: &Batch, unit_hexes: &[String], id: &str) -> Option<BuiltProof> {
    let mut sorted = unit_hexes.to_vec();
    sorted.sort();
    let n = sorted.len();
    // Adjacent pair straddling id, or outside min/max.
    let mut data = trace_roots(batch);
    let obj = data.as_object_mut()?;
    obj.insert("unit_id".into(), id.into());
    // Find insertion point.
    let pos = sorted.iter().position(|s| s.as_str() > id).unwrap_or(n);
    if pos > 0 && pos < n {
        let li = pos - 1;
        let ri = pos;
        obj.insert("left".into(), sorted[li].clone().into());
        obj.insert("left_proof".into(), proof_json(&sorted, li));
        obj.insert("right".into(), sorted[ri].clone().into());
        obj.insert("right_proof".into(), proof_json(&sorted, ri));
    } else if pos == 0 {
        obj.insert("left".into(), sorted[0].clone().into());
        obj.insert("left_proof".into(), proof_json(&sorted, 0));
    } else {
        obj.insert("left".into(), sorted[n - 1].clone().into());
        obj.insert("left_proof".into(), proof_json(&sorted, n - 1));
    }
    Some(BuiltProof {
        pred: "omit".into(),
        fill_aa: false,
        clamp_aa: false,
        data,
    })
}

fn fill_proof(
    batch: &Batch,
    k: usize,
    unit_hex: &str,
    pre_leaves: &[String],
    post_leaves: &[String],
) -> Option<BuiltProof> {
    // Reconstruct this unit's fills from the batch fills list (prefix match).
    let prefix = format!("f:{}:", unit_hex);
    let unit_fills: Vec<&String> = batch
        .fills
        .iter()
        .filter(|f| f.starts_with(&prefix))
        .collect();
    if unit_fills.is_empty() {
        return None;
    }
    // Ghost: maker ord leaf absent from pre leaves.
    for f in &unit_fills {
        let parts: Vec<&str> = f.split(':').collect();
        if parts.len() != 12 {
            continue;
        }
        let maker_hex = parts[4].to_string();
        let maker_order_hex = parts[6].to_string();
        let market = parts[7].to_string();
        let fill_price = parts[8].to_string();
        let fill_qty = parts[9].to_string();
        let fill_seq = parts[10].to_string();
        let opp_side = if parts[11] == "0" { "1" } else { "0" }.to_string();
        // Prefix-range ghost: fraud iff NO pre leaf carries this order id.
        // Any same-id leaf sits inside [$lo,$hi) and breaks every AA
        // straddle, so only emit then.
        let ord_prefix = format!("ord:{}:", maker_order_hex);
        let ghost_hit = !pre_leaves.iter().any(|l| l.starts_with(&ord_prefix));
        if ghost_hit {
            let idx = index_of(&batch.fills, f)?;
            let mut data = serde_json::json!({
                "trace_root": batch.checkpoint.trace_root,
                "fills_root": batch.checkpoint.fills_root,
                "ops_root": batch.checkpoint.ops_root,
                "k": k,
                "fill": f,
                "fill_proof": proof_json(&batch.fills, idx),
            });
            // Non-membership neighbors for the [$lo,$hi) range: reuse omit
            // geometry over the pre wit leaves with wit_count bound.
            let mut sorted = pre_leaves.to_vec();
            sorted.sort();
            let pos = sorted
                .iter()
                .position(|s| s.as_str() > ord_prefix.as_str())
                .unwrap_or(sorted.len());
            let obj = data.as_object_mut()?;
            obj.insert(
                "maker_ord".into(),
                format!(
                    "ord:{}:{}:{}:{}:{}:{}:{}",
                    maker_order_hex, market, opp_side, fill_price, fill_seq, fill_qty, maker_hex
                )
                .into(),
            );
            if pos > 0 && pos < sorted.len() {
                obj.insert("left".into(), sorted[pos - 1].clone().into());
                obj.insert("left_proof".into(), {
                    let p = obyte_merkle::proof(&sorted, pos - 1);
                    serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                });
                obj.insert("right".into(), sorted[pos].clone().into());
                obj.insert("right_proof".into(), {
                    let p = obyte_merkle::proof(&sorted, pos);
                    serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                });
            } else if !sorted.is_empty() {
                let i = if pos == 0 { 0 } else { sorted.len() - 1 };
                obj.insert("left".into(), sorted[i].clone().into());
                obj.insert("left_proof".into(), {
                    let p = obyte_merkle::proof(&sorted, i);
                    serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                });
            }
            return Some(BuiltProof {
                pred: "ghost".into(),
                fill_aa: true,
                clamp_aa: false,
                data,
            });
        }
    }
    // Skip: another live order strictly better than the filled maker.
    for f in &unit_fills {
        let parts: Vec<&str> = f.split(':').collect();
        if parts.len() != 12 {
            continue;
        }
        let maker_order_hex = parts[6].to_string();
        let market = parts[7].to_string();
        let price: i64 = parts[8].parse().ok()?;
        let side = parts[11];
        let maker_ord = pre_leaves
            .iter()
            .find(|l| {
                l.starts_with("ord:") && {
                    let o: Vec<&str> = l.split(':').collect();
                    o.len() == 8 && o[1] == maker_order_hex && o[2] == market
                }
            })?
            .clone();
        let mo: Vec<&str> = maker_ord.split(':').collect();
        let (mo_side, mo_price, mo_seq): (u8, i64, u64) = (
            mo[3].parse().ok()?,
            mo[4].parse().ok()?,
            mo[5].parse().ok()?,
        );
        for cand in pre_leaves.iter().filter(|l| l.starts_with("ord:")) {
            let o: Vec<&str> = cand.split(':').collect();
            if o.len() != 8 || o[2] != market {
                continue;
            }
            if o[1] == maker_order_hex {
                continue;
            }
            let (c_side, c_price, c_seq): (u8, i64, u64) =
                match (o[3].parse(), o[4].parse(), o[5].parse()) {
                    (Ok(a), Ok(b), Ok(c)) => (a, b, c),
                    _ => continue,
                };
            let c_rem: u64 = o[6].parse().unwrap_or(0);
            if c_rem == 0 {
                continue;
            }
            let better = if side == "0" {
                c_side == 1
                    && (c_price < mo_price || (c_price == mo_price && c_seq < mo_seq))
                    && c_price <= price
            } else if side == "1" {
                c_side == 0
                    && (c_price > mo_price || (c_price == mo_price && c_seq < mo_seq))
                    && c_price >= price
            } else {
                false
            };
            if better {
                let idx = index_of(&batch.fills, f)?;
                let mut data = serde_json::json!({
                    "trace_root": batch.checkpoint.trace_root,
                    "fills_root": batch.checkpoint.fills_root,
                    "ops_root": batch.checkpoint.ops_root,
                    "k": k,
                    "fill": f,
                    "fill_proof": proof_json(&batch.fills, idx),
                    "maker_ord": maker_ord,
                    "better_ord": cand,
                });
                let pre_fields = pre_wit_fields(batch, k, pre_leaves);
                data.as_object_mut()?
                    .extend(pre_fields.as_object()?.clone());
                // Membership proofs for both orders in pre_wit.
                let mi = index_of(pre_leaves, &maker_ord)?;
                let bi = index_of(pre_leaves, cand)?;
                let obj = data.as_object_mut()?;
                obj.insert("maker_proof".into(), {
                    let p = obyte_merkle::proof(pre_leaves, mi);
                    serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                });
                obj.insert("better_proof".into(), {
                    let p = obyte_merkle::proof(pre_leaves, bi);
                    serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                });
                return Some(BuiltProof {
                    pred: "skip".into(),
                    fill_aa: true,
                    clamp_aa: false,
                    data,
                });
            }
        }
    }
    // fill_math (taker + maker, full apply_fill): expected post col/qty/entry
    // per side from the pre leaves; the first posted-leg mismatch becomes
    // the proof. No insurance clamp is modeled: when the honest replay legs
    // themselves diverge from the no-clamp expectation, the side is skipped
    // (unprovable, watcher stays silent).
    for f in &unit_fills {
        let parts: Vec<&str> = f.split(':').collect();
        if parts.len() != 12 {
            continue;
        }
        let taker_hex = parts[3].to_string();
        let maker_hex = parts[4].to_string();
        let market = parts[7].to_string();
        let price: i64 = match parts[8].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let qty: u64 = match parts[9].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let taker_side = parts[11];
        if taker_side != "0" && taker_side != "1" {
            continue;
        }
        let maker_side = if taker_side == "0" { "1" } else { "0" };
        let pre_meta = match pre_leaves
            .iter()
            .find(|l| l.starts_with(&format!("meta:{}:", market)))
        {
            Some(m) => m.clone(),
            None => continue,
        };
        let mparts: Vec<&str> = pre_meta.split(':').collect();
        if mparts.len() != 9 {
            continue;
        }
        let fee_bps: u128 = match mparts[5].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let notional =
            qty as u128 * (price as i128).abs() as u128 / 100_000_000 * 1_000_000 / 100_000_000;
        let fee = (notional * fee_bps / 10_000) as i128;
        // Posted post legs: the commitments the AA checks proofs against.
        let posted_post: Vec<String> = batch
            .leaf_trace
            .get(k)
            .cloned()
            .unwrap_or_else(|| post_leaves.to_vec());
        let sides = [
            ("taker", taker_hex.as_str(), taker_side),
            ("maker", maker_hex.as_str(), maker_side),
        ];
        for (who, acct_hex, side_acct) in sides {
            let delta: i64 = if side_acct == "0" {
                qty as i64
            } else {
                -(qty as i64)
            };
            let pre_acct = match pre_leaves
                .iter()
                .find(|l| l.starts_with(&format!("acct:{}:", acct_hex)))
            {
                Some(a) => a.clone(),
                None => continue,
            };
            let pre_parts: Vec<&str> = pre_acct.split(':').collect();
            if pre_parts.len() != 5 {
                continue;
            }
            let old_col: i128 = match pre_parts[2].parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let pre_pos_opt = pre_leaves
                .iter()
                .find(|l| {
                    l.starts_with("pos:") && {
                        let o: Vec<&str> = l.split(':').collect();
                        o.len() == 5 && o[1] == acct_hex && o[2] == market
                    }
                })
                .cloned();
            let pos_absent = pre_pos_opt.is_none();
            let (old_qty, old_entry): (i64, i64) = match &pre_pos_opt {
                None => (0, 0),
                Some(p) => {
                    let o: Vec<&str> = p.split(':').collect();
                    match (o[3].parse(), o[4].parse()) {
                        (Ok(q), Ok(e)) => (q, e),
                        _ => continue,
                    }
                }
            };
            // Expected legs: Account::apply_fill + taker fee, no clamp.
            let abs_old = old_qty.abs() as i128;
            let abs_delta = delta.abs() as i128;
            let same = old_qty == 0 || (old_qty > 0 && delta > 0) || (old_qty < 0 && delta < 0);
            let (exp_qty, exp_entry, exp_col, exp_pos_absent) = if same {
                let eq = old_qty + delta;
                let ee = if old_qty == 0 {
                    price
                } else {
                    ((abs_old * i128::from(old_entry) + i128::from(qty) * i128::from(price))
                        / (abs_old + i128::from(qty))) as i64
                };
                let ec = if who == "taker" {
                    old_col - fee
                } else {
                    old_col
                };
                (eq, ee, ec, false)
            } else {
                let close = abs_old.min(abs_delta);
                let signed: i128 = if old_qty > 0 {
                    price as i128 - old_entry as i128
                } else {
                    old_entry as i128 - price as i128
                };
                let pnl = signed * close * 1_000_000 / 100_000_000 / 100_000_000;
                let ec = if who == "taker" {
                    old_col + pnl - fee
                } else {
                    old_col + pnl
                };
                let leftover = abs_old - close;
                let open = abs_delta - close;
                if leftover == 0 && open == 0 {
                    (0, 0, ec, true)
                } else if leftover == 0 {
                    (
                        if delta > 0 {
                            open as i64
                        } else {
                            -(open as i64)
                        },
                        price,
                        ec,
                        false,
                    )
                } else {
                    (
                        if old_qty > 0 {
                            leftover as i64
                        } else {
                            -(leftover as i64)
                        },
                        old_entry,
                        ec,
                        false,
                    )
                }
            };
            // Clamp guard: the honest replay legs must match the no-clamp
            // expectation, else this side is unprovable (skip it).
            let replay_ok = match post_leaves
                .iter()
                .find(|l| l.starts_with(&format!("acct:{}:", acct_hex)))
            {
                Some(a) => {
                    let c: i128 = match a.split(':').nth(2).unwrap_or("").parse() {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if c != exp_col {
                        false
                    } else if exp_pos_absent {
                        !post_leaves.iter().any(|l| {
                            l.starts_with("pos:") && {
                                let o: Vec<&str> = l.split(':').collect();
                                o.len() == 5 && o[1] == acct_hex && o[2] == market
                            }
                        })
                    } else {
                        match post_leaves.iter().find(|l| {
                            l.starts_with("pos:") && {
                                let o: Vec<&str> = l.split(':').collect();
                                o.len() == 5 && o[1] == acct_hex && o[2] == market
                            }
                        }) {
                            Some(p) => {
                                let o: Vec<&str> = p.split(':').collect();
                                o[3].parse::<i64>().ok() == Some(exp_qty)
                                    && o[4].parse::<i64>().ok() == Some(exp_entry)
                            }
                            None => false,
                        }
                    }
                }
                None => continue,
            };
            if !replay_ok {
                // Honest replay diverges from the no-clamp expectation: this
                // side clamped honestly (or fraudulently). Route to the clamp
                // predicate — the clamp AA replays equity and convicts on
                // skipped/wrong-amount/over-charged legs, and bounces honest
                // clamped heights ('no fraud').
                if let Some(p) = clamp_proof(batch, k, f, pre_leaves, post_leaves, &posted_post) {
                    return Some(p);
                }
                continue;
            }
            // Posted legs: mismatch with the expectation is the fraud.
            let posted_acct = match posted_post
                .iter()
                .find(|l| l.starts_with(&format!("acct:{}:", acct_hex)))
            {
                Some(a) => a.clone(),
                None => continue,
            };
            let posted_col: i128 = match posted_acct.split(':').nth(2).unwrap_or("").parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let posted_pos_opt = posted_post
                .iter()
                .find(|l| {
                    l.starts_with("pos:") && {
                        let o: Vec<&str> = l.split(':').collect();
                        o.len() == 5 && o[1] == acct_hex && o[2] == market
                    }
                })
                .cloned();
            let posted_ok = if posted_col != exp_col {
                false
            } else if exp_pos_absent {
                posted_pos_opt.is_none()
            } else {
                match &posted_pos_opt {
                    Some(p) => {
                        let o: Vec<&str> = p.split(':').collect();
                        o[3].parse::<i64>().ok() == Some(exp_qty)
                            && o[4].parse::<i64>().ok() == Some(exp_entry)
                    }
                    None => false,
                }
            };
            if posted_ok {
                continue; // honest side — check the other party
            }
            if !exp_pos_absent && posted_pos_opt.is_none() {
                continue; // omitted pos leaf has no membership proof
            }
            let idx = index_of(&batch.fills, f)?;
            let mut data = serde_json::json!({
                "trace_root": batch.checkpoint.trace_root,
                "fills_root": batch.checkpoint.fills_root,
                "ops_root": batch.checkpoint.ops_root,
                "k": k,
                "fill": f,
                "fill_proof": proof_json(&batch.fills, idx),
                "who": who,
                "pre_acct": pre_acct,
                "post_acct": posted_acct,
                "pre_meta": pre_meta,
                "pos_absent": pos_absent,
                "post_pos_absent": exp_pos_absent,
            });
            let pre_fields = pre_wit_fields(batch, k, pre_leaves);
            let post_wit = batch.trace.get(k)?.clone();
            let post_proof = proof_json(&batch.trace, k);
            let pre_idx = index_of(pre_leaves, &pre_acct)?;
            let post_acct_idx = index_of(&posted_post, data["post_acct"].as_str()?)?;
            let meta_idx = index_of(pre_leaves, &pre_meta)?;
            data.as_object_mut()?
                .extend(pre_fields.as_object()?.clone());
            let obj = data.as_object_mut()?;
            obj.insert("post_wit".into(), post_wit.into());
            obj.insert("post_proof".into(), post_proof);
            obj.insert("pre_acct_proof".into(), {
                let p = obyte_merkle::proof(pre_leaves, pre_idx);
                serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
            });
            obj.insert("post_acct_proof".into(), {
                let p = obyte_merkle::proof(&posted_post, post_acct_idx);
                serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
            });
            obj.insert("pre_meta_proof".into(), {
                let p = obyte_merkle::proof(pre_leaves, meta_idx);
                serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
            });
            if let Some(pp) = &pre_pos_opt {
                let pi = index_of(pre_leaves, pp)?;
                obj.insert("pre_pos".into(), pp.clone().into());
                obj.insert("pre_pos_proof".into(), {
                    let p = obyte_merkle::proof(pre_leaves, pi);
                    serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                });
            } else {
                // Claimed-absent pre pos: prefix-range non-membership
                // neighbors over the SORTED pre leaves (AA checks the
                // [$plo,$phi) straddle). Note: proofs here are over the
                // sorted order; the AA only checks root/index/geometry.
                let mut sorted = pre_leaves.to_vec();
                sorted.sort();
                let plo = format!("pos:{}:{}:", acct_hex, market);
                let pos = sorted
                    .iter()
                    .position(|s| s.as_str() > plo.as_str())
                    .unwrap_or(sorted.len());
                if pos > 0 && pos < sorted.len() {
                    for (key, idx) in [("pleft", pos - 1), ("pright", pos)] {
                        obj.insert(format!("{}_proof", key).into(), {
                            let p = obyte_merkle::proof(&sorted, idx);
                            serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                        });
                    }
                    obj.insert("pleft".into(), sorted[pos - 1].clone().into());
                    obj.insert("pright".into(), sorted[pos].clone().into());
                } else if !sorted.is_empty() {
                    let i = if pos == 0 { 0 } else { sorted.len() - 1 };
                    obj.insert("pleft".into(), sorted[i].clone().into());
                    obj.insert("pleft_proof".into(), {
                        let p = obyte_merkle::proof(&sorted, i);
                        serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                    });
                } else {
                    continue;
                }
            }
            if !exp_pos_absent {
                let lp = posted_pos_opt.clone()?;
                let li = index_of(&posted_post, &lp)?;
                obj.insert("post_pos".into(), lp.into());
                obj.insert("post_pos_proof".into(), {
                    let p = obyte_merkle::proof(&posted_post, li);
                    serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                });
            }
            return Some(BuiltProof {
                pred: "fill_math".into(),
                fill_aa: true,
                clamp_aa: false,
                data,
            });
        }
    }
    None
}
/// Clamp proof (doc 12 §2.1): the honest replay clamped on this fill, so the
/// posted legs carry (honest or fraudulent) clamp outcomes. Recompute the
/// honest shortfall per side from pre legs, simulate the clamp AA's three
/// legs against the POSTED commitments, and emit the first side the AA
/// would convict. Returns None when the posted legs match the honest replay
/// on every leg (honest clamped height → the AA would bounce 'no fraud').
fn clamp_proof(
    batch: &Batch,
    k: usize,
    f: &str,
    pre_leaves: &[String],
    _post_leaves: &[String],
    posted_post: &[String],
) -> Option<BuiltProof> {
    use operp_types::signed_notional_usd;
    let parts: Vec<&str> = f.split(':').collect();
    if parts.len() != 12 {
        return None;
    }
    let taker_hex = parts[3].to_string();
    let maker_hex = parts[4].to_string();
    let market = parts[7].to_string();
    let price: i64 = parts[8].parse().ok()?;
    let qty: u64 = parts[9].parse().ok()?;
    let taker_side = parts[11];
    if taker_side != "0" && taker_side != "1" {
        return None;
    }
    let maker_side = if taker_side == "0" { "1" } else { "0" };
    // Pre meta: fee schedule + fill-market mark (clamp-time marks are pre).
    let pre_meta = pre_leaves
        .iter()
        .find(|l| l.starts_with(&format!("meta:{}:", market)))?
        .clone();
    let mparts: Vec<&str> = pre_meta.split(':').collect();
    if mparts.len() != 9 {
        return None;
    }
    let fee_bps: u128 = mparts[5].parse().ok()?;
    let fill_mark: i64 = mparts[8].parse().ok()?;
    let notional =
        qty as u128 * (price as i128).abs() as u128 / 100_000_000 * 1_000_000 / 100_000_000;
    let fee = (notional * fee_bps / 10_000) as i128;
    // Pre marks per market for upnl (fill market + extras share this map).
    let pre_marks: std::collections::HashMap<String, i64> = pre_leaves
        .iter()
        .filter(|l| l.starts_with("meta:"))
        .filter_map(|l| {
            let o: Vec<&str> = l.split(':').collect();
            if o.len() == 9 {
                o[8].parse::<i64>().ok().map(|m| (o[1].to_string(), m))
            } else {
                None
            }
        })
        .collect();
    let zero_acct = "0".repeat(64);
    let ins_pre = pre_leaves
        .iter()
        .find(|l| l.starts_with(&format!("acct:{}:", zero_acct)))?
        .clone();
    let ins_pre_col: i128 = ins_pre.split(':').nth(2)?.parse().ok()?;
    let ins_post = posted_post
        .iter()
        .find(|l| l.starts_with(&format!("acct:{}:", zero_acct)))?
        .clone();
    let ins_post_col: i128 = ins_post.split(':').nth(2)?.parse().ok()?;
    // Posted receipt deltas per side (absent = 0).
    let posted_delta = |hex: &str, leaves_pre: &[String], leaves_post: &[String]| -> i128 {
        let pre: i128 = leaves_pre
            .iter()
            .find(|l| l.starts_with(&format!("clamp:{}:", hex)))
            .and_then(|l| l.split(':').nth(2))
            .and_then(|s| s.parse::<i128>().ok())
            .unwrap_or(0);
        let post: i128 = leaves_post
            .iter()
            .find(|l| l.starts_with(&format!("clamp:{}:", hex)))
            .and_then(|l| l.split(':').nth(2))
            .and_then(|s| s.parse::<i128>().ok())
            .unwrap_or(0);
        post - pre
    };
    let taker_delta = posted_delta(&taker_hex, pre_leaves, posted_post);
    let maker_delta = posted_delta(&maker_hex, pre_leaves, posted_post);
    let sides = [
        ("taker", taker_hex.as_str(), taker_side, taker_delta),
        ("maker", maker_hex.as_str(), maker_side, maker_delta),
    ];
    for (who, acct_hex, side_acct, _own_delta) in sides {
        let delta: i64 = if side_acct == "0" {
            qty as i64
        } else {
            -(qty as i64)
        };
        let pre_acct = pre_leaves
            .iter()
            .find(|l| l.starts_with(&format!("acct:{}:", acct_hex)))?
            .clone();
        let pre_parts: Vec<&str> = pre_acct.split(':').collect();
        if pre_parts.len() != 5 {
            continue;
        }
        let old_col: i128 = pre_parts[2].parse().ok()?;
        let pre_pos_opt = pre_leaves
            .iter()
            .find(|l| {
                l.starts_with("pos:") && {
                    let o: Vec<&str> = l.split(':').collect();
                    o.len() == 5 && o[1] == acct_hex && o[2] == market
                }
            })
            .cloned();
        let (old_qty, old_entry): (i64, i64) = match &pre_pos_opt {
            None => (0, 0),
            Some(p) => {
                let o: Vec<&str> = p.split(':').collect();
                match (o[3].parse(), o[4].parse()) {
                    (Ok(q), Ok(e)) => (q, e),
                    _ => continue,
                }
            }
        };
        // Expected no-clamp legs (same replay as fill_math).
        let abs_old = old_qty.abs() as i128;
        let abs_delta = delta.abs() as i128;
        let same = old_qty == 0 || (old_qty > 0 && delta > 0) || (old_qty < 0 && delta < 0);
        let (exp_qty, exp_entry, exp_col, exp_pos_absent) = if same {
            let eq = old_qty + delta;
            let ee = if old_qty == 0 {
                price
            } else {
                ((abs_old * i128::from(old_entry) + i128::from(qty) * i128::from(price))
                    / (abs_old + i128::from(qty))) as i64
            };
            let ec = if who == "taker" {
                old_col - fee
            } else {
                old_col
            };
            (eq, ee, ec, false)
        } else {
            let close = abs_old.min(abs_delta);
            let signed: i128 = if old_qty > 0 {
                price as i128 - old_entry as i128
            } else {
                old_entry as i128 - price as i128
            };
            // Rust truncates toward zero; mirror fill_proof's port.
            let pnl_raw = signed * close * 1_000_000;
            let pnl = pnl_raw / 100_000_000 / 100_000_000;
            let ec = if who == "taker" {
                old_col + pnl - fee
            } else {
                old_col + pnl
            };
            let leftover = abs_old - close;
            let open = abs_delta - close;
            if leftover == 0 && open == 0 {
                (0, 0, ec, true)
            } else if leftover == 0 {
                (
                    if delta > 0 {
                        open as i64
                    } else {
                        -(open as i64)
                    },
                    price,
                    ec,
                    false,
                )
            } else {
                (
                    if old_qty > 0 {
                        leftover as i64
                    } else {
                        -(leftover as i64)
                    },
                    old_entry,
                    ec,
                    false,
                )
            }
        };
        // Posted post legs for this side.
        let posted_acct = posted_post
            .iter()
            .find(|l| l.starts_with(&format!("acct:{}:", acct_hex)))?
            .clone();
        let posted_col: i128 = posted_acct.split(':').nth(2)?.parse().ok()?;
        let posted_pos_opt = posted_post
            .iter()
            .find(|l| {
                l.starts_with("pos:") && {
                    let o: Vec<&str> = l.split(':').collect();
                    o.len() == 5 && o[1] == acct_hex && o[2] == market
                }
            })
            .cloned();
        // Pos leg must match the replay (entry ±1 like the AA); a divergent
        // pos leg is fraud by itself.
        let pos_bad = if exp_pos_absent {
            posted_pos_opt.is_some()
        } else {
            match &posted_pos_opt {
                Some(p) => {
                    let o: Vec<&str> = p.split(':').collect();
                    o.len() != 5
                        || o[3].parse::<i64>().ok() != Some(exp_qty)
                        || (o[4].parse::<i64>().unwrap_or(i64::MAX) - exp_entry).abs() > 1
                }
                None => true,
            }
        };
        // upnl over POSTED post positions at PRE marks (mirrors the AA):
        // fill-market leg from the replayed qty/entry, extras from posted.
        let mut upnl: i128 = 0;
        if !pos_bad && !exp_pos_absent {
            let entry_used: i64 = posted_pos_opt
                .as_ref()
                .and_then(|p| p.split(':').nth(4)?.parse::<i64>().ok())
                .unwrap_or(exp_entry);
            upnl += signed_notional_usd(exp_qty, fill_mark)
                - signed_notional_usd(exp_qty, entry_used);
        } else if !exp_pos_absent {
            upnl += signed_notional_usd(exp_qty, fill_mark)
                - signed_notional_usd(exp_qty, exp_entry);
        }
        // Extra post positions (posted) × pre marks, cap 3 (AA pos ≤ 4).
        let mut extras: Vec<(String, String)> = posted_post
            .iter()
            .filter(|l| {
                l.starts_with("pos:") && {
                    let o: Vec<&str> = l.split(':').collect();
                    o.len() == 5 && o[1] == acct_hex && o[2] != market
                }
            })
            .map(|l| {
                let o: Vec<&str> = l.split(':').collect();
                (l.clone(), o[2].to_string())
            })
            .collect();
        extras.sort_by(|a, b| a.0.cmp(&b.0));
        if extras.len() > 3 {
            continue; // beyond the AA's pos ≤ 4 bound — print-only
        }
        let mut extra_ok = true;
        for (pos_leaf, mkt) in &extras {
            let o: Vec<&str> = pos_leaf.split(':').collect();
            let q: i64 = match o[3].parse() {
                Ok(v) => v,
                Err(_) => {
                    extra_ok = false;
                    break;
                }
            };
            let e: i64 = match o[4].parse() {
                Ok(v) => v,
                Err(_) => {
                    extra_ok = false;
                    break;
                }
            };
            match pre_marks.get(mkt) {
                Some(mk) => {
                    upnl += signed_notional_usd(q, *mk) - signed_notional_usd(q, e);
                }
                None => {
                    extra_ok = false;
                    break;
                }
            }
        }
        if !extra_ok {
            continue;
        }
        let equity_noclamp = exp_col + upnl;
        let shortfall = if equity_noclamp < 0 {
            -equity_noclamp
        } else {
            0
        };
        // Posted legs vs honest replay (mirrors the AA verdict).
        let own_claimed = if who == "taker" {
            taker_delta
        } else {
            maker_delta
        };
        let other_claimed = if who == "taker" {
            maker_delta
        } else {
            taker_delta
        };
        // Insurance leg mirrors the AA: the fill taker fee (side-independent)
        // minus both sides' receipt deltas.
        let legs_ok = !pos_bad
            && posted_col == exp_col + shortfall
            && own_claimed == shortfall
            && ins_post_col - ins_pre_col == fee - shortfall - other_claimed;
        if legs_ok {
            continue; // honest side — try the other party
        }
        let idx = index_of(&batch.fills, f)?;
        let mut data = serde_json::json!({
            "trace_root": batch.checkpoint.trace_root,
            "ops_root": batch.checkpoint.ops_root,
            "k": k,
            "fill": f,
            "fill_proof": proof_json(&batch.fills, idx),
            "pre_acct": pre_acct,
            "post_acct": posted_acct,
            "pre_meta": pre_meta,
            "pos_absent": pre_pos_opt.is_none(),
            "post_pos_absent": exp_pos_absent && posted_pos_opt.is_none(),
            "xp_count": extras.len(),
        });
        let pre_fields = pre_wit_fields(batch, k, pre_leaves);
        let post_wit = batch.trace.get(k)?.clone();
        let post_proof = proof_json(&batch.trace, k);
        let pre_idx = index_of(pre_leaves, &pre_acct)?;
        let post_acct_idx = index_of(posted_post, data["post_acct"].as_str()?)?;
        let meta_idx = index_of(pre_leaves, &pre_meta)?;
        let ins_pre_idx = index_of(pre_leaves, &ins_pre)?;
        let ins_post_idx = index_of(posted_post, &ins_post)?;
        data.as_object_mut()?
            .extend(pre_fields.as_object()?.clone());
        let obj = data.as_object_mut()?;
        obj.insert("post_wit".into(), post_wit.into());
        obj.insert("post_proof".into(), post_proof);
        obj.insert("pre_acct_proof".into(), {
            let p = obyte_merkle::proof(pre_leaves, pre_idx);
            serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
        });
        obj.insert("post_acct_proof".into(), {
            let p = obyte_merkle::proof(posted_post, post_acct_idx);
            serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
        });
        obj.insert("pre_meta_proof".into(), {
            let p = obyte_merkle::proof(pre_leaves, meta_idx);
            serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
        });
        obj.insert("insurance_pre".into(), ins_pre.clone().into());
        obj.insert("insurance_pre_proof".into(), {
            let p = obyte_merkle::proof(pre_leaves, ins_pre_idx);
            serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
        });
        obj.insert("insurance_post".into(), ins_post.clone().into());
        obj.insert("insurance_post_proof".into(), {
            let p = obyte_merkle::proof(posted_post, ins_post_idx);
            serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
        });
        // Pre pos (or ghost non-membership).
        if let Some(pp) = &pre_pos_opt {
            let pi = index_of(pre_leaves, pp)?;
            obj.insert("pre_pos".into(), pp.clone().into());
            obj.insert("pre_pos_proof".into(), {
                let p = obyte_merkle::proof(pre_leaves, pi);
                serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
            });
        } else {
            let mut sorted = pre_leaves.to_vec();
            sorted.sort();
            let plo = format!("pos:{}:{}:", acct_hex, market);
            let pos = sorted
                .iter()
                .position(|s| s.as_str() > plo.as_str())
                .unwrap_or(sorted.len());
            if pos > 0 && pos < sorted.len() {
                for (key, idx) in [("pleft", pos - 1), ("pright", pos)] {
                    obj.insert(format!("{}_proof", key).into(), {
                        let p = obyte_merkle::proof(&sorted, idx);
                        serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                    });
                }
                obj.insert("pleft".into(), sorted[pos - 1].clone().into());
                obj.insert("pright".into(), sorted[pos].clone().into());
            } else if !sorted.is_empty() {
                let i = if pos == 0 { 0 } else { sorted.len() - 1 };
                obj.insert("pleft".into(), sorted[i].clone().into());
                obj.insert("pleft_proof".into(), {
                    let p = obyte_merkle::proof(&sorted, i);
                    serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                });
            } else {
                continue;
            }
        }
        // Posted post pos (when the replay expects one).
        if !exp_pos_absent {
            let lp = posted_pos_opt.clone()?;
            // If the posted pos itself diverged, the AA convicts via the
            // pos flag — but the challenge still needs a membership proof
            // of the POSTED leaf, which exists whenever the leaf is there.
            let li = index_of(posted_post, &lp)?;
            obj.insert("post_pos".into(), lp.into());
            obj.insert("post_pos_proof".into(), {
                let p = obyte_merkle::proof(posted_post, li);
                serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
            });
        }
        // Clamp receipt leaves: posted sides prove member; absent → flag.
        let pre_cl_leaf = pre_leaves
            .iter()
            .find(|l| l.starts_with(&format!("clamp:{}:", acct_hex)))
            .cloned();
        if let Some(leaf) = pre_cl_leaf {
            let li = index_of(pre_leaves, &leaf)?;
            obj.insert("pre_clamp".into(), leaf.into());
            obj.insert("pre_clamp_proof".into(), {
                let p = obyte_merkle::proof(pre_leaves, li);
                serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
            });
        } else {
            obj.insert("pre_clamp_absent".into(), true.into());
        }
        let post_cl_leaf = posted_post
            .iter()
            .find(|l| l.starts_with(&format!("clamp:{}:", acct_hex)))
            .cloned();
        if let Some(leaf) = post_cl_leaf {
            let li = index_of(posted_post, &leaf)?;
            obj.insert("post_clamp".into(), leaf.into());
            obj.insert("post_clamp_proof".into(), {
                let p = obyte_merkle::proof(posted_post, li);
                serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
            });
        } else {
            obj.insert("post_clamp_absent".into(), true.into());
        }
        // Other side posted receipts (pre honest + post posted).
        let other_hex = if who == "taker" {
            maker_hex.as_str()
        } else {
            taker_hex.as_str()
        };
        let other_pre_leaf = pre_leaves
            .iter()
            .find(|l| l.starts_with(&format!("clamp:{}:", other_hex)))
            .cloned();
        if let Some(leaf) = other_pre_leaf {
            let li = index_of(pre_leaves, &leaf)?;
            obj.insert("other_pre".into(), leaf.into());
            obj.insert("other_pre_proof".into(), {
                let p = obyte_merkle::proof(pre_leaves, li);
                serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
            });
        } else {
            obj.insert("other_pre_absent".into(), true.into());
        }
        let other_post_leaf = posted_post
            .iter()
            .find(|l| l.starts_with(&format!("clamp:{}:", other_hex)))
            .cloned();
        if let Some(leaf) = other_post_leaf {
            let li = index_of(posted_post, &leaf)?;
            obj.insert("other_post".into(), leaf.into());
            obj.insert("other_post_proof".into(), {
                let p = obyte_merkle::proof(posted_post, li);
                serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
            });
        } else {
            obj.insert("other_post_absent".into(), true.into());
        }
        // Extra legs xp0..xp2 / xm0..xm2.
        for (i, (pos_leaf, mkt)) in extras.iter().enumerate() {
            let li = index_of(posted_post, pos_leaf)?;
            obj.insert(format!("xp{}", i).into(), pos_leaf.clone().into());
            obj.insert(format!("xp{}_proof", i).into(), {
                let p = obyte_merkle::proof(posted_post, li);
                serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
            });
            let meta_leaf = pre_leaves
                .iter()
                .find(|l| l.starts_with(&format!("meta:{}:", mkt)))?
                .clone();
            let mi = index_of(pre_leaves, &meta_leaf)?;
            obj.insert(format!("xm{}", i).into(), meta_leaf.into());
            obj.insert(format!("xm{}_proof", i).into(), {
                let p = obyte_merkle::proof(pre_leaves, mi);
                serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
            });
        }
        return Some(BuiltProof {
            pred: "clamp".into(),
            fill_aa: false,
            clamp_aa: true,
            data,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use operp_dag::{genesis_id, sign_unit, unit_id, Op};
    use operp_types::{account_id_from_pubkey, AccountId};

    fn sk(n: u8) -> [u8; 32] {
        [n; 32]
    }
    fn acct_of(secret: &[u8; 32]) -> AccountId {
        let pk = SigningKey::from_bytes(secret).verifying_key().to_bytes();
        account_id_from_pubkey(&pk)
    }
    fn test_addr() -> String {
        "A".repeat(32)
    }

    #[test]
    fn deposit_mismatch_builds_proof() {
        let secret = sk(7);
        let acct = acct_of(&secret);
        let g = genesis_id();
        let aa = [9u8; 32];
        let u = sign_unit(
            vec![g],
            Op::Deposit {
                account: acct,
                addr: test_addr(),
                amount: 100,
                aa_unit: aa,
            },
            &secret,
        );
        let id = unit_id(&u);
        let mut eng = Engine::new();
        eng.state.deposits_allowed.insert((aa, false));
        eng.ingest(u).unwrap();
        let prev = operp_state::ChainState::new();
        let mut eng2 = eng.clone();
        let mut batch = Batch::from_applied(&prev, &mut eng2, &[id]).expect("batch");
        // Tamper the posted post leaf: col stays 0 despite +100 deposit.
        if let Some(leaves) = batch.leaf_trace.get_mut(0) {
            for l in leaves.iter_mut() {
                if l.starts_with(&format!("acct:{}:", hex::encode(acct.0))) {
                    let parts: Vec<&str> = l.split(':').collect();
                    *l = format!("acct:{}:0:{}:{}", parts[1], parts[3], parts[4]);
                }
            }
        }
        let mut replay = Engine::new();
        let proof = build_proof(&batch, &mut replay, &[], 0, None).expect("proof");
        assert_eq!(proof.pred, "deposit");
        assert!(!proof.fill_aa);
    }
    #[test]
    fn dep_evidence_shapes_build_proof() {
        // Doc 12 §2.3: fictitious anchor (no receipt), amount mismatch, and
        // base<->PERP confusion all yield pred == "dep_evidence"; an exact
        // receipt match falls through to bookkeeping (None here — honest).
        use base64::Engine as _;
        let secret = sk(7);
        let acct = acct_of(&secret);
        let g = genesis_id();
        let aa = [9u8; 32];
        let anchor = base64::engine::general_purpose::STANDARD.encode(aa);
        assert_eq!(anchor.len(), 44);
        let build = || {
            let u = sign_unit(
                vec![g],
                Op::Deposit {
                    account: acct,
                    addr: test_addr(),
                    amount: 100,
                    aa_unit: aa,
                },
                &secret,
            );
            let id = unit_id(&u);
            let mut eng = Engine::new();
            eng.state.deposits_allowed.insert((aa, false));
            eng.ingest(u).unwrap();
            let prev = operp_state::ChainState::new();
            let mut eng2 = eng.clone();
            Batch::from_applied(&prev, &mut eng2, &[id]).expect("batch")
        };
        // Sanity: the committed op descriptor carries the anchor.
        let b0 = build();
        assert_eq!(
            b0.ops[0],
            format!("d:{}:100:{}", hex::encode(acct.0), anchor)
        );
        let fresh = || {
            let mut replay = Engine::new();
            replay.state.deposits_allowed.insert((aa, false));
            replay
        };
        // 1. Missing receipt → dep_evidence.
        let b = build();
        let no_receipt = |_: &str, _: bool| -> Result<Option<i128>, String> { Ok(None) };
        let p = build_proof(&b, &mut fresh(), &[], 0, Some(&no_receipt)).expect("missing proof");
        assert_eq!(p.pred, "dep_evidence");
        assert!(!p.fill_aa);
        assert!(!p.clamp_aa);
        assert_eq!(p.data.get("op").and_then(|v| v.as_str()), Some(b.ops[0].as_str()));
        // 2. Amount mismatch → dep_evidence.
        let b = build();
        let wrong = |_: &str, _: bool| -> Result<Option<i128>, String> { Ok(Some(99)) };
        let p = build_proof(&b, &mut fresh(), &[], 0, Some(&wrong)).expect("mismatch proof");
        assert_eq!(p.pred, "dep_evidence");
        // 3. Exact receipt → no receipt fraud (bookkeeping honest → None).
        let b = build();
        let exact = |_: &str, _: bool| -> Result<Option<i128>, String> { Ok(Some(100)) };
        assert!(build_proof(&b, &mut fresh(), &[], 0, Some(&exact)).is_none());
        // 4. Transport failure → receipt check skipped (None).
        let b = build();
        let flaky = |_: &str, _: bool| -> Result<Option<i128>, String> { Err("hub down".into()) };
        assert!(build_proof(&b, &mut fresh(), &[], 0, Some(&flaky)).is_none());
    }

    #[test]
    fn omit_missing_forced_id_builds_proof() {
        // Batch with one honest deposit unit; the forced id is absent.
        let secret = sk(7);
        let acct = acct_of(&secret);
        let g = genesis_id();
        let aa = [9u8; 32];
        let u = sign_unit(
            vec![g],
            Op::Deposit {
                account: acct,
                addr: test_addr(),
                amount: 100,
                aa_unit: aa,
            },
            &secret,
        );
        let id = unit_id(&u);
        let mut eng = Engine::new();
        eng.state.deposits_allowed.insert((aa, false));
        eng.ingest(u).unwrap();
        let prev = operp_state::ChainState::new();
        let mut eng2 = eng.clone();
        let batch = Batch::from_applied(&prev, &mut eng2, &[id]).expect("batch");
        let forced = hex::encode([0xabu8; 32]);
        let mut replay = Engine::new();
        let proof = build_proof(&batch, &mut replay, &[(forced.clone(), 0)], 999, None).expect("proof");
        assert_eq!(proof.pred, "omit");
        assert!(!proof.fill_aa);
        assert_eq!(
            proof.data.get("unit_id").and_then(|v| v.as_str()),
            Some(forced.as_str())
        );
    }

    #[test]
    fn fill_math_reduce_builds_proof() {
        use operp_types::{
            OrderType, Side, TimeInForce, UnitId, BTC_USD, PRICE_SCALE, QTY_SCALE, USD_SCALE,
        };
        let alice = sk(1);
        let bob = sk(2);
        let alice_id = acct_of(&alice);
        let bob_id = acct_of(&bob);
        let fund = |eng: &mut Engine| {
            for id in [alice_id, bob_id] {
                eng.state
                    .account_mut(id)
                    .credit(10_000 * USD_SCALE as i128)
                    .unwrap();
            }
        };
        let mut eng = Engine::new();
        fund(&mut eng);
        let prev = eng.state.clone();
        let g = genesis_id();
        let px1 = 100_000 * PRICE_SCALE as i64;
        let px2 = 105_000 * PRICE_SCALE as i64;
        let q1 = QTY_SCALE;
        let q2 = QTY_SCALE / 2;
        let place = |parents: Vec<UnitId>,
                     secret: &[u8; 32],
                     account: AccountId,
                     side: Side,
                     price: i64,
                     qty: u64,
                     seq: u64| {
            sign_unit(
                parents,
                Op::Place {
                    account,
                    market: BTC_USD,
                    side,
                    typ: OrderType::Limit,
                    tif: TimeInForce::Gtc,
                    price,
                    qty,
                    client_seq: seq,
                },
                secret,
            )
        };
        // k=0: bob asks 1 @100k (rests). k=1: alice bids 1 @100k (fill1:
        // alice long 1 @100k). k=2: bob bids 0.5 @105k (rests). k=3: alice
        // asks 0.5 @105k (fill2, taker alice Ask) reducing the long and
        // realizing +2500 USD pnl into collateral.
        let ask1 = place(vec![g], &bob, bob_id, Side::Ask, px1, q1, 1);
        let id1 = unit_id(&ask1);
        eng.ingest(ask1).unwrap();
        let bid1 = place(vec![id1], &alice, alice_id, Side::Bid, px1, q1, 1);
        let id2 = unit_id(&bid1);
        eng.ingest(bid1).unwrap();
        let bid2 = place(vec![id2], &bob, bob_id, Side::Bid, px2, q2, 2);
        let id3 = unit_id(&bid2);
        eng.ingest(bid2).unwrap();
        let ask2 = place(vec![id3], &alice, alice_id, Side::Ask, px2, q2, 2);
        let id4 = unit_id(&ask2);
        eng.ingest(ask2).unwrap();
        let mut eng2 = eng.clone();
        let mut batch =
            Batch::from_applied(&prev, &mut eng2, &[id1, id2, id3, id4]).expect("batch");
        // Liar drops the realized pnl from the taker's posted post col.
        let alice_hex = hex::encode(alice_id.0);
        if let Some(leaves) = batch.leaf_trace.get_mut(3) {
            for l in leaves.iter_mut() {
                if l.starts_with(&format!("acct:{}:", alice_hex)) {
                    let p: Vec<&str> = l.split(':').collect();
                    let col: i128 = p[2].parse().unwrap();
                    *l = format!(
                        "acct:{}:{}:{}:{}",
                        p[1],
                        col - 2_500 * USD_SCALE as i128,
                        p[3],
                        p[4]
                    );
                }
            }
        }
        batch.trace[3] = obyte_merkle::root(&batch.leaf_trace[3]);
        batch.checkpoint.trace_root = obyte_merkle::root(&batch.trace);
        let mut replay = Engine::new();
        fund(&mut replay);
        let proof = build_proof(&batch, &mut replay, &[], 0, None).expect("proof");
        assert_eq!(proof.pred, "fill_math");
        assert!(proof.fill_aa);
        assert_eq!(
            proof.data.get("who").and_then(|v| v.as_str()),
            Some("taker")
        );
    }
    #[test]
    fn honest_batch_builds_no_proof() {
        // Clean deposit batch, no inbox, untampered leaves: None.
        let secret = sk(7);
        let acct = acct_of(&secret);
        let g = genesis_id();
        let aa = [9u8; 32];
        let u = sign_unit(
            vec![g],
            Op::Deposit {
                account: acct,
                addr: test_addr(),
                amount: 100,
                aa_unit: aa,
            },
            &secret,
        );
        let id = unit_id(&u);
        let mut eng = Engine::new();
        eng.state.deposits_allowed.insert((aa, false));
        eng.ingest(u).unwrap();
        let prev = operp_state::ChainState::new();
        let mut eng2 = eng.clone();
        let batch = Batch::from_applied(&prev, &mut eng2, &[id]).expect("batch");
        let mut replay = Engine::new();
        // Replay on a fresh engine at genesis prev root: the deposit
        // replays honestly, no divergence.
        replay.state.deposits_allowed.insert((aa, false));
        assert!(build_proof(&batch, &mut replay, &[], 0, None).is_none());
    }
    #[test]
    fn honest_clamp_builds_no_proof() {
        // Maker bankrupted by a dump: honest clamp legs match everywhere.
        use operp_types::{
            OrderType, Side, TimeInForce, UnitId, BTC_USD, PRICE_SCALE, QTY_SCALE, USD_SCALE,
        };
        let taker = sk(1);
        let maker = sk(2);
        let taker_id = acct_of(&taker);
        let maker_id = acct_of(&maker);
        let mut eng = Engine::new();
        eng.state
            .account_mut(taker_id)
            .credit(1_000_000 * USD_SCALE as i128)
            .unwrap();
        eng.state
            .account_mut(maker_id)
            .credit(50_000 * USD_SCALE as i128)
            .unwrap();
        let prev = eng.state.clone();
        let g = genesis_id();
        let place = |parents: Vec<UnitId>,
                     secret: &[u8; 32],
                     account: AccountId,
                     side: Side,
                     price: i64,
                     qty: u64,
                     seq: u64| {
            sign_unit(
                parents,
                Op::Place {
                    account,
                    market: BTC_USD,
                    side,
                    typ: OrderType::Limit,
                    tif: TimeInForce::Gtc,
                    price,
                    qty,
                    client_seq: seq,
                },
                secret,
            )
        };
        let px_hi = 100_000 * PRICE_SCALE as i64;
        let px_lo = 10_000 * PRICE_SCALE as i64;
        // k=0: maker bids 1 @100k (rests). k=1: taker asks 1 @100k (fill1:
        // maker long 1 @100k). k=2: taker bids 1 @10k (rests). k=3: maker
        // asks 1 @10k (fill2: maker closes for -90k into 50k collateral →
        // bankrupt, honest clamp).
        let b1 = place(vec![g], &maker, maker_id, Side::Bid, px_hi, QTY_SCALE, 1);
        let id1 = unit_id(&b1);
        eng.ingest(b1).unwrap();
        let a1 = place(vec![id1], &taker, taker_id, Side::Ask, px_hi, QTY_SCALE, 1);
        let id2 = unit_id(&a1);
        eng.ingest(a1).unwrap();
        let b2 = place(vec![id2], &taker, taker_id, Side::Bid, px_lo, QTY_SCALE, 2);
        let id3 = unit_id(&b2);
        eng.ingest(b2).unwrap();
        let a2 = place(vec![id3], &maker, maker_id, Side::Ask, px_lo, QTY_SCALE, 2);
        let id4 = unit_id(&a2);
        eng.ingest(a2).unwrap();
        // Honest replay clamped the maker: receipt + zeroed collateral. The
        // maker takes fill2 (5 USD fee on 10k notional), so the shortfall is
        // 40k loss + 5 fee = 40005k.
        let maker_hex = hex::encode(maker_id.0);
        assert_eq!(eng.state.accounts[&maker_id].collateral, 0);
        assert_eq!(
            eng.state.clamp_paid.get(&maker_id).copied(),
            Some(40_005 * USD_SCALE as i128)
        );
        let mut eng2 = eng.clone();
        let batch =
            Batch::from_applied(&prev, &mut eng2, &[id1, id2, id3, id4]).expect("batch");
        // Sanity: the posted batch carries the clamp receipt leaf.
        assert!(batch.leaf_trace[3].iter().any(|l| l.starts_with(&format!(
            "clamp:{}:",
            maker_hex
        ))));
        let mut replay = Engine::new();
        replay
            .state
            .account_mut(taker_id)
            .credit(1_000_000 * USD_SCALE as i128)
            .unwrap();
        replay
            .state
            .account_mut(maker_id)
            .credit(50_000 * USD_SCALE as i128)
            .unwrap();
        assert!(build_proof(&batch, &mut replay, &[], 0, None).is_none());
    }
    fn clamp_liar_legs_build_clamp_proof() {
        // Same bankruptcy fixture; each liar shape yields pred == "clamp".
        use operp_types::{
            OrderType, Side, TimeInForce, UnitId, BTC_USD, PRICE_SCALE, QTY_SCALE, USD_SCALE,
        };
        let taker = sk(1);
        let maker = sk(2);
        let taker_id = acct_of(&taker);
        let maker_id = acct_of(&maker);
        let fund = |eng: &mut Engine| {
            eng.state
                .account_mut(taker_id)
                .credit(1_000_000 * USD_SCALE as i128)
                .unwrap();
            eng.state
                .account_mut(maker_id)
                .credit(50_000 * USD_SCALE as i128)
                .unwrap();
        };
        let build = || {
            let mut eng = Engine::new();
            fund(&mut eng);
            let prev = eng.state.clone();
            let g = genesis_id();
            let place = |parents: Vec<UnitId>,
                         secret: &[u8; 32],
                         account: AccountId,
                         side: Side,
                         price: i64,
                         qty: u64,
                         seq: u64| {
                sign_unit(
                    parents,
                    Op::Place {
                        account,
                        market: BTC_USD,
                        side,
                        typ: OrderType::Limit,
                        tif: TimeInForce::Gtc,
                        price,
                        qty,
                        client_seq: seq,
                    },
                    secret,
                )
            };
            let px_hi = 100_000 * PRICE_SCALE as i64;
            let px_lo = 10_000 * PRICE_SCALE as i64;
            let b1 = place(vec![g], &maker, maker_id, Side::Bid, px_hi, QTY_SCALE, 1);
            let id1 = unit_id(&b1);
            eng.ingest(b1).unwrap();
            let a1 = place(vec![id1], &taker, taker_id, Side::Ask, px_hi, QTY_SCALE, 1);
            let id2 = unit_id(&a1);
            eng.ingest(a1).unwrap();
            let b2 = place(vec![id2], &taker, taker_id, Side::Bid, px_lo, QTY_SCALE, 2);
            let id3 = unit_id(&b2);
            eng.ingest(b2).unwrap();
            let a2 = place(vec![id3], &maker, maker_id, Side::Ask, px_lo, QTY_SCALE, 2);
            let id4 = unit_id(&a2);
            eng.ingest(a2).unwrap();
            let mut eng2 = eng.clone();
            Batch::from_applied(&prev, &mut eng2, &[id1, id2, id3, id4]).expect("batch")
        };
        let maker_hex = hex::encode(maker_id.0);
        let retrace = |batch: &mut Batch| {
            batch.trace[3] = obyte_merkle::root(&batch.leaf_trace[3]);
            batch.checkpoint.trace_root = obyte_merkle::root(&batch.trace);
        };
        let fresh_replay = || {
            let mut replay = Engine::new();
            fund(&mut replay);
            replay
        };
        // 1. Skipped clamp: drop the receipt leaf AND restore the bankrupt
        //    collateral (operator posts the no-clamp outcome).
        let mut b = build();
        if let Some(leaves) = b.leaf_trace.get_mut(3) {
            leaves.retain(|l| !l.starts_with(&format!("clamp:{}:", maker_hex)));
            for l in leaves.iter_mut() {
                if l.starts_with(&format!("acct:{}:", maker_hex)) {
                    let p: Vec<&str> = l.split(':').collect();
                    *l = format!(
                        "acct:{}:{}:{}:{}",
                        p[1],
                        -40_000 * USD_SCALE as i128,
                        p[3],
                        p[4]
                    );
                }
            }
        }
        retrace(&mut b);
        let p = build_proof(&b, &mut fresh_replay(), &[], 0, None).expect("skip proof");
        assert_eq!(p.pred, "clamp");
        assert!(p.clamp_aa);
        // 2. Wrong amount: halve the receipt total, keep collateral honest.
        let mut b = build();
        if let Some(leaves) = b.leaf_trace.get_mut(3) {
            for l in leaves.iter_mut() {
                if l.starts_with(&format!("clamp:{}:", maker_hex)) {
                    *l = format!("clamp:{}:{}", maker_hex, 20_000 * USD_SCALE as i128);
                }
            }
        }
        retrace(&mut b);
        let p = build_proof(&b, &mut fresh_replay(), &[], 0, None).expect("amount proof");
        assert_eq!(p.pred, "clamp");
        assert!(p.clamp_aa);
        // 3. Over-charged user: receipt honest, posted collateral debited
        //    5k below the honest zero.
        let mut b = build();
        if let Some(leaves) = b.leaf_trace.get_mut(3) {
            for l in leaves.iter_mut() {
                if l.starts_with(&format!("acct:{}:", maker_hex)) {
                    let p: Vec<&str> = l.split(':').collect();
                    let col: i128 = p[2].parse().unwrap();
                    *l = format!(
                        "acct:{}:{}:{}:{}",
                        p[1],
                        col - 5_000 * USD_SCALE as i128,
                        p[3],
                        p[4]
                    );
                }
            }
        }
        retrace(&mut b);
        let p = build_proof(&b, &mut fresh_replay(), &[], 0, None).expect("overcharge proof");
        assert_eq!(p.pred, "clamp");
        assert!(p.clamp_aa);
    }
}
