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
    /// `ghost`, `skip`).
    pub pred: String,
    /// True → post to the fill dispute AA (`--fill`); false → main dispute AA.
    pub fill_aa: bool,
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
pub fn build_proof(
    batch: &Batch,
    replay: &mut Engine,
    inbox: &[(String, u64)],
    submit_ts: u64,
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
            if let Some(p) = deposit_proof(batch, k, &op, &pre_leaves, &post_leaves, true) {
                return Some(p);
            }
        } else if op.starts_with("w:") || op.starts_with("W:") {
            if let Some(p) = deposit_proof(batch, k, &op, &pre_leaves, &post_leaves, false) {
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
) -> Option<BuiltProof> {
    // Parse op: d:{acct}:{amount} (3 parts) or w:{acct}:{amount}:{nonce}.
    let parts: Vec<&str> = op.split(':').collect();
    if parts.len() < 3 {
        return None;
    }
    let acct_hex = parts[1].to_string();
    let amount: i128 = parts[2].parse().ok()?;
    // Fresh account: no pre leaf — pre col is 0, and the AA takes the
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
                format!("ord:{}:{}:{}:{}:{}:{}:{}", maker_order_hex, market, opp_side, fill_price, fill_seq, fill_qty, maker_hex).into(),
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
        let price: u64 = parts[8].parse().ok()?;
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
        let (mo_side, mo_price, mo_seq): (u8, u64, u64) = (
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
            let (c_side, c_price, c_seq): (u8, u64, u64) =
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
        let price: u64 = match parts[8].parse() {
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
        let notional = qty as u128 * price as u128 / 100_000_000 * 1_000_000 / 100_000_000;
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
            let (old_qty, old_entry): (i64, u64) = match &pre_pos_opt {
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
            let same =
                old_qty == 0 || (old_qty > 0 && delta > 0) || (old_qty < 0 && delta < 0);
            let (exp_qty, exp_entry, exp_col, exp_pos_absent) = if same {
                let eq = old_qty + delta;
                let ee = if old_qty == 0 {
                    price
                } else {
                    ((abs_old as u128 * old_entry as u128 + qty as u128 * price as u128)
                        / (abs_old as u128 + qty as u128)) as u64
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
                                    && o[4].parse::<u64>().ok() == Some(exp_entry)
                            }
                            None => false,
                        }
                    }
                }
                None => continue,
            };
            if !replay_ok {
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
            let posted_col: i128 = match posted_acct
                .split(':')
                .nth(2)
                .unwrap_or("")
                .parse()
            {
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
                            && o[4].parse::<u64>().ok() == Some(exp_entry)
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
                data,
            });
        }
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
        let proof = build_proof(&batch, &mut replay, &[], 0).expect("proof");
        assert_eq!(proof.pred, "deposit");
        assert!(!proof.fill_aa);
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
        let proof = build_proof(&batch, &mut replay, &[(forced.clone(), 0)], 999).expect("proof");
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
        let px1 = 100_000 * PRICE_SCALE;
        let px2 = 105_000 * PRICE_SCALE;
        let q1 = QTY_SCALE;
        let q2 = QTY_SCALE / 2;
        let place = |parents: Vec<UnitId>,
                     secret: &[u8; 32],
                     account: AccountId,
                     side: Side,
                     price: u64,
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
        let mut batch = Batch::from_applied(&prev, &mut eng2, &[id1, id2, id3, id4]).expect("batch");
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
        let proof = build_proof(&batch, &mut replay, &[], 0).expect("proof");
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
        assert!(build_proof(&batch, &mut replay, &[], 0).is_none());
    }
}
