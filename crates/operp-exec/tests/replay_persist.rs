//! Gap 11 acceptance tests (docs/mainnet/11-replay-persistence.md §3).
//!
//! Covers the two storage halves of Choice A-lite:
//!   * height-windowed dedup (`withdrawals`, `seen_aa_units`) surviving 300+
//!     heights and a restart via `chainstate.<height>.snap`,
//!   * the gov-nonce watermark surviving a crash via `gov_nonces.journal`
//!     alone (no snapshot), with no double-apply across the watermark.
//!
//! The window expansion (256 → 2048) ships behind the activation gate
//! (`REPLAY_ACTIVATION_HEIGHT`, flipped at deploy). Tests exercise the new
//! window path by overriding `state.height` past the gate instead of waiting
//! for deployment.

use ed25519_dalek::SigningKey;
use operp_dag::{genesis_id, sign_unit, unit_id, Op};
use operp_exec::{Engine, ExecEvent, RejectReason};
use operp_state::{ChainState, Withdrawal};
use operp_types::{
    account_id_from_pubkey, genesis_params, AccountId, Height, BTC_USD, USD_SCALE,
    REPLAY_ACTIVATION_HEIGHT, REPLAY_WINDOW, REPLAY_WINDOW_LEGACY,
};

fn sk(n: u8) -> [u8; 32] {
    [n; 32]
}

fn acct_of(secret: &[u8; 32]) -> AccountId {
    let pk = SigningKey::from_bytes(secret).verifying_key().to_bytes();
    account_id_from_pubkey(&pk)
}

/// Tests run standalone (no AA feed): admit every deposit of both asset
/// kinds and seed the BTC_USD market, mirroring the unit-test harness.
fn allow_all(eng: &mut Engine) {
    eng.state.deposits_allowed = (0u8..=255)
        .flat_map(|b| [([b; 32], false), ([b; 32], true)])
        .collect();
    eng.state.markets.insert(BTC_USD, genesis_params());
}

/// 32-char uppercase [A-Z2-7] Obyte-style test address.
fn test_addr(n: u8) -> String {
    let mut bytes = vec![b'A'; 32];
    bytes[0] = b'A' + (n % 26);
    String::from_utf8(bytes).unwrap()
}

fn deposit(parents: Vec<operp_types::UnitId>, secret: &[u8; 32], amount: i128, aa: u8) -> operp_dag::Unit {
    sign_unit(
        parents,
        Op::Deposit { account: acct_of(secret), addr: test_addr(aa), amount, aa_unit: [aa; 32] },
        secret,
    )
}

fn withdraw(parents: Vec<operp_types::UnitId>, secret: &[u8; 32], amount: i128, nonce: u64) -> operp_dag::Unit {
    sign_unit(parents, Op::Withdraw { account: acct_of(secret), amount, nonce }, secret)
}

fn gov_dep(parents: Vec<operp_types::UnitId>, secret: &[u8; 32], amount: u128, aa: u8) -> operp_dag::Unit {
    sign_unit(
        parents,
        Op::GovDeposit { account: acct_of(secret), addr: test_addr(aa), amount, aa_unit: [aa; 32] },
        secret,
    )
}

fn gov_with(parents: Vec<operp_types::UnitId>, secret: &[u8; 32], amount: u128, nonce: u64) -> operp_dag::Unit {
    sign_unit(parents, Op::GovWithdraw { account: acct_of(secret), amount, nonce }, secret)
}

/// Unique scratch store dir under the OS temp dir (no external deps).
fn temp_store(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("operp-replay-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn stored(dir: &std::path::Path) -> Engine {
    let mut eng = Engine::new();
    eng.store_dir = Some(dir.to_path_buf());
    eng
}

/// One REAL batch-commit step: cut a batch through `Batch::from_applied`
/// (height advance, ledger pruning, snapshot cadence, gov-nonce WAL flush)
/// rather than hand-rolling the same sequence. Each step deposits a fresh
/// minimal amount under a step-unique AA unit so `from_applied` has a
/// non-empty applied set; collisions with the test's own AA units only make
/// that step's deposit rejected (still committable), never affect assertions.
fn commit_step(eng: &mut Engine, i: u32) {
    use operp_settle::Batch;
    let g = genesis_id();
    let prev = eng.state.clone();
    // Secret, aa byte and amount all derive from the FULL index, so wrapped
    // aa bytes across >256 steps still produce distinct units (dag dedup).
    let secret = sk((i as u8).wrapping_add(64));
    let d = deposit(
        vec![g],
        &secret,
        USD_SCALE as i128 * (1 + i as i128),
        i as u8,
    );
    let id = unit_id(&d);
    eng.ingest(d).unwrap();
    Batch::from_applied(&prev, eng, &[id]).unwrap();
}

fn rejected<'a>(evs: &'a [ExecEvent]) -> Option<&'a RejectReason> {
    evs.iter().find_map(|e| match e {
        ExecEvent::Rejected { reason, .. } => Some(reason),
        _ => None,
    })
}

#[test]
fn duplicate_withdraw_300h_rejected_after_restart() {
    let dir = temp_store("1");
    let mut eng = stored(&dir);
    allow_all(&mut eng);

    // Height override: jump past the activation gate so the 2048 window
    // path runs (deployment flips REPLAY_ACTIVATION_HEIGHT; tests can't wait).
    eng.state.height = REPLAY_ACTIVATION_HEIGHT;

    let alice = sk(1);
    let g = genesis_id();
    let d = deposit(vec![g], &alice, 10_000 * USD_SCALE as i128, 1);
    let tip = unit_id(&d);
    eng.ingest(d).unwrap();

    // Withdraw nonce=7 at h.
    let w = withdraw(vec![tip], &alice, 100 * USD_SCALE as i128, 7);
    let tip = unit_id(&w);
    let evs = eng.ingest(w).unwrap();
    assert!(evs.iter().any(|e| matches!(e, ExecEvent::Applied { .. })));
    let key = (acct_of(&alice), 7u64);
    assert!(eng.state.withdrawals.contains_key(&key));

    // Advance 150 heights, then restart MID-STREAM and keep going on the
    // recovered engine — recovery must be seamless mid-batch-stream.
    for i in 0..150u16 {
        commit_step(&mut eng, u32::from(i));
    }
    eng.flush_snapshot().unwrap();
    let mut eng = Engine::load_or_genesis(&dir).unwrap();
    allow_all(&mut eng);
    assert!(
        eng.state.withdrawals.contains_key(&key),
        "restart must not lose the dedup entry"
    );
    for i in 150..310u16 {
        commit_step(&mut eng, u32::from(i));
    }

    // Entry must survive 310 heights under the 2048 window (legacy 256
    // would have pruned it at +257 and re-opened the replay hole).
    assert!(
        eng.state.withdrawals.contains_key(&key),
        "entry must survive 300+ heights with window=2048"
    );

    // Duplicate (account, nonce=7) re-ingested after the restart(s):
    // rejected as DuplicateNonce — no double-apply.
    let dup = withdraw(vec![g], &alice, 100 * USD_SCALE as i128, 7);
    let evs = eng.ingest(dup).unwrap();
    assert_eq!(
        rejected(&evs),
        Some(&RejectReason::DuplicateNonce),
        "duplicate withdraw after 300h + restart must be rejected"
    );
}

#[test]
fn gov_nonce_watermark_survives_restart_without_snapshot() {
    let dir = temp_store("2");
    let mut eng = stored(&dir);
    allow_all(&mut eng);
    eng.state.height = 50;

    let alice = sk(1);
    let g = genesis_id();
    let d = gov_dep(vec![g], &alice, 1_000, 7);
    let tip = unit_id(&d);
    eng.ingest(d).unwrap();

    // GovWithdraw nonce=5: buffered at ingest, persisted to the journal at
    // BATCH COMMIT (`from_applied`) — an uncommitted batch never burns a
    // nonce (H2), so the commit must happen before the simulated crash.
    let w = gov_with(vec![tip], &alice, 100, 5);
    let wid = unit_id(&w);
    let prev = eng.state.clone();
    let evs = eng.ingest(w).unwrap();
    assert!(
        evs.iter().any(|e| matches!(e, ExecEvent::Applied { .. })),
        "gov_with nonce=5 must apply, got {:?}",
        evs
    );
    operp_settle::Batch::from_applied(&prev, &mut eng, &[wid]).unwrap();

    // Crash WITHOUT any snapshot: the journal alone must carry the watermark
    // across the restart (closes the snapshot-cadence gap of up to 63 heights).
    let mut eng2 = Engine::load_or_genesis(&dir).unwrap();
    allow_all(&mut eng2);
    assert_eq!(
        eng2.state.seen_gov_nonces.get(&acct_of(&alice)).copied(),
        Some(5),
        "watermark must survive a snapshot-less crash via the journal"
    );

    // No double-apply across the watermark after restart:
    // the exact same nonce is still consumed...
    let evs = eng2.ingest(gov_with(vec![g], &alice, 50, 5)).unwrap();
    assert_eq!(rejected(&evs), Some(&RejectReason::DuplicateNonce));
    // ...and so is any lower nonce (strict watermark, gaps allowed).
    let evs = eng2.ingest(gov_with(vec![g], &alice, 50, 4)).unwrap();
    assert_eq!(rejected(&evs), Some(&RejectReason::DuplicateNonce));
    // A strictly higher nonce applies and re-journals... (PERP balances live
    // in the snapshot, not the journal — with no snapshot they come from
    // temp_data replay; here a fresh GovDeposit re-funds the account.)
    let evs = eng2.ingest(gov_dep(vec![g], &alice, 500, 8)).unwrap();
    assert!(evs.iter().any(|e| matches!(e, ExecEvent::Applied { .. })), "refund must apply, got {:?}", evs);
    let w6 = gov_with(vec![g], &alice, 50, 6);
    let prev3 = eng2.state.clone();
    let evs = eng2.ingest(w6.clone()).unwrap();
    assert!(
        evs.iter().any(|e| matches!(e, ExecEvent::Applied { .. })),
        "higher nonce must apply, got {:?}",
        evs
    );
    operp_settle::Batch::from_applied(&prev3, &mut eng2, &[unit_id(&w6)]).unwrap();
    // ...and survives yet another restart.
    let eng3 = Engine::load_or_genesis(&dir).unwrap();
    assert_eq!(eng3.state.seen_gov_nonces.get(&acct_of(&alice)).copied(), Some(6));
}

#[test]
fn aa_unit_reused_after_300h_still_rejected_after_restart() {
    let dir = temp_store("3");
    let mut eng = stored(&dir);
    allow_all(&mut eng);
    eng.state.height = REPLAY_ACTIVATION_HEIGHT;

    let alice = sk(1);
    let bob = sk(2);
    let g = genesis_id();

    // Deposit endorsing AA unit [9;32] at h.
    let d = deposit(vec![g], &alice, 1_000 * USD_SCALE as i128, 9);
    let evs = eng.ingest(d).unwrap();
    assert!(evs.iter().any(|e| matches!(e, ExecEvent::Applied { .. })));
    assert!(eng.state.seen_aa_units.contains_key(&[9u8; 32]));

    for i in 0..300u16 {
        commit_step(&mut eng, u32::from(i));
    }
    eng.flush_snapshot().unwrap();
    let mut eng2 = Engine::load_or_genesis(&dir).unwrap();
    allow_all(&mut eng2);
    assert!(
        eng2.state.seen_aa_units.contains_key(&[9u8; 32]),
        "seen_aa_units entry must survive 300 heights + restart under window=2048"
    );

    // Reused aa_unit on a fresh Deposit op: rejected as DuplicateDeposit even
    // though the (unit, kind) anchor is present in deposits_allowed — proving
    // the rejection comes from the persisted dedup map, not the anchor set.
    let dup = deposit(vec![g], &bob, 500 * USD_SCALE as i128, 9);
    let evs = eng2.ingest(dup).unwrap();
    assert_eq!(
        rejected(&evs),
        Some(&RejectReason::DuplicateDeposit),
        "reused aa_unit after 300h + restart must be rejected"
    );

    // Same holds on the GovDeposit path.
    let dup = gov_dep(vec![g], &bob, 500, 9);
    let evs = eng2.ingest(dup).unwrap();
    assert_eq!(rejected(&evs), Some(&RejectReason::DuplicateDeposit));
}

#[test]
fn activation_gate_selects_window_by_height() {
    // One dedup entry created at h0, re-checked 300 heights later.
    fn entry_at(h0: Height) -> ChainState {
        let mut st = ChainState::new();
        st.height = h0;
        let raw = [7u8; 32];
        st.withdrawals
            .insert((AccountId(raw), 1), Withdrawal { amount: 1, pending: true, height: h0 });
        st.seen_aa_units.insert(raw, h0);
        st
    }

    // Below the gate (legacy path): a 300-height-old entry has already
    // expired under the legacy 256 window...
    let mut st = entry_at(REPLAY_ACTIVATION_HEIGHT - 10_000);
    st.height += 300;
    st.prune_withdrawals(st.height);
    st.prune_aa_units(st.height);
    assert!(
        st.withdrawals.is_empty() && st.seen_aa_units.is_empty(),
        "below the gate the legacy 256 window must still prune at 256"
    );

    // ...while above the gate (height override → new window path) the same
    // 300-height spread is well inside the 2048 window and survives.
    let mut st = entry_at(REPLAY_ACTIVATION_HEIGHT);
    st.height += 300;
    st.prune_withdrawals(st.height);
    st.prune_aa_units(st.height);
    assert_eq!(st.withdrawals.len(), 1, "above the gate nothing expires before 2048 heights");
    assert_eq!(st.seen_aa_units.len(), 1);
}

#[test]
fn prune_still_bounds_memory() {
    // Fill withdrawals/aa_units across more than one full 2048 window above
    // the gate, advance past the horizon, prune: everything older than the
    // window must go — bounded, not infinite.
    let h0 = REPLAY_ACTIVATION_HEIGHT;
    let n = (REPLAY_WINDOW + 513) as usize;
    let mut st = ChainState::new();
    st.height = h0;
    for i in 0..n as u64 {
        let mut raw = [0u8; 32];
        raw[..8].copy_from_slice(&i.to_le_bytes());
        st.withdrawals.insert(
            (AccountId(raw), i),
            Withdrawal { amount: 1, pending: true, height: h0 + i },
        );
        st.seen_aa_units.insert(raw, h0 + i);
    }
    assert_eq!(st.withdrawals.len(), n);
    st.height = h0 + REPLAY_WINDOW + 512;
    st.prune_withdrawals(st.height);
    st.prune_aa_units(st.height);
    // Retained iff entry_height + WINDOW > H ⇔ entry_height > h0 + 512,
    // i.e. exactly REPLAY_WINDOW entries (heights h0+513 ..= h0+512+2048).
    assert_eq!(st.withdrawals.len() as u64, REPLAY_WINDOW);
    assert_eq!(st.seen_aa_units.len() as u64, REPLAY_WINDOW);
}

#[test]
fn restart_midstream_recovered_via_validate_against_no_double_apply() {
    use operp_account::Account;
    use operp_settle::Batch;

    let dir = temp_store("6");
    let mut eng = stored(&dir);
    allow_all(&mut eng);
    eng.state.height = REPLAY_ACTIVATION_HEIGHT;

    let alice = acct_of(&sk(1));
    // Seed collateral directly (test harness); keeps the batch free of
    // Deposit/GovDeposit ops, whose evidence checks are gap-9 territory.
    eng.state
        .accounts
        .entry(alice)
        .or_insert_with(|| Account::new(alice))
        .credit(10_000 * USD_SCALE as i128)
        .unwrap();

    // Pre-commit checkpoint: snapshot the state the batch builds on, so the
    // restarted node boots from it and replays the finalized batch forward.
    let prev = eng.state.clone();
    eng.flush_snapshot().unwrap();

    let g = genesis_id();
    let w = withdraw(vec![g], &sk(1), 100 * USD_SCALE as i128, 7);
    let wid = unit_id(&w);
    eng.ingest(w).unwrap();
    let batch = Batch::from_applied(&prev, &mut eng, &[wid]).unwrap();

    // Crash + restart between batch production and validation: recovered
    // engine loads the pre-commit snapshot and replays the batch via
    // validate_against — exactly the design's recovery sequence.
    let mut eng2 = Engine::load_or_genesis(&dir).unwrap();
    allow_all(&mut eng2);
    assert_eq!(eng2.state.state_root(), prev.state_root(), "restart must boot at the pre-commit snapshot");
    batch
        .validate_against(prev.state_root(), &mut eng2)
        .expect("replay after restart must reproduce the batch");

    // Recovered state matches the producer's post-batch state exactly.
    assert_eq!(eng2.state.state_root(), eng.state.state_root());
    assert!(eng2.state.withdrawals.contains_key(&(alice, 7)));

    // No double-apply across the watermark: the duplicate withdraw is
    // rejected on the recovered engine.
    // Distinct unit (different amount ⇒ different id — the byte-identical
    // original is already DAG-deduped), same (account, nonce): must hit the
    // persisted dedup map, not the DAG.
    let dup = withdraw(vec![g], &sk(1), 99 * USD_SCALE as i128, 7);
    let evs = eng2.ingest(dup).unwrap();
    assert_eq!(
        rejected(&evs),
        Some(&RejectReason::DuplicateNonce),
        "duplicate must be rejected after restart + validate_against recovery"
    );
}

/// H2 regression: a validation replay that FAILS must not persist the batch's
/// gov-withdraw nonces. The batch is produced (and committed) on the producer
/// engine, then validated against a cloned validator with its own store dir;
/// validation ingests the GovWithdraw (buffering nonce 5) but fails on a
/// tampered fills hash. A restart of the validator must boot WITHOUT nonce 5 —
/// no burning nonces from batches that never committed on this node.
#[test]
fn failed_validate_against_does_not_persist_gov_nonce() {
    use operp_settle::SettleError;

    let producer_dir = temp_store("h2a");
    let validator_dir = temp_store("h2b");
    let mut eng = stored(&producer_dir);
    allow_all(&mut eng);
    eng.state.height = 50;

    let alice = acct_of(&sk(1));
    eng.state.perp_balances.insert(alice, 1_000);
    eng.state.perp_supply = 1_000;
    let prev = eng.state.clone();

    // Validator engine: identical state (clone), separate store dir — the
    // design's recovery shape (fresh node replaying a produced batch).
    let mut validator = eng.clone();
    validator.store_dir = Some(validator_dir.clone());

    let g = genesis_id();
    let w = gov_with(vec![g], &sk(1), 100, 5);
    let wid = unit_id(&w);
    eng.ingest(w).unwrap();
    let mut batch = operp_settle::Batch::from_applied(&prev, &mut eng, &[wid]).unwrap();
    // Producer committed: its own watermark carries nonce 5.
    assert_eq!(eng.state.seen_gov_nonces.get(&alice).copied(), Some(5));

    // Corrupt the checkpoint so validation fails AFTER replaying the batch.
    batch.checkpoint.fills_hash = [0xAA; 32];
    let err = batch.validate_against(prev.state_root(), &mut validator).unwrap_err();
    assert!(matches!(err, SettleError::FillsMismatch), "got {err:?}");

    // The validator replay advanced its in-memory watermark...
    assert_eq!(validator.state.seen_gov_nonces.get(&alice).copied(), Some(5));
    // ...but restart rebuilds from snapshot + journal: nonce 5 must be GONE.
    let eng3 = Engine::load_or_genesis(&validator_dir).unwrap();
    assert_eq!(
        eng3.state.seen_gov_nonces.get(&alice).copied(),
        None,
        "failed validation must not burn the nonce on the validator node"
    );
    let _ = std::fs::remove_dir_all(&producer_dir);
    let _ = std::fs::remove_dir_all(&validator_dir);
}
