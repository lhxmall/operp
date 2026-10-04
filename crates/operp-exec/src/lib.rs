use operp_account::AccountError;
use operp_book::{BookError, Fill, Order};
use operp_dag::{unit_id, Dag, DagError, Op, SigVerifier, Unit};
use operp_state::journal::{GovNonceJournal, GovNonceRecord};
use operp_state::persist;
use operp_state::{ChainState, Proposal};
use operp_types::{
    bps, funding_notional_usd, funding_rate_bps, funding_rate_cash, liq_order_id, notional_usd,
    order_id, risk_params_ok, valid_obyte_addr, AccountId, Bps, ExecStatus, Height, MarketId,
    MarketParams, OrderId, OrderType, ParamKey, Price, Qty, Seq, Side, TimeInForce, UnitId, Usd,
    CREATE_MARKET_FEE_PERP, INSURANCE_ACCOUNT, MAX_LIVE_ORDERS_PER_ACCOUNT, MIN_OPEN_EQUITY,
    PROPOSAL_DURATION_SEQS, PROPOSAL_MIN_STAKE_PERP, PROPOSAL_QUORUM_DEN, PROPOSAL_QUORUM_NUM,
};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Withdrawal ledger bound: once this many (account, nonce) entries are
/// pending, further withdrawals are rejected with Risk until entries clear.
/// Keeps ChainState.withdrawals bounded.
const WITHDRAWALS_CAP: usize = 65_536;

#[derive(Clone, Debug)]
pub struct Engine {
    pub dag: Dag,
    pub state: ChainState,
    pub log: Vec<ExecEvent>,
    /// Cached pubkey -> VerifyingKey decompression for ingest verification.
    pub sig_verifier: SigVerifier,
    /// Persistence root (`gap 11 v1`). `None` = ephemeral engine (tests,
    /// replay validators). When set: gov-nonce WAL + optional snapshots.
    pub store_dir: Option<PathBuf>,
    /// Replay-validation mode (H2): while validating a batch, gov-withdraw
    /// nonces are NOT written to the WAL — only `Batch::from_applied` on the
    /// production path persists them, at batch-commit time.
    pub validating: bool,
    /// Gov-withdraw nonces awaiting durable commit. Pushed at ingest,
    /// flushed to the WAL by [`Engine::flush_gov_wal`] when the batch
    /// commits (`Batch::from_applied`); dropped (never persisted) if the
    /// batch is abandoned — no more burning nonces on uncommitted batches.
    pub pending_gov_wal: Vec<(AccountId, u64)>,
    /// Per-unit witness roots in log order (one `wit_root` per `apply_one`,
    /// applied or rejected). `Batch::from_applied` takes the last
    /// `applied.len()` entries as the batch trace.
    pub wit_trace: Vec<String>,
    /// Leaf counts paired with `wit_trace` (one per `apply_one`, in order).
    /// Lets dispute predicates prove witness-tree non-membership at any unit.
    pub wit_count_trace: Vec<u32>,
    /// Full witness leaf sets paired with `wit_trace` (one per `apply_one`,
    /// in order). `Batch::from_applied` takes the last `applied.len()`
    /// entries as `leaf_trace` DA for watcher proof building. Unbounded
    /// per-unit growth is capped by pruning alongside `wit_trace`.
    pub wit_leaf_trace: Vec<Vec<String>>,
    /// Reentrancy guard: set while `liquidate` is mid-flight so a nested
    /// call (force-sell from `place`) returns no fills without touching
    /// state. Cleared on every exit path including `Err`.
    liquidating: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecEvent {
    Applied {
        unit: UnitId,
        seq: Seq,
        fills: Vec<Fill>,
        status: ExecStatus,
    },
    Rejected {
        unit: UnitId,
        reason: RejectReason,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RejectReason {
    BadSig,
    BadAccount,
    DuplicateClientSeq,
    DuplicateDeposit,
    /// Deposit op referencing an AA unit not in the batch's on-chain deposit set.
    UnbackedDeposit,
    DuplicateNonce,
    Risk,
    Book(BookError),
    Insufficient,
    NotFound,
    NotLiquidatable,
    /// Vote/FinalizeProposal referencing an unknown proposal id.
    NoProposal,
    NotBonded,
    AlreadyBonded,
    Unbonding,
    SlashNotEligible,
    /// Commit-reveal v2: commit unknown/expired/consumed, hash mismatch,
    /// wrong account, or reveal missing its Commit parent (doc 03 §2.3.3).
    BadCommit,
}
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ExecError {
    #[error("bad signature")]
    BadSig,
    #[error("dag: {0}")]
    Dag(#[from] DagError),
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}
/// One pro-rata share of an ADL residual hole (#9): non-last counterparties
/// take `hole * delta / total` floored, the last takes the remainder — both
/// capped at that counterparty's own positive delta so no debit ever exceeds
/// what it gained. Free of state so the unit test pins the arithmetic.
fn adl_haircut_share(hole: i128, delta: i128, total: i128, is_last: bool) -> i128 {
    let raw = if is_last { hole } else { hole * delta / total };
    raw.min(delta)
}

impl Engine {
    pub fn new() -> Self {
        Self {
            dag: Dag::new(),
            state: ChainState::new(),
            log: Vec::new(),
            sig_verifier: SigVerifier::new(),
            store_dir: None,
            validating: false,
            pending_gov_wal: Vec::new(),
            wit_trace: Vec::new(),
            wit_count_trace: Vec::new(),
            wit_leaf_trace: Vec::new(),
            liquidating: false,
        }
    }

    /// Restart recovery (gap 11): load the newest `chainstate.<height>.snap`
    /// from `dir` (genesis state when none exists), then max-merge the
    /// gov-nonce WAL over it. The DAG and event log restart empty — finalized
    /// batches newer than the snapshot must be replayed via
    /// `Batch::validate_against` by the caller, exactly as the design's
    /// recovery sequence prescribes.
    pub fn load_or_genesis(dir: &Path) -> std::io::Result<Self> {
        let mut state = match persist::load_latest(dir)? {
            Some((_, s)) => s,
            None => ChainState::new(),
        };
        let journal = GovNonceJournal::open(dir)?;
        for GovNonceRecord { account, nonce, .. } in journal.read_all()? {
            let cur = state.seen_gov_nonces.get(&account).copied().unwrap_or(0);
            if nonce > cur {
                state.seen_gov_nonces.insert(account, nonce);
            }
        }
        Ok(Self {
            dag: Dag::new(),
            state,
            log: Vec::new(),
            sig_verifier: SigVerifier::new(),
            store_dir: Some(dir.to_path_buf()),
            validating: false,
            pending_gov_wal: Vec::new(),
            wit_trace: Vec::new(),
            wit_count_trace: Vec::new(),
            wit_leaf_trace: Vec::new(),
            liquidating: false,
        })
    }

    /// Write a snapshot of the current state to the store dir. No-op for
    /// ephemeral engines. Compacts the gov-nonce WAL into the same atomic
    /// checkpoint.
    pub fn flush_snapshot(&mut self) -> std::io::Result<Option<PathBuf>> {
        let Some(dir) = self.store_dir.clone() else {
            return Ok(None);
        };
        persist::save_snapshot(&dir, &self.state).map(Some)
    }

    /// Cadence wrapper: flush every [`persist::SNAPSHOT_EVERY`] heights.
    /// Returns whether a snapshot was written this call.
    pub fn maybe_flush_snapshot(&mut self) -> std::io::Result<bool> {
        if self.store_dir.is_none()
            || self.state.height == 0
            || self.state.height % persist::SNAPSHOT_EVERY != 0
        {
            return Ok(false);
        }
        self.flush_snapshot()?;
        Ok(true)
    }

    /// Durably persist every gov-withdraw nonce buffered since the last
    /// flush, then clear the buffer. Called at batch commit
    /// (`Batch::from_applied`) so an abandoned/uncommitted batch never burns
    /// nonces on disk (H2). No-op on ephemeral or validating engines.
    pub fn flush_gov_wal(&mut self) -> std::io::Result<()> {
        let Some(dir) = self.store_dir.clone() else {
            self.pending_gov_wal.clear();
            return Ok(());
        };
        if self.validating {
            self.pending_gov_wal.clear();
            return Ok(());
        }
        if self.pending_gov_wal.is_empty() {
            return Ok(());
        }
        let j = GovNonceJournal::open(&dir)?;
        for (account, nonce) in &self.pending_gov_wal {
            j.append(*account, *nonce, self.state.height)?;
        }
        self.pending_gov_wal.clear();
        Ok(())
    }

    /// WAL-checkpoint the gov-nonce journal once it exceeds the compaction
    /// threshold. Called after batch commits; cheap no-op below 1 MB.
    pub fn compact_journal_if_needed(&mut self) -> std::io::Result<()> {
        let Some(dir) = self.store_dir.clone() else {
            return Ok(());
        };
        let j = GovNonceJournal::open(&dir)?;
        if j.should_compact() {
            j.compact(&self.state.seen_gov_nonces)?;
        }
        Ok(())
    }

    pub fn ingest(&mut self, unit: Unit) -> Result<Vec<ExecEvent>, ExecError> {
        // Hash exactly once: the signature is verified against this id and
        // the same id is handed to the DAG, skipping its recomputation.
        let id = unit_id(&unit);
        if !self.sig_verifier.verify_by_id(&unit, &id) {
            return Err(ExecError::BadSig);
        }
        self.dag.insert_verified(unit, id)?;
        Ok(self.apply_ready())
    }

    pub fn apply_ready(&mut self) -> Vec<ExecEvent> {
        let ready = self.dag.ready_linearized();
        let mut out = Vec::new();
        for id in ready {
            let ev = self.apply_one(id);
            self.log.push(ev.clone());
            out.push(ev);
        }
        out
    }

    /// Drop log entries for units already settled in a batch. Call after
    /// cutting a batch so the log stays bounded without losing pending events.
    pub fn prune_below(&mut self, unit_ids: &[UnitId]) {
        let gone: HashSet<UnitId> = unit_ids.iter().copied().collect();
        let before = self.log.len();
        self.log.retain(|e| match e {
            ExecEvent::Applied { unit, .. } => !gone.contains(unit),
            ExecEvent::Rejected { unit, .. } => !gone.contains(unit),
        });
        // wit_trace stays aligned with the log (one entry per apply_one, in
        // order): batches commit oldest-first, so drop the same count from
        // the front.
        let dropped = before.saturating_sub(self.log.len());
        if dropped > 0 {
            let n = dropped.min(self.wit_trace.len());
            self.wit_trace.drain(..n);
            let m = dropped.min(self.wit_count_trace.len());
            self.wit_count_trace.drain(..m);
            let l = dropped.min(self.wit_leaf_trace.len());
            self.wit_leaf_trace.drain(..l);
        }
    }

    /// Promote log entries for units contained in a FINALIZED batch height
    /// from Optimistic to Final (local node view; the AA finalize event is
    /// observed off-engine). Returns the number of promoted entries. Log
    /// statuses are not part of state_root, so replay determinism is intact.
    pub fn promote_finalized(&mut self, unit_ids: &[UnitId]) -> usize {
        let fin: HashSet<UnitId> = unit_ids.iter().copied().collect();
        let mut n = 0;
        for e in self.log.iter_mut() {
            if let ExecEvent::Applied { unit, status, .. } = e {
                if *status == ExecStatus::Optimistic && fin.contains(unit) {
                    *status = ExecStatus::Final;
                    n += 1;
                }
            }
        }
        n
    }

    pub fn note_finalized(&mut self, root: [u8; 32], height: operp_types::Height) {
        self.state.note_finalized(root, height);
        // Step9: rotate the DAG EVICTION salt to
        // sha256(ORDERING_SALT_DOMAIN || finalized_root || epoch_le), where
        // epoch = height / ORDERING_EPOCH_UNITS. Deriving from (root, epoch)
        // — not the raw root — keeps eviction stable within an epoch and
        // forces rotation at epoch boundaries even if the same root were
        // re-finalized. The salt deliberately does NOT influence execution
        // order anymore (desalted, user-approved): `Dag::ready_linearized`
        // uses plain lex order; only orphan eviction stays salted.
        let epoch = (height / operp_types::ORDERING_EPOCH_UNITS).to_le_bytes();
        let mut buf = Vec::with_capacity(operp_types::ORDERING_SALT_DOMAIN.len() + 64);
        buf.extend_from_slice(operp_types::ORDERING_SALT_DOMAIN);
        buf.extend_from_slice(&root);
        buf.extend_from_slice(&epoch);
        let salt = operp_types::sha256(&buf);
        self.dag.set_eviction_salt(salt);
    }

    fn apply_one(&mut self, id: UnitId) -> ExecEvent {
        let unit = self.dag.get(id).cloned().expect("unit in dag");
        // seq counts only APPLIED units: dispatch runs against the current
        // counter and it advances solely on success, so a rejected unit never
        // consumes a sequence number (deterministic across replays — every
        // validator rejects identically). last_unit updates either way.
        let event = match self.dispatch(id, self.state.seq, &unit.op) {
            Ok(fills) => {
                let seq = self.state.seq;
                self.state.seq += 1;
                ExecEvent::Applied {
                    unit: id,
                    seq,
                    fills,
                    status: ExecStatus::Optimistic,
                }
            }
            Err(reason) => ExecEvent::Rejected { unit: id, reason },
        };
        self.dag.mark_executed(id);
        self.state.last_unit = id;
        self.wit_trace.push(operp_state::wit_root(&self.state));
        let leaves = operp_state::wit_leaves(&self.state);
        self.wit_count_trace.push(leaves.len() as u32);
        self.wit_leaf_trace.push(leaves);
        event
    }

    fn dispatch(&mut self, id: UnitId, seq: Seq, op: &Op) -> Result<Vec<Fill>, RejectReason> {
        match op {
            Op::Place {
                account,
                market,
                side,
                typ,
                tif,
                price,
                qty,
                client_seq,
                isolated,
                margin,
            } => self.place(
                *account,
                *market,
                *side,
                *typ,
                *tif,
                *price,
                *qty,
                *client_seq,
                id,
                seq,
                *isolated,
                *margin,
            ),
            Op::Cancel { account, order_id } => self.cancel(*account, *order_id),
            Op::Deposit {
                account,
                addr,
                amount,
                aa_unit,
            } => self.deposit(*account, addr, *amount, *aa_unit),
            Op::Withdraw {
                account,
                amount,
                nonce,
            } => self.withdraw(*account, *amount, *nonce),
            Op::Liquidate {
                caller,
                target,
                market,
            } => self.liquidate(id, seq, *caller, *target, *market),
            Op::ReportPrice {
                oracle,
                market,
                price,
            } => {
                // Bond gate: only PERP-bonded accounts may report prices;
                // unknown markets have no book to index either.
                if !self.state.oracle_bonds.contains_key(oracle) {
                    return Err(RejectReason::BadAccount);
                }
                if !self.state.markets.contains_key(market) {
                    return Err(RejectReason::NotFound);
                }
                // Spot-only markets have no oracle feed: same signal as
                // unknown markets so watchers need no new error path.
                if self
                    .state
                    .markets
                    .get(market)
                    .map(|p| p.spot_only)
                    .unwrap_or(false)
                {
                    return Err(RejectReason::NotFound);
                }
                // Doc 06 §2.7: pass the pre-increment global seq so TWAP
                // samples carry intra-height ordering without wall clocks.
                let caller_seq = self.state.seq;
                self.state
                    .apply_report(*oracle, *market, *price, caller_seq)
                    .map_err(map_state)?;
                Ok(Vec::new())
            }
            Op::GovDeposit {
                account,
                addr,
                amount,
                aa_unit,
            } => self.gov_deposit(*account, addr, *amount, *aa_unit),
            Op::GovWithdraw {
                account,
                amount,
                nonce,
            } => self.gov_withdraw(*account, *amount, *nonce),
            Op::CreateMarket {
                creator,
                symbol,
                tick_size,
                im_bps,
                mm_bps,
                taker_fee_bps,
                keeper_reward_bps,
                spot_only,
                funding_rate,
                usd_per_unit,
                funding_cap_bps,
            } => self.create_market(
                *creator,
                *symbol,
                *tick_size,
                *im_bps,
                *mm_bps,
                *taker_fee_bps,
                *keeper_reward_bps,
                *spot_only,
                *funding_rate,
                *usd_per_unit,
                *funding_cap_bps,
            ),
            Op::CreateProposal {
                creator,
                market,
                key,
                value,
            } => self.create_proposal(*creator, *market, *key, *value, seq),
            Op::Vote {
                voter,
                proposal_id,
                approve,
            } => self.vote(*voter, *proposal_id, *approve, seq),
            Op::FinalizeProposal {
                caller,
                proposal_id,
            } => self.finalize_proposal(*caller, *proposal_id, seq),
            Op::StakeOracle { account } => self.stake_oracle(*account),
            Op::UnstakeOracle { account } => self.unstake_oracle(*account),
            Op::SlashOracle {
                challenger,
                target,
                market,
            } => self.slash_oracle(*challenger, *target, *market),
            Op::Commit {
                account,
                commit,
                ttl_height,
            } => self.commit_op(id, *account, *commit, *ttl_height),
            Op::Reveal {
                account,
                commit_ref,
                op,
                salt,
            } => self.reveal_op(id, *account, *commit_ref, op, salt),
            Op::UpdateExternalPrice {
                source,
                market,
                price,
                source_id,
            } => {
                let caller_seq = self.state.seq;
                self.update_external_price(*source, *market, *price, *source_id, caller_seq)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn place(
        &mut self,
        account: AccountId,
        market: operp_types::MarketId,
        side: Side,
        typ: OrderType,
        tif: TimeInForce,
        price: operp_types::Price,
        qty: Qty,
        client_seq: u64,
        unit: UnitId,
        seq: Seq,
        isolated: bool,
        margin: u64,
    ) -> Result<Vec<Fill>, RejectReason> {
        let last = self
            .state
            .seen_client_seq
            .get(&account)
            .copied()
            .unwrap_or(0);
        let ok_seq = if last == 0 {
            client_seq == 1
        } else {
            client_seq == last + 1
        };
        if !ok_seq {
            return Err(RejectReason::DuplicateClientSeq);
        }

        // Intake overflow guards (DoS): qty must fit i64 for positions, and the
        // price*qty product must fit i128 before signed notional math (blocks
        // u64::MAX-style inputs that would wrap notional_usd / bps).
        if qty > i64::MAX as u64 {
            return Err(RejectReason::Risk);
        }
        let mark = *self.state.marks.get(&market).unwrap_or(&0);
        let px_for_notional = if typ == OrderType::Limit && price != 0 {
            price
        } else {
            mark
        };
        // Worst-case bound: estimate notional at max(limit/mark, mark) for
        // both sides. Previously Ask used max but Bid used mark alone, under-
        // estimating margin for Market Bids. Also gate unknown market.
        match self.state.markets.get(&market) {
            Some(p) if !p.delisted => {}
            _ => return Err(RejectReason::Risk),
        }
        // Live-order count cap across every book: applies even to an IOC
        // that would never rest — otherwise a spam loop of IOC places is
        // unbounded even though resting state stays bounded.
        let live_count = self
            .state
            .books
            .values()
            .map(|b| b.live_orders().filter(|o| o.account == account).count())
            .sum::<usize>();
        if live_count >= MAX_LIVE_ORDERS_PER_ACCOUNT {
            return Err(RejectReason::Risk);
        }
        // Signed prices: margin must cover the larger *magnitude* — a plain
        // max() would let a short at -100 post margin against mark -1.
        let px_est = if px_for_notional.abs() >= mark.abs() {
            px_for_notional
        } else {
            mark
        };
        // unsigned_abs is exact (no MIN-wrap): negative estimates feed the
        // guard as magnitudes.
        let px_abs: u128 = px_est.unsigned_abs() as u128;
        if px_abs
            .checked_mul(qty as u128)
            .map(|n| n > i128::MAX as u128)
            .unwrap_or(true)
        {
            return Err(RejectReason::Risk);
        }
        // Tick alignment: limit orders must sit on the market's price grid.
        // Market orders (price = 0) are exempt by construction; unknown or
        // delisted markets were rejected above.
        if typ == OrderType::Limit && price != 0 {
            if let Some(p) = self.state.markets.get(&market) {
                if p.tick_size != 0 && price % p.tick_size != 0 {
                    return Err(RejectReason::Risk);
                }
            }
        }
        // Funding band (#7): an encoded rate beyond ±100% is a broken feed,
        // not a market — same comparison as update_external_price. Applies
        // to closes as well as opens: every margin/OI figure prices off
        // usd_per_unit, so an out-of-band rate can only promise the
        // insurance fund money the order never risked. A market order's
        // price of 0 is far out of band on purpose — funding-rate books
        // trade explicit rates only.
        if self.state.market_params(market).funding_rate && funding_rate_bps(price).abs() > 10_000 {
            return Err(RejectReason::Risk);
        }

        let snap = {
            let acct = self.state.accounts.get(&account);
            match acct {
                Some(a) => a.snapshot(&self.state.marks, &self.state.markets),
                None => operp_account::Account::new(account)
                    .snapshot(&self.state.marks, &self.state.markets),
            }
        };
        let pos_qty = self
            .state
            .accounts
            .get(&account)
            .and_then(|a| a.positions.get(&market))
            .map(|p| p.qty)
            .unwrap_or(0);
        // Mode gate: an account's exposure to one market has one mode —
        // the position's if it exists, else its first live order's. A
        // mismatched order would let cross losses leak into a bucket (or
        // vice versa), so it is rejected before any risk math.
        let pos_mode = if qty != 0 {
            self.state
                .accounts
                .get(&account)
                .and_then(|a| a.positions.get(&market))
                .map(|p| p.isolated)
        } else {
            None
        };
        let order_mode = self.own_live_order_mode(account, market);
        if let Some(m) = pos_mode.or(order_mode) {
            if m != isolated {
                return Err(RejectReason::Risk);
            }
        }
        // Reduce-only gate: isolated positions are judged on their own
        // bucket risk, cross positions on the pooled snapshot as today.
        let reduce_only = if isolated {
            self.state
                .accounts
                .get(&account)
                .map(|a| a.isolated_risk(market, &self.state.marks, &self.state.markets))
                .map(|r| r.reduce_only)
                .unwrap_or(false)
        } else {
            snap.reduce_only
        };
        if reduce_only {
            let reducing = match side {
                Side::Bid => pos_qty < 0,
                Side::Ask => pos_qty > 0,
            };
            if !reducing {
                return Err(RejectReason::Risk);
            }
        }

        // Open-quantity IM gate: the part of the order that closes existing
        // position is reduce-exempt; only the remainder that opens or flips
        // past zero must post initial margin. A flat-out direction check
        // would let undercollateralized accounts flip positions for free.
        let signed = match side {
            Side::Bid => qty as i64,
            Side::Ask => -(qty as i64),
        };
        let open_qty = if pos_qty != 0 && signed.signum() != pos_qty.signum() {
            signed + pos_qty.abs().min(signed.abs()) * pos_qty.signum()
        } else {
            signed
        };
        // Margin-field rules (before the open block: they apply to pure
        // reduces too). Cross orders carry no margin; an isolated pure
        // reduce has no opening exposure to back, so escrow there is
        // meaningless and rejected.
        if margin != 0 && !isolated {
            return Err(RejectReason::Risk);
        }
        if isolated && open_qty == 0 && margin != 0 {
            return Err(RejectReason::Risk);
        }
        if open_qty != 0 {
            // Unmarked-market hole: with no mark and no limit price, px_est
            // is 0, so the IM estimate below is 0 and a zero-collateral
            // account walks straight through the gate.
            if px_est == 0 {
                return Err(RejectReason::Risk);
            }
            let params = self.state.market_params(market);
            // Funding-rate markets price money off the listing multiplier:
            // the encoded book price there is a rate, not dollars.
            let open_notional = match params.funding_rate {
                true => funding_notional_usd(open_qty.unsigned_abs(), params.usd_per_unit),
                false => notional_usd(open_qty.unsigned_abs(), px_est),
            };
            // An opening order must carry real notional; a zero-notional
            // *reduce* order may still close an unmarked position.
            if open_notional == 0 {
                return Err(RejectReason::Risk);
            }
            let extra_im = bps(open_notional, params.im_bps);
            // Funding-rate opens must also cover this order's own worst-case
            // peg payout (notional × cap), not just im_bps: the peg pays
            // rate-cash peer-to-peer up to the cap regardless of the
            // encoded-price distance.
            let extra_im = if params.funding_rate {
                extra_im.max(
                    funding_notional_usd(open_qty.unsigned_abs(), params.usd_per_unit)
                        * i128::from(params.funding_cap_bps)
                        / 10_000,
                )
            } else {
                extra_im
            };
            let resting = self.resting_open_im(account);
            if isolated {
                // Isolated floor: the bucket must cover this order's own IM
                // (at least 1 USD unit — a zero bucket would be free
                // exposure), fit inside spendable collateral, and leave the
                // cross pool healthy after escrow. No MIN_OPEN_EQUITY: the
                // margin floor is its equivalent.
                if i128::from(margin) < extra_im.max(1) {
                    return Err(RejectReason::Risk);
                }
                if i128::from(margin) > self.collateral_of(account) {
                    return Err(RejectReason::Risk);
                }
                if snap.equity - i128::from(margin) < snap.im + resting {
                    return Err(RejectReason::Risk);
                }
            } else {
                // Equity must cover position IM + the IM reserved for resting
                // opening orders + this order's own opening IM. `snapshot` only
                // sees booked positions, not the margin pending openings will
                // demand once they fill; the order being placed is not in the
                // book yet, so it is not double-counted. Reduce-only orders
                // cannot grow exposure, so they are not subject to this check.
                if snap.equity < snap.im + resting + extra_im {
                    return Err(RejectReason::Risk);
                }
                if snap.equity < MIN_OPEN_EQUITY {
                    return Err(RejectReason::Risk);
                }
            }
            // Funding-rate open-interest cap: worst-case peg payout
            // (notional × market cap) must fit inside the insurance fund at
            // all times, so a burst of openings can never promise more than
            // the fund can pay. A non-positive fund rejects every opening.
            // Runs for both margin modes, after the mode's own gates.
            if params.funding_rate {
                let oi = self.funding_open_interest(market, account, open_qty);
                let worst_payout = funding_notional_usd(oi, params.usd_per_unit)
                    * i128::from(params.funding_cap_bps)
                    / 10_000;
                let insurance = self
                    .state
                    .accounts
                    .get(&INSURANCE_ACCOUNT)
                    .map(|a| a.collateral.max(0))
                    .unwrap_or(0);
                if worst_payout > insurance {
                    return Err(RejectReason::Risk);
                }
            }
        }

        // Escrow: margin leaves collateral while the order lives in the
        // book; it returns via fills (bucket), cancel, or the unfilled
        // remainder. An escrowed own maker is rejected outright
        // (SelfTrade::Reject): canceling it would refund its margin_left
        // to collateral inside this same unit — a cash leg no fill
        // predicate can model, so the dispute's exact identity would
        // false-verdict the honest batch.
        let escrow = if isolated { i128::from(margin) } else { 0 };
        // Matching may mutate earlier makers before a later fill fails.
        // Stage book, escrow, account fills and refunds together so an Err
        // discards the entire candidate state.
        let mut candidate = self.state.clone();
        if escrow != 0 {
            candidate.account_mut(account).collateral -= escrow;
        }
        let oid = order_id(account, market, client_seq);
        let order = Order {
            id: oid,
            account,
            market,
            side,
            typ,
            tif,
            price,
            qty,
            remaining: qty,
            seq,
            isolated,
            margin_left: if isolated { margin } else { 0 },
        };
        let mut result = match candidate
            .book_mut(market)
            .submit_with(order, operp_book::SelfTrade::Reject)
        {
            Ok(r) => r,
            Err(e) => return Err(RejectReason::Book(e)),
        };
        // Funding-rate markets realize rate-cash, not price-diff PnL; tag
        // the fills so the dispute AA picks the funding identity (book
        // submit defaults to kind 0).
        if candidate.market_params(market).funding_rate {
            for f in &mut result.fills {
                f.kind = 1;
            }
        }
        for fill in &result.fills {
            candidate.apply_fill_pair(fill).map_err(map_acct)?;
        }
        // Refunds: STP-canceled makers' escrow and the taker's unfilled
        // remainder (when it did not rest) return to collateral.
        for (acct, amt) in &result.refunds {
            if *amt > 0 {
                candidate.account_mut(*acct).collateral += i128::from(*amt);
            }
        }
        if !result.taker_resting && result.taker_margin_left > 0 {
            candidate.account_mut(account).collateral += i128::from(result.taker_margin_left);
        }
        // Force-sell: any fill party still liquidatable after this fill is
        // closed in the same unit (book IOC, then ADL inside `liquidate`).
        // The user fill is already applied, so a nested liquidation Err is
        // ignored — never fail the place over it. Returned fills join this
        // unit's fill list; fill_math bounces a multi-fill unit, so they
        // must not become a second op.
        let mut fills = result.fills;
        candidate.seen_client_seq.insert(account, client_seq);
        self.state = candidate;
        let extra = self.force_sell_fill_parties(&fills, unit, seq);
        fills.extend(extra);
        Ok(fills)
    }

    /// Force-sell every fill party that is still liquidatable after a user
    /// fill, in the same unit. The other fill party is the liquidation
    /// caller; insurance is never a caller or target. `liquidate` does the
    /// book IOC first, then ADL onto opposite positions — no insurance
    /// buyer anywhere. Err (e.g. the snapshot flipped after the claw) is
    /// ignored: the user fill already applied and there is no retry.
    fn force_sell_fill_parties(&mut self, fills: &[Fill], unit: UnitId, seq: Seq) -> Vec<Fill> {
        let mut extra = Vec::new();
        for fill in fills {
            for (target, caller) in [(fill.taker, fill.maker), (fill.maker, fill.taker)] {
                if target == caller || target == INSURANCE_ACCOUNT {
                    continue;
                }
                // Same liquidatable fork as `liquidate`: an isolated
                // position is judged on its bucket risk, everything else
                // on the pooled account snapshot.
                let liquidatable = match self
                    .state
                    .accounts
                    .get(&target)
                    .and_then(|a| a.positions.get(&fill.market))
                {
                    Some(p) if p.isolated => self
                        .state
                        .accounts
                        .get(&target)
                        .map(|a| {
                            a.isolated_risk(fill.market, &self.state.marks, &self.state.markets)
                                .liquidatable
                        })
                        .unwrap_or(false),
                    _ => self
                        .state
                        .accounts
                        .get(&target)
                        .map(|a| {
                            a.snapshot(&self.state.marks, &self.state.markets)
                                .liquidatable
                        })
                        .unwrap_or(false),
                };
                if !liquidatable {
                    continue;
                }
                if let Ok(fs) = self.liquidate(unit, seq, caller, target, fill.market) {
                    extra.extend(fs);
                }
            }
        }
        extra
    }

    /// First live order of `account` on `books[market]`'s margin mode, if
    /// any: orders from the same account on one market must share a mode.
    fn own_live_order_mode(&self, account: AccountId, market: MarketId) -> Option<bool> {
        self.state
            .books
            .get(&market)
            .and_then(|b| b.live_orders().find(|o| o.account == account))
            .map(|o| o.isolated)
    }

    fn collateral_of(&self, account: AccountId) -> Usd {
        self.state
            .accounts
            .get(&account)
            .map(|a| a.collateral)
            .unwrap_or(0)
    }

    /// Funding-rate open interest for `market`: positive position qty
    /// across all accounts, plus this order's opening qty, plus the
    /// opening remaining qty of this account's resting orders on the market
    /// (bids above the short they reduce, asks above the long they reduce).
    /// Over-counting resting qty is intentional — the cap is a worst case.
    fn funding_open_interest(&self, market: MarketId, account: AccountId, open_qty: i64) -> Qty {
        let mut oi: u128 = 0;
        for a in self.state.accounts.values() {
            if let Some(pos) = a.positions.get(&market) {
                if pos.qty > 0 {
                    oi += pos.qty as u128;
                }
            }
        }
        oi += open_qty.unsigned_abs() as u128;
        if let Some(book) = self.state.books.get(&market) {
            let pos_qty = self
                .state
                .accounts
                .get(&account)
                .and_then(|a| a.positions.get(&market))
                .map(|p| p.qty)
                .unwrap_or(0);
            let mut bid_qty: u128 = 0;
            let mut ask_qty: u128 = 0;
            for o in book.live_orders().filter(|o| o.account == account) {
                match o.side {
                    Side::Bid => bid_qty += o.remaining as u128,
                    Side::Ask => ask_qty += o.remaining as u128,
                }
            }
            let short = (-pos_qty).max(0) as u128;
            let long = pos_qty.max(0) as u128;
            oi += bid_qty.saturating_sub(short);
            oi += ask_qty.saturating_sub(long);
        }
        // Positions fit i64 by intake guards; clamp instead of trusting the
        // accumulation above.
        oi.min(i64::MAX as u128) as Qty
    }

    /// IM that the account's currently resting orders will demand once they
    /// fill and open (or add to) positions. `snapshot` cannot see these —
    /// booked positions only materialize at fill time — so `place` reserves
    /// them on top. Per market, only the larger side can ultimately be
    /// open (fills net the book against the position), so reserve
    /// `max(bid_im, ask_im)`, not the sum.
    fn resting_open_im(&self, account: AccountId) -> Usd {
        let mut total: Usd = 0;
        for (market, book) in &self.state.books {
            let mut bid_qty: i64 = 0;
            let mut ask_qty: i64 = 0;
            let mut bid_notional: Usd = 0;
            let mut ask_notional: Usd = 0;
            for o in book
                .live_orders()
                .filter(|o| o.account == account && !o.isolated)
            {
                // Funding-rate books rest at encoded rates: their margin is
                // the multiplier notional, not a dollar price. Isolated
                // orders are skipped: their margin already left collateral
                // at place time — counting it here would double-reserve.
                let n = match self.state.markets.get(market) {
                    Some(p) if p.funding_rate => funding_notional_usd(o.remaining, p.usd_per_unit),
                    _ => {
                        let px = if o.price != 0 {
                            o.price
                        } else {
                            self.state.marks.get(market).copied().unwrap_or(0)
                        };
                        notional_usd(o.remaining, px)
                    }
                };
                match o.side {
                    Side::Bid => {
                        bid_qty += o.remaining as i64;
                        bid_notional += n;
                    }
                    Side::Ask => {
                        ask_qty += o.remaining as i64;
                        ask_notional += n;
                    }
                }
            }
            if bid_qty == 0 && ask_qty == 0 {
                continue;
            }
            let pos_qty = self
                .state
                .accounts
                .get(&account)
                .and_then(|a| a.positions.get(market))
                .map(|p| p.qty)
                .unwrap_or(0);
            // Bids reduce only a short, asks reduce only a long: whichever
            // side's remaining qty exceeds what it can reduce opens.
            let bid_opens = bid_qty > (-pos_qty).max(0);
            let ask_opens = ask_qty > pos_qty.max(0);
            let im_bps = self.state.market_params(*market).im_bps;
            let bid_im = if bid_opens {
                bps(bid_notional, im_bps)
            } else {
                0
            };
            let ask_im = if ask_opens {
                bps(ask_notional, im_bps)
            } else {
                0
            };
            total += bid_im.max(ask_im);
        }
        total
    }

    fn cancel(&mut self, account: AccountId, order_id: OrderId) -> Result<Vec<Fill>, RejectReason> {
        // Cross-market lookup: order ids bind account+market+client_seq, so the
        // id alone identifies the market. books is bounded by listed markets.
        let market = self
            .state
            .books
            .iter()
            .find(|(_, book)| book.get(order_id).map(|o| o.account) == Some(account))
            .map(|(m, _)| *m)
            .ok_or(RejectReason::NotFound)?;
        let canceled = self
            .state
            .book_mut(market)
            .cancel(order_id)
            .map_err(RejectReason::Book)?;
        // Isolated escrow rides on the order: cancel returns its remainder.
        if canceled.margin_left > 0 {
            self.state.account_mut(account).collateral += i128::from(canceled.margin_left);
        }
        Ok(Vec::new())
    }

    fn deposit(
        &mut self,
        account: AccountId,
        addr: &str,
        amount: Usd,
        aa_unit: [u8; 32],
    ) -> Result<Vec<Fill>, RejectReason> {
        if self.state.seen_aa_units.contains_key(&aa_unit)
            || self.state.consumed_deposits.contains(&aa_unit)
        {
            return Err(RejectReason::DuplicateDeposit);
        }
        // Deposit must reference a real AA deposit event in this batch window;
        // the bool kind binds the endorsement to collateral, not PERP.
        if !self.state.deposits_allowed.contains(&(aa_unit, false)) {
            return Err(RejectReason::UnbackedDeposit);
        }
        // The withdrawal address must be a well-formed Obyte address: it is
        // the key of this account's AA-side merkle leaf.
        if !valid_obyte_addr(addr) {
            return Err(RejectReason::BadAccount);
        }
        // First deposit binds the address; rebinding to a different one would
        // orphan or duplicate the account's AA leaf.
        match self.state.aa_addresses.get(&account) {
            Some(bound) if bound != addr => return Err(RejectReason::BadAccount),
            Some(_) => {}
            None => {
                self.state.aa_addresses.insert(account, addr.to_string());
            }
        }
        self.state
            .account_mut(account)
            .credit(amount)
            .map_err(map_acct)?;
        self.state.seen_aa_units.insert(aa_unit, self.state.height);
        self.state.consumed_deposits.insert(aa_unit);
        Ok(Vec::new())
    }

    fn withdraw(
        &mut self,
        account: AccountId,
        amount: Usd,
        nonce: u64,
    ) -> Result<Vec<Fill>, RejectReason> {
        if self.state.withdrawals.contains_key(&(account, nonce)) {
            return Err(RejectReason::DuplicateNonce);
        }
        if self.state.withdrawals.len() >= WITHDRAWALS_CAP {
            return Err(RejectReason::Risk);
        }
        let marks = self.state.marks.clone();
        let params = self.state.markets.clone();
        self.state
            .account_mut(account)
            .debit(amount, &marks, &params)
            .map_err(map_acct)?;
        // Cumulative signed-withdrawal ledger committed as `W` in the AA
        // leaf: the vault AA enforces "this claim + prior claims <= W".
        *self.state.withdrawn_total.entry(account).or_insert(0) += amount;
        self.state.withdrawals.insert(
            (account, nonce),
            operp_state::Withdrawal {
                amount,
                pending: true,
                height: self.state.height,
            },
        );
        Ok(Vec::new())
    }

    /// Guarded entry — dispatch and force-sell both land here. A nested
    /// call (one made while another `liquidate` is mid-flight) returns no
    /// fills before touching any state, so an outer call's book submit,
    /// fills, and ADL never interleave with a second cascade. The flag is
    /// cleared on every exit path, `Err` included.
    fn liquidate(
        &mut self,
        unit: UnitId,
        seq: Seq,
        caller: AccountId,
        target: AccountId,
        market: operp_types::MarketId,
    ) -> Result<Vec<Fill>, RejectReason> {
        if self.liquidating {
            return Ok(Vec::new());
        }
        self.liquidating = true;
        let out = self.liquidate_inner(unit, seq, caller, target, market);
        self.liquidating = false;
        out
    }

    fn liquidate_inner(
        &mut self,
        unit: UnitId,
        seq: Seq,
        caller: AccountId,
        target: AccountId,
        market: operp_types::MarketId,
    ) -> Result<Vec<Fill>, RejectReason> {
        // Self-liquidation is banned: a keeper must not trigger its own account.
        if caller == target {
            return Err(RejectReason::BadAccount);
        }
        if target == INSURANCE_ACCOUNT || caller == INSURANCE_ACCOUNT {
            // Insurance fund never liquidates or is liquidated.
            return Err(RejectReason::NotLiquidatable);
        }
        let pos = self
            .state
            .accounts
            .get(&target)
            .and_then(|a| a.positions.get(&market))
            .cloned();
        // Isolation fork: an isolated position is liquidatable on its own
        // bucket risk (`isolated_risk`), a cross one on the pooled account
        // snapshot as today.
        let liquidatable = match &pos {
            Some(p) if p.isolated => self
                .state
                .accounts
                .get(&target)
                .map(|a| {
                    a.isolated_risk(market, &self.state.marks, &self.state.markets)
                        .liquidatable
                })
                .unwrap_or(false),
            _ => {
                self.state
                    .accounts
                    .get(&target)
                    .ok_or(RejectReason::NotFound)?
                    .snapshot(&self.state.marks, &self.state.markets)
                    .liquidatable
            }
        };
        if !liquidatable {
            return Err(RejectReason::NotLiquidatable);
        }
        let pos_qty = pos.as_ref().map(|p| p.qty).unwrap_or(0);
        let target_isolated_pos = pos.as_ref().map(|p| p.isolated).unwrap_or(false);
        if pos_qty == 0 {
            return Err(RejectReason::NotLiquidatable);
        }
        // Funding-rate markets close off-book at the external index: their
        // book prices are rates, so an IOC there would trade against a rate
        // ladder instead of unwinding dollars. No book submit, no mark write.
        if self
            .state
            .markets
            .get(&market)
            .map(|p| p.funding_rate)
            .unwrap_or(false)
        {
            return self.liquidate_funding_off_book(unit, seq, caller, target, market, pos_qty);
        }
        let side = if pos_qty > 0 { Side::Ask } else { Side::Bid };
        let qty = pos_qty.unsigned_abs();
        let oid = liq_order_id(unit);
        let order = Order {
            id: oid,
            account: target,
            market,
            side,
            typ: OrderType::Market,
            tif: TimeInForce::Ioc,
            price: 0,
            qty,
            remaining: qty,
            seq,
            isolated: false,
            margin_left: 0,
        };
        let result = self
            .state
            .book_mut(market)
            .submit(order)
            .map_err(RejectReason::Book)?;
        // Default self-trade policy: cancel-maker-continue (the target's
        // book must clear for the close to execute; kind 3's identity is
        // unchanged by this PR).
        let mut fills = result.fills;
        // Liquidation book fills carry the keeper reward, distinct from a
        // plain place (kind 0/1): the AA subtracts the reward on taker legs.
        for f in &mut fills {
            f.kind = 3;
        }
        for fill in &fills {
            // Invariant: AccountError from apply_fill_pair is unreachable here
            // by construction — the liquidation order's qty comes from the
            // target's i64 position at a u64 price, so qty·price fits i128 and
            // positions fit i64; its checked arithmetic cannot overflow.
            // Should it ever fire anyway, this unit would surface as Rejected
            // with partially-applied state; that is a documented known
            // limitation, not a handled case.
            self.state.apply_fill_pair(fill).map_err(map_acct)?;
        }
        // Escrow returns (#10): STP refunds and the liquidation IOC's
        // unfilled remainder are the target's own money — mirror place().
        for (acct, amt) in &result.refunds {
            if *amt > 0 {
                self.state.account_mut(*acct).collateral += i128::from(*amt);
            }
        }
        if !result.taker_resting && result.taker_margin_left > 0 {
            self.state.account_mut(target).collateral += i128::from(result.taker_margin_left);
        }
        let still = if target_isolated_pos {
            self.state
                .accounts
                .get(&target)
                .map(|a| {
                    a.isolated_risk(market, &self.state.marks, &self.state.markets)
                        .liquidatable
                })
                .unwrap_or(false)
        } else {
            self.state
                .accounts
                .get(&target)
                .map(|a| {
                    a.snapshot(&self.state.marks, &self.state.markets)
                        .liquidatable
                })
                .unwrap_or(false)
        };
        let remaining_pos = self
            .state
            .accounts
            .get(&target)
            .and_then(|a| a.positions.get(&market))
            .map(|p| p.qty)
            .unwrap_or(0);
        let mut keeper_paid = Usd::from(0u64);
        if still && remaining_pos != 0 {
            // ADL remainder: the book did not finish the close, so the
            // still-liquidatable remainder is walked onto opposite-sign
            // positions at the current mark — insurance is never the
            // buyer of last resort. Each take is a zero-sum kind-2 fill
            // (the dispute AA always bounces kind 2; no haircut formula
            // here). Candidates exhausted → the unsold qty stays:
            // negative collateral remains, the target is not credited,
            // nothing is printed.
            let mark = *self.state.marks.get(&market).unwrap_or(&0);
            let close_side = if remaining_pos > 0 {
                Side::Ask
            } else {
                Side::Bid
            };
            let mut remaining = remaining_pos.unsigned_abs();
            // Opposite-sign holders only, excluding the target and
            // insurance. Larger |qty| first, AccountId ascending on ties
            // (explicit tie-break keeps the order deterministic).
            let mut candidates: Vec<(AccountId, Qty)> = self
                .state
                .accounts
                .iter()
                .filter(|(id, a)| {
                    **id != target
                        && **id != INSURANCE_ACCOUNT
                        && a.positions
                            .get(&market)
                            .is_some_and(|p| p.qty.signum() == -remaining_pos.signum())
                })
                .map(|(id, a)| (*id, a.positions[&market].qty.unsigned_abs()))
                .collect();
            candidates.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            let target_isolated = self
                .state
                .accounts
                .get(&target)
                .and_then(|a| a.positions.get(&market))
                .map(|p| p.isolated)
                .unwrap_or(false);
            for (maker_acct, maker_qty) in candidates {
                if remaining == 0 {
                    break;
                }
                let take = remaining.min(maker_qty);
                if take == 0 {
                    continue;
                }
                let fill = Fill {
                    taker_id: oid,
                    maker_id: OrderId([0u8; 32]),
                    taker: target,
                    maker: maker_acct,
                    market,
                    price: mark,
                    qty: take,
                    seq,
                    taker_side: close_side,
                    taker_post: 0,
                    maker_post: 0,
                    taker_isolated: target_isolated,
                    maker_isolated: false,
                    kind: 2,
                };
                self.state.apply_fill_pair(&fill).map_err(map_acct)?;
                fills.push(fill);
                remaining -= take;
            }
        }
        // Keeper reward: bps of filled notional, seized from the
        // liquidatee's own collateral — insurance never funds the reward.
        // A target with no positive collateral leaves the keeper with
        // nothing.
        for f in &fills {
            let keeper_bps = self.state.market_params(market).keeper_reward_bps;
            keeper_paid += bps(notional_usd(f.qty, f.price), keeper_bps);
        }
        if keeper_paid > 0 {
            // Realized PnL settles into collateral, so the target's spendable
            // balance is just its collateral.
            let bal = self
                .state
                .accounts
                .get(&target)
                .map(|a| a.collateral)
                .unwrap_or(0);
            let pay = keeper_paid.min(bal.max(0));
            if pay > 0 {
                if let Some(a) = self.state.accounts.get_mut(&target) {
                    a.collateral -= pay;
                }
                self.state
                    .account_mut(caller)
                    .credit(pay)
                    .map_err(map_acct)?;
            }
        }
        Ok(fills)
    }

    /// Funding-rate liquidation, off-book: close the target at the external
    /// index (mark as fallback), ADL the closed qty onto opposite-sign
    /// positions, then positive-PnL counterparties take a pro-rata haircut
    /// of any residual hole — zero-sum, insurance untouched. A hole they
    /// cannot cover stays on the account: collateral is never printed.
    /// Keeper reward is seized from the target afterwards.
    /// Returns synthetic fills for the event log (state is already applied).
    fn liquidate_funding_off_book(
        &mut self,
        unit: UnitId,
        seq: Seq,
        caller: AccountId,
        target: AccountId,
        market: MarketId,
        pos_qty: i64,
    ) -> Result<Vec<Fill>, RejectReason> {
        let usd = self.state.market_params(market).usd_per_unit;
        // Price: fresh external index; fall back to a non-zero mark when the
        // feed is dead; both missing means there is nothing to close at.
        let price = match self.state.fresh_external_index(market) {
            Some(p) => p,
            None => match self.state.marks.get(&market).copied() {
                Some(m) if m != 0 => m,
                _ => return Err(RejectReason::NotLiquidatable),
            },
        };
        let abs_qty = pos_qty.unsigned_abs();
        // Smallest close (1..=abs_qty) whose simulated fill leaves the
        // target not liquidatable; none qualifies → full close.
        let mut lo: u64 = 1;
        let mut hi: u64 = abs_qty;
        let mut dq: u64 = abs_qty;
        let close_side = if pos_qty > 0 { Side::Ask } else { Side::Bid };
        while lo <= hi {
            let mid = lo + (hi - lo) / 2;
            let qualifies = self
                .state
                .accounts
                .get(&target)
                .cloned()
                .map(|mut sim| {
                    let target_isolated = self
                        .state
                        .accounts
                        .get(&target)
                        .and_then(|a| a.positions.get(&market))
                        .map(|p| p.isolated)
                        .unwrap_or(false);
                    sim.apply_fill(
                        close_side,
                        true,
                        price,
                        mid,
                        market,
                        Some(usd),
                        0,
                        target_isolated,
                    )
                    .is_ok()
                        && !if target_isolated {
                            // Isolated: the simulated close must restore the
                            // bucket's own health, not the cross snapshot's.
                            sim.isolated_risk(market, &self.state.marks, &self.state.markets)
                                .liquidatable
                        } else {
                            sim.snapshot(&self.state.marks, &self.state.markets)
                                .liquidatable
                        }
                })
                .unwrap_or(false);
            if qualifies {
                dq = mid;
                if mid == 1 {
                    break;
                }
                hi = mid - 1;
            } else {
                lo = mid + 1;
            }
        }
        // ADL candidates: opposite-sign positions, excluding the target and
        // insurance. Deterministic order: close-price unrealized rate cash
        // desc, then notional/equity desc, then AccountId asc.
        let mut cps: Vec<(AccountId, i64, Usd)> = Vec::new();
        for (id, a) in &self.state.accounts {
            if *id == target || *id == INSURANCE_ACCOUNT {
                continue;
            }
            if let Some(p) = a.positions.get(&market) {
                if p.qty != 0 && p.qty.signum() == -pos_qty.signum() {
                    let unrealized = funding_rate_cash(
                        p.qty,
                        funding_rate_bps(price) - funding_rate_bps(p.entry_price),
                        usd,
                    );
                    cps.push((*id, p.qty, unrealized));
                }
            }
        }
        cps.sort_by(|a, b| {
            b.2.cmp(&a.2)
                .then_with(|| {
                    let ratio = |id: AccountId, q: Qty| {
                        let e = self
                            .state
                            .accounts
                            .get(&id)
                            .map(|x| {
                                // Isolated cp positions rank on their own
                                // bucket equity; cross ones on the pooled
                                // snapshot as today.
                                let cp_isolated = x
                                    .positions
                                    .get(&market)
                                    .map(|p| p.isolated)
                                    .unwrap_or(false);
                                if cp_isolated {
                                    x.isolated_risk(market, &self.state.marks, &self.state.markets)
                                        .equity
                                } else {
                                    x.snapshot(&self.state.marks, &self.state.markets).equity
                                }
                            })
                            .unwrap_or(0)
                            .max(1);
                        funding_notional_usd(q, usd) / e
                    };
                    ratio(b.0, b.1.unsigned_abs()).cmp(&ratio(a.0, a.1.unsigned_abs()))
                })
                .then_with(|| a.0.cmp(&b.0))
        });
        let oid = liq_order_id(unit);
        let mut fills: Vec<Fill> = Vec::new();
        let mut remaining = dq;
        // Positive collateral deltas recorded for this call: the only pools
        // the residual haircut may ever touch.
        let mut pos_deltas: Vec<(AccountId, Usd)> = Vec::new();
        for (cp, cp_qty, _) in cps {
            if remaining == 0 {
                break;
            }
            let take = cp_qty.unsigned_abs().min(remaining);
            if take == 0 {
                continue;
            }
            // Opposite-sign holder closes its own way: a short buys back,
            // a long sells — paired with the target's closing side.
            let cp_side = if cp_qty > 0 { Side::Ask } else { Side::Bid };
            let before = self
                .state
                .accounts
                .get(&cp)
                .map(|a| a.collateral)
                .unwrap_or(0);
            let cp_isolated = self
                .state
                .accounts
                .get(&cp)
                .and_then(|a| a.positions.get(&market))
                .map(|p| p.isolated)
                .unwrap_or(false);
            let target_isolated = self
                .state
                .accounts
                .get(&target)
                .and_then(|a| a.positions.get(&market))
                .map(|p| p.isolated)
                .unwrap_or(false);
            {
                let a = self.state.account_mut(cp);
                a.apply_fill(
                    cp_side,
                    true,
                    price,
                    take,
                    market,
                    Some(usd),
                    0,
                    cp_isolated,
                )
                .map_err(map_acct)?;
            }
            {
                let a = self.state.account_mut(target);
                a.apply_fill(
                    close_side,
                    false,
                    price,
                    take,
                    market,
                    Some(usd),
                    0,
                    target_isolated,
                )
                .map_err(map_acct)?;
            }
            let after = self
                .state
                .accounts
                .get(&cp)
                .map(|a| a.collateral)
                .unwrap_or(0);
            if after > before {
                pos_deltas.push((cp, after - before));
            }
            // No taker fee inside this fill and no socialization: ADL is
            // the transfer, not a trade.
            fills.push(Fill {
                taker_id: oid,
                maker_id: OrderId([0u8; 32]),
                taker: cp,
                maker: target,
                market,
                price,
                qty: take,
                seq,
                taker_side: cp_side,
                taker_post: 0,
                maker_post: 0,
                taker_isolated: cp_isolated,
                maker_isolated: target_isolated,
                kind: 2,
            });
            remaining -= take;
        }
        let target_equity = |s: &ChainState| {
            s.accounts
                .get(&target)
                .map(|a| {
                    // Isolated: residual bucket + remaining uPnL after the
                    // ADL fills; cross: pooled equity as today.
                    let tgt_isolated = a
                        .positions
                        .get(&market)
                        .map(|p| p.isolated)
                        .unwrap_or(false);
                    if tgt_isolated {
                        a.isolated_risk(market, &s.marks, &s.markets).equity
                    } else {
                        a.snapshot(&s.marks, &s.markets).equity
                    }
                })
                .unwrap_or(0)
        };
        // No insurance top-up: the fund never pays a loss. The residual
        // hole below is haircut from positive-PnL ADL counterparties
        // instead (zero-sum, insurance not debited); whatever they cannot
        // cover stays on the account as negative equity.
        let equity = target_equity(&self.state);
        // Residual hole: haircut positive-PnL ADL counterparties pro-rata,
        // last in ADL order takes the remainder. Each is debited at most
        // the positive delta recorded for this call, and every debit lands
        // on the target (collateral or isolated bucket) — money moves, it
        // never vanishes (#9).
        if equity < 0 {
            let mut hole = -equity;
            let total: Usd = pos_deltas.iter().map(|(_, d)| *d).sum();
            if total > 0 {
                let last = pos_deltas.last().map(|(id, _)| *id);
                for (id, delta) in &pos_deltas {
                    if hole <= 0 || total <= 0 {
                        break;
                    }
                    let share = adl_haircut_share(hole, *delta, total, Some(*id) == last);
                    if share <= 0 {
                        continue;
                    }
                    if let Some(a) = self.state.accounts.get_mut(id) {
                        a.collateral -= share;
                    }
                    // Credit the target through the isolated-vs-cross
                    // branch (bucket while the position still exists,
                    // collateral once it is gone).
                    let tgt_still_isolated = self
                        .state
                        .accounts
                        .get(&target)
                        .map(|a| {
                            a.positions
                                .get(&market)
                                .map(|p| p.isolated)
                                .unwrap_or(false)
                        })
                        .unwrap_or(false);
                    if tgt_still_isolated {
                        if let Some(a) = self.state.accounts.get_mut(&target) {
                            *a.isolated_margin.entry(market).or_insert(0) += share;
                        }
                    } else if let Some(a) = self.state.accounts.get_mut(&target) {
                        a.collateral += share;
                    }
                    hole -= share;
                }
            }
        }
        // Keeper reward: bps of the multiplier notional of the closed qty,
        // seized from the target's positive collateral after the steps
        // above. No book fill, so no reward from a book price.
        let reward = bps(
            funding_notional_usd(dq, usd),
            self.state.market_params(market).keeper_reward_bps,
        );
        if reward > 0 {
            let bal = self
                .state
                .accounts
                .get(&target)
                .map(|a| a.collateral.max(0))
                .unwrap_or(0);
            let pay = reward.min(bal);
            if pay > 0 {
                if let Some(a) = self.state.accounts.get_mut(&target) {
                    a.collateral -= pay;
                }
                self.state
                    .account_mut(caller)
                    .credit(pay)
                    .map_err(map_acct)?;
            }
        }
        Ok(fills)
    }

    fn gov_deposit(
        &mut self,
        account: AccountId,
        addr: &str,
        amount: u128,
        aa_unit: [u8; 32],
    ) -> Result<Vec<Fill>, RejectReason> {
        if self.state.seen_aa_units.contains_key(&aa_unit)
            || self.state.consumed_deposits.contains(&aa_unit)
        {
            return Err(RejectReason::DuplicateDeposit);
        }
        // PERP deposits are backed by the same on-chain AA feed as collateral;
        // the bool kind binds the endorsement to PERP, not collateral.
        if !self.state.deposits_allowed.contains(&(aa_unit, true)) {
            return Err(RejectReason::UnbackedDeposit);
        }
        // Same address rule as a collateral deposit: the account's AA leaf is
        // keyed by this address regardless of asset kind.
        if !valid_obyte_addr(addr) {
            return Err(RejectReason::BadAccount);
        }
        match self.state.aa_addresses.get(&account) {
            Some(bound) if bound != addr => return Err(RejectReason::BadAccount),
            Some(_) => {}
            None => {
                self.state.aa_addresses.insert(account, addr.to_string());
            }
        }
        let new_bal = self
            .state
            .perp_balances
            .get(&account)
            .copied()
            .unwrap_or(0)
            .checked_add(amount)
            .ok_or(RejectReason::Risk)?;
        let new_supply = self
            .state
            .perp_supply
            .checked_add(amount)
            .ok_or(RejectReason::Risk)?;
        self.state.perp_balances.insert(account, new_bal);
        self.state.perp_supply = new_supply;
        self.state.seen_aa_units.insert(aa_unit, self.state.height);
        self.state.consumed_deposits.insert(aa_unit);
        Ok(Vec::new())
    }

    fn gov_withdraw(
        &mut self,
        account: AccountId,
        amount: u128,
        nonce: u64,
    ) -> Result<Vec<Fill>, RejectReason> {
        // Strictly increasing nonce watermark per account: any nonce at or
        // below the highest consumed one is a replay, and gaps are allowed.
        let watermark = self
            .state
            .seen_gov_nonces
            .get(&account)
            .copied()
            .unwrap_or(0);
        if nonce <= watermark {
            return Err(RejectReason::DuplicateNonce);
        }
        let bal = self.state.perp_balances.get(&account).copied().unwrap_or(0);
        if bal < amount {
            return Err(RejectReason::Insufficient);
        }
        // Durability (H2, low-D19): the nonce is buffered here and fsynced
        // to the WAL only when the batch commits (`flush_gov_wal` from
        // `Batch::from_applied`). Uncommitted batches — crash after ingest,
        // or validation replays — never persist the nonce, so a withdraw
        // that never committed does not burn the account's nonce. The
        // in-memory watermark still advances at ingest (duplicate detection
        // semantics unchanged).
        if self.store_dir.is_some() && !self.validating {
            self.pending_gov_wal.push((account, nonce));
        }
        self.state.perp_balances.insert(account, bal - amount);
        self.state.perp_supply -= amount;
        self.state.seen_gov_nonces.insert(account, nonce);
        Ok(Vec::new())
    }

    #[allow(clippy::too_many_arguments)]
    fn create_market(
        &mut self,
        creator: AccountId,
        symbol: [u8; 16],
        tick_size: operp_types::Price,
        im_bps: Bps,
        mm_bps: Bps,
        taker_fee_bps: Bps,
        keeper_reward_bps: Bps,
        spot_only: bool,
        funding_rate: bool,
        usd_per_unit: u64,
        funding_cap_bps: u64,
    ) -> Result<Vec<Fill>, RejectReason> {
        // A funding-rate market needs a reporter index, which spot_only
        // rejects outright — mutually exclusive kinds, rejected before any
        // PERP changes hands.
        if spot_only && funding_rate {
            return Err(RejectReason::Risk);
        }
        // Signed price grid: tick stays strictly positive; a zero or
        // negative grid would break limit alignment (`price % tick_size`).
        if tick_size <= 0
            || !risk_params_ok(
                im_bps,
                mm_bps,
                taker_fee_bps,
                keeper_reward_bps,
                funding_rate,
                funding_cap_bps,
            )
        {
            return Err(RejectReason::Risk);
        }
        // Money scale is listing-time and only meaningful on funding-rate
        // markets: regular markets keep the encoded-price dollar path, so a
        // non-zero multiplier there would be silently ignored at best.
        let money_ok = if funding_rate {
            (1..=1_000_000_000).contains(&usd_per_unit)
        } else {
            usd_per_unit == 0
        };
        if !money_ok {
            return Err(RejectReason::Risk);
        }
        let bal = self.state.perp_balances.get(&creator).copied().unwrap_or(0);
        if bal < CREATE_MARKET_FEE_PERP {
            return Err(RejectReason::Insufficient);
        }
        // Listing fee is burned: debit the creator, shrink circulating supply,
        // grow the cumulative burned counter (claimable deflation; no sweep).
        self.state
            .perp_balances
            .insert(creator, bal - CREATE_MARKET_FEE_PERP);
        self.state.perp_supply -= CREATE_MARKET_FEE_PERP;
        self.state.perp_burned += CREATE_MARKET_FEE_PERP;
        let id = MarketId(self.state.next_market_id);
        self.state.next_market_id += 1;
        self.state.markets.insert(
            id,
            MarketParams {
                symbol,
                tick_size,
                im_bps,
                mm_bps,
                taker_fee_bps,
                keeper_reward_bps,
                spot_only,
                funding_rate,
                usd_per_unit,
                funding_cap_bps,
                delisted: false,
            },
        );
        // The creator is the market's external index feed: there is no op
        // to edit this set, so listing is the only way in. Idempotent.
        if funding_rate {
            self.state.external_sources.insert(creator);
        }
        Ok(Vec::new())
    }

    fn create_proposal(
        &mut self,
        creator: AccountId,
        market: MarketId,
        key: u8,
        value: u64,
        seq: Seq,
    ) -> Result<Vec<Fill>, RejectReason> {
        let key = ParamKey::from_u8(key).ok_or(RejectReason::Risk)?;
        if key == ParamKey::Delist {
            // Delist carries no value.
            if value != 0 {
                return Err(RejectReason::Risk);
            }
        }
        if !self.state.markets.contains_key(&market) {
            return Err(RejectReason::NotFound);
        }
        // Bps updates must produce a still-legal parameter set; an illegal
        // one would be silently dropped at finalize anyway.
        if key != ParamKey::Delist {
            let mut params = self.state.markets[&market];
            apply_param(&mut params, key, value);
            if !risk_params_ok(
                params.im_bps,
                params.mm_bps,
                params.taker_fee_bps,
                params.keeper_reward_bps,
                params.funding_rate,
                params.funding_cap_bps,
            ) {
                return Err(RejectReason::Risk);
            }
        }
        // Threshold check only — the stake is not locked or escrowed.
        let bal = self.state.perp_balances.get(&creator).copied().unwrap_or(0);
        if bal < PROPOSAL_MIN_STAKE_PERP {
            return Err(RejectReason::Insufficient);
        }
        // Step10: bounded proposal table — unbounded growth is a state-bloat
        // DoS. 64 concurrent proposals is ample for governance throughput.
        if self.state.proposals.len() >= 64 {
            return Err(RejectReason::Risk);
        }
        let id = self.state.next_proposal_id;
        self.state.next_proposal_id += 1;
        self.state.proposals.insert(
            id,
            Proposal {
                creator,
                market,
                key,
                value,
                created_seq: seq,
                deadline_seq: seq + PROPOSAL_DURATION_SEQS,
                supply_at_create: self.state.perp_supply,
                yes: 0,
                no: 0,
                voted: HashSet::new(),
                // Voting weight is frozen at creation: burning or moving
                // PERP afterwards can neither boost nor dodge a ballot, and
                // the quorum denominator stays fixed. Zero balances are
                // dropped from the snapshot (they vote 0 anyway — tally
                // reads use `unwrap_or(0)`), keeping proposal payloads slim.
                weight_snapshot: self
                    .state
                    .perp_balances
                    .iter()
                    .filter(|(_, &b)| b != 0)
                    .map(|(a, &b)| (*a, b))
                    .collect(),
            },
        );
        Ok(Vec::new())
    }

    fn vote(
        &mut self,
        voter: AccountId,
        proposal_id: u64,
        approve: bool,
        seq: Seq,
    ) -> Result<Vec<Fill>, RejectReason> {
        let p = self
            .state
            .proposals
            .get_mut(&proposal_id)
            .ok_or(RejectReason::NoProposal)?;
        if seq >= p.deadline_seq {
            return Err(RejectReason::Risk);
        }
        if !p.voted.insert(voter) {
            return Err(RejectReason::Risk);
        }
        // Weight comes from the creation-time snapshot, never the live
        // balance: burning PERP after creating the proposal can neither
        // boost nor dodge a ballot.
        let w = p.weight_snapshot.get(&voter).copied().unwrap_or(0);
        if approve {
            p.yes += w;
        } else {
            p.no += w;
        }
        Ok(Vec::new())
    }

    fn finalize_proposal(
        &mut self,
        caller: AccountId,
        proposal_id: u64,
        seq: Seq,
    ) -> Result<Vec<Fill>, RejectReason> {
        // Permissionless finalization: `caller` only signs the unit.
        let _ = caller;
        let (pass, market, key, value) = {
            let p = self
                .state
                .proposals
                .get(&proposal_id)
                .ok_or(RejectReason::NoProposal)?;
            if seq < p.deadline_seq {
                return Err(RejectReason::Risk);
            }
            let pass = p.yes > p.no
                && p.yes * PROPOSAL_QUORUM_DEN >= p.supply_at_create * PROPOSAL_QUORUM_NUM;
            (pass, p.market, p.key, p.value)
        };
        if pass {
            if let Some(params) = self.state.markets.get(&market) {
                let mut updated = *params;
                apply_param(&mut updated, key, value);
                // A passed-but-illegal proposal is a no-op: never write an
                // out-of-policy field, but still consume the proposal.
                let legal = key == ParamKey::Delist
                    || risk_params_ok(
                        updated.im_bps,
                        updated.mm_bps,
                        updated.taker_fee_bps,
                        updated.keeper_reward_bps,
                        updated.funding_rate,
                        updated.funding_cap_bps,
                    );
                if legal {
                    self.state.markets.insert(market, updated);
                }
            }
        }
        // Remove the proposal either way — it can no longer be voted on or
        // re-finalized. Ids are never reused: next_proposal_id is monotonic
        // and committed inside meta_leaf.
        self.state.proposals.remove(&proposal_id);
        Ok(Vec::new())
    }

    fn stake_oracle(&mut self, account: AccountId) -> Result<Vec<Fill>, RejectReason> {
        self.state.apply_stake(account).map_err(map_state)?;
        Ok(Vec::new())
    }

    fn unstake_oracle(&mut self, account: AccountId) -> Result<Vec<Fill>, RejectReason> {
        self.state.apply_unstake(account).map_err(map_state)?;
        Ok(Vec::new())
    }

    fn slash_oracle(
        &mut self,
        challenger: AccountId,
        target: AccountId,
        market: MarketId,
    ) -> Result<Vec<Fill>, RejectReason> {
        self.state
            .apply_slash(challenger, target, market)
            .map_err(map_state)?;
        Ok(Vec::new())
    }

    // -----------------------------------------------------------------------
    // Commit-reveal ordering v2 (doc 03 §2.3)
    //
    /// Register a commitment (doc 03 §2.3.3 rule 1 + §2.3.5 DoS bounds).
    /// Commits carry no content MEV; they are ordered by the v1 salted key
    /// like any other unit.
    fn commit_op(
        &mut self,
        id: UnitId,
        account: AccountId,
        commit: [u8; 32],
        ttl_height: Height,
    ) -> Result<Vec<Fill>, RejectReason> {
        if self.state.commits.contains_key(&commit) {
            return Err(RejectReason::BadCommit);
        }
        // Bound the reveal deadline to COMMIT_TTL_HEIGHTS past creation so
        // the pending set is memory-bounded; TTL ~16 heights ≈ 32 s.
        let commit_height = self.state.height;
        if ttl_height <= commit_height
            || ttl_height > commit_height + operp_types::COMMIT_TTL_HEIGHTS
        {
            return Err(RejectReason::BadCommit);
        }
        // Per-account pending-commit cap (doc 03 §2.3.5, e.g. 8).
        let pending = self
            .state
            .commits
            .values()
            .filter(|e| e.account == account && !e.revealed)
            .count();
        if pending >= operp_types::MAX_PENDING_COMMITS_PER_ACCOUNT {
            return Err(RejectReason::BadCommit);
        }
        self.state.commits.insert(
            commit,
            operp_state::CommitEntry {
                account,
                commit_unit: id,
                commit_height,
                ttl_height,
                revealed: false,
            },
        );
        Ok(Vec::new())
    }

    /// Reveal a committed operation (doc 03 §2.3.3 rule 3): preimage check,
    /// account match, TTL window, not-yet-revealed, and parent-edge
    /// enforcement (the Reveal unit must descend from its Commit unit, doc
    /// §2.3.4). On success the commit is consumed and the inner op executes
    /// through the normal path (price-time, risk checks unchanged).
    fn reveal_op(
        &mut self,
        id: UnitId,
        account: AccountId,
        commit_ref: [u8; 32],
        inner: &Op,
        salt: &[u8; 32],
    ) -> Result<Vec<Fill>, RejectReason> {
        let entry = match self.state.commits.get(&commit_ref) {
            Some(e) => *e,
            None => return Err(RejectReason::BadCommit),
        };
        if entry.revealed
            || entry.account != account
            || self.state.height > entry.ttl_height
            || operp_dag::reveal_commit_hash(inner, salt) != commit_ref
        {
            return Err(RejectReason::BadCommit);
        }
        // Parent-edge constraint: the Commit's unit id must be among this
        // unit's parents so DAG topo order places the reveal after it and
        // `ready_linearized` stays pure.
        let parents = self
            .dag
            .get(id)
            .map(|u| u.parents.clone())
            .unwrap_or_default();
        if !parents.contains(&entry.commit_unit) {
            return Err(RejectReason::BadCommit);
        }
        // Doc order: consume the commit first ("set revealed = true"), then
        // execute the inner op; both steps are deterministic on replay.
        self.state.commits.get_mut(&commit_ref).unwrap().revealed = true;
        let seq = self.state.seq;
        self.dispatch(id, seq, inner)
    }

    /// External keeper price intake (doc 06 §2.6): gated on the
    /// AggregatedExternal source selection, the governance allowlist, and a
    /// live known market. Writes only the sidechain-internal ring.
    fn update_external_price(
        &mut self,
        source: AccountId,
        market: MarketId,
        price: Price,
        source_id: u8,
        caller_seq: Seq,
    ) -> Result<Vec<Fill>, RejectReason> {
        let funding_rate = self
            .state
            .markets
            .get(&market)
            .map(|p| p.funding_rate)
            .unwrap_or(false);
        // Funding-rate markets trade the external rate itself: their feed
        // must work regardless of the global source selection (the peg pays
        // only from a fresh external print). Regular markets keep the
        // AggregatedExternal gate.
        if !funding_rate
            && self.state.funding_source != operp_types::FundingSourceKind::AggregatedExternal
        {
            return Err(RejectReason::NotFound);
        }
        if !self.state.external_sources.contains(&source) {
            return Err(RejectReason::BadAccount);
        }
        if !self.state.markets.contains_key(&market) || price == 0 {
            return Err(RejectReason::NotFound);
        }
        // The ring carries an encoded rate on funding-rate markets; a print
        // beyond ±100% is a broken feed, not a market. Regular markets carry
        // dollar prices in the same ring — their scale is untouched here.
        if funding_rate && operp_types::funding_rate_bps(price).abs() > 10_000 {
            return Err(RejectReason::NotFound);
        }
        if self
            .state
            .markets
            .get(&market)
            .map(|p| p.spot_only)
            .unwrap_or(false)
        {
            return Err(RejectReason::NotFound);
        }
        self.state
            .apply_external_price(source, market, price, source_id, caller_seq);
        // A fresh print may unblock this window's peg payment (or arm it).
        if funding_rate {
            self.state.settle_funding_peg(market);
        }
        Ok(Vec::new())
    }
}

/// Apply a governance parameter key to a copy of `MarketParams`. Shared by
/// proposal creation (validation) and finalization (write).
fn apply_param(params: &mut MarketParams, key: ParamKey, value: u64) {
    match key {
        ParamKey::ImBps => params.im_bps = value,
        ParamKey::MmBps => params.mm_bps = value,
        ParamKey::TakerFeeBps => params.taker_fee_bps = value,
        ParamKey::KeeperRewardBps => params.keeper_reward_bps = value,
        ParamKey::Delist => params.delisted = true,
    }
}

fn map_acct(e: AccountError) -> RejectReason {
    match e {
        AccountError::Insufficient | AccountError::NonPositive => RejectReason::Insufficient,
        AccountError::Overflow | AccountError::QtyTooLarge => RejectReason::Risk,
    }
}

fn map_state(e: operp_state::StateError) -> RejectReason {
    match e {
        operp_state::StateError::InsufficientPerp => RejectReason::Insufficient,
        operp_state::StateError::UnknownMarket => RejectReason::NotFound,
        operp_state::StateError::AlreadyBonded => RejectReason::AlreadyBonded,
        operp_state::StateError::NotBonded => RejectReason::NotBonded,
        operp_state::StateError::Unbonding => RejectReason::Unbonding,
        operp_state::StateError::SlashNotEligible => RejectReason::SlashNotEligible,
        operp_state::StateError::NotFound => RejectReason::NotFound,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use operp_dag::{genesis_id, sign_unit, unit_id, Op};
    use operp_types::{
        account_id_from_pubkey, BTC_USD, ORACLE_BOND_PERP, PRICE_SCALE, QTY_SCALE, USD_SCALE,
    };

    /// Tests/examples run standalone (no AA feed): admit every deposit of
    /// BOTH asset kinds and seed the BTC_USD market with genesis params.
    /// Production replay injects real sets via `ChainState::deposits_allowed`
    /// keyed by (unit, is_perp); markets are created permissionlessly via
    /// `Op::CreateMarket`.
    fn allow_all(eng: &mut Engine) {
        eng.state.deposits_allowed = (0u8..=255)
            .flat_map(|b| [([b; 32], false), ([b; 32], true)])
            .collect();
        eng.state
            .markets
            .insert(BTC_USD, operp_types::genesis_params());
    }

    fn sk(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn acct_of(secret: &[u8; 32]) -> AccountId {
        let pk = SigningKey::from_bytes(secret).verifying_key().to_bytes();
        account_id_from_pubkey(&pk)
    }

    /// 32-char uppercase [A-Z2-7] Obyte-style test address, varied by `n`.
    fn test_addr(n: u8) -> String {
        let mut bytes = vec![b'A'; 32];
        bytes[0] = b'A' + (n % 26);
        String::from_utf8(bytes).unwrap()
    }

    fn deposit(parents: Vec<UnitId>, secret: &[u8; 32], amount: Usd, aa: u8) -> Unit {
        let account = acct_of(secret);
        sign_unit(
            parents,
            Op::Deposit {
                account,
                addr: test_addr(aa),
                amount,
                aa_unit: [aa; 32],
            },
            secret,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn place_on(
        parents: Vec<UnitId>,
        secret: &[u8; 32],
        market: MarketId,
        side: Side,
        typ: OrderType,
        tif: TimeInForce,
        price: operp_types::Price,
        qty: Qty,
        client_seq: u64,
    ) -> Unit {
        let account = acct_of(secret);
        sign_unit(
            parents,
            Op::Place {
                account,
                market,
                side,
                typ,
                tif,
                price,
                qty,
                client_seq,
                isolated: false,
                margin: 0,
            },
            secret,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn place(
        parents: Vec<UnitId>,
        secret: &[u8; 32],
        side: Side,
        typ: OrderType,
        tif: TimeInForce,
        price: operp_types::Price,
        qty: Qty,
        client_seq: u64,
    ) -> Unit {
        let account = acct_of(secret);
        sign_unit(
            parents,
            Op::Place {
                account,
                market: BTC_USD,
                side,
                typ,
                tif,
                price,
                qty,
                client_seq,
                isolated: false,
                margin: 0,
            },
            secret,
        )
    }

    /// Isolated-mode place; `margin` in USD_SCALE units.
    #[allow(clippy::too_many_arguments)]
    fn place_iso(
        parents: Vec<UnitId>,
        secret: &[u8; 32],
        market: MarketId,
        side: Side,
        typ: OrderType,
        tif: TimeInForce,
        price: operp_types::Price,
        qty: Qty,
        client_seq: u64,
        margin: u64,
    ) -> Unit {
        let account = acct_of(secret);
        sign_unit(
            parents,
            Op::Place {
                account,
                market,
                side,
                typ,
                tif,
                price,
                qty,
                client_seq,
                isolated: true,
                margin,
            },
            secret,
        )
    }

    #[test]
    fn two_crossing_orders_fill() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        let alice = sk(1);
        let bob = sk(2);
        let d1 = deposit(vec![g], &alice, 10_000 * USD_SCALE as i128, 1);
        let id1 = unit_id(&d1);
        eng.ingest(d1).unwrap();
        let d2 = deposit(vec![id1], &bob, 10_000 * USD_SCALE as i128, 2);
        let id2 = unit_id(&d2);
        eng.ingest(d2).unwrap();
        let px = 100_000 * PRICE_SCALE as i64;
        let qty = QTY_SCALE;
        let ask = place(
            vec![id2],
            &bob,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty,
            1,
        );
        let id3 = unit_id(&ask);
        eng.ingest(ask).unwrap();
        let bid = place(
            vec![id3],
            &alice,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty,
            1,
        );
        let evs = eng.ingest(bid).unwrap();
        let fills: Vec<_> = evs
            .iter()
            .filter_map(|e| match e {
                ExecEvent::Applied { fills, .. } if !fills.is_empty() => Some(fills.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(fills.len(), 1);
        let _a = acct_of(&alice);
        let b = acct_of(&bob);
        assert_eq!(
            eng.state.accounts.get(&b).unwrap().positions[&BTC_USD].qty,
            -(qty as i64)
        );
    }

    #[test]
    fn duplicate_client_seq_rejected() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        let alice = sk(1);
        let d1 = deposit(vec![g], &alice, 10_000 * USD_SCALE as i128, 1);
        let id1 = unit_id(&d1);
        eng.ingest(d1).unwrap();
        let p1 = place(
            vec![id1],
            &alice,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            90_000 * PRICE_SCALE as i64,
            QTY_SCALE,
            1,
        );
        let id2 = unit_id(&p1);
        eng.ingest(p1).unwrap();
        let p2 = place(
            vec![id2],
            &alice,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            91_000 * PRICE_SCALE as i64,
            QTY_SCALE,
            1,
        );
        let evs = eng.ingest(p2).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::DuplicateClientSeq,
                ..
            }
        )));
    }

    #[test]
    fn deposit_then_withdraw() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        let alice = sk(1);
        let d1 = deposit(vec![g], &alice, 10_000 * USD_SCALE as i128, 1);
        let id1 = unit_id(&d1);
        eng.ingest(d1).unwrap();
        let account = acct_of(&alice);
        let w = sign_unit(
            vec![id1],
            Op::Withdraw {
                account,
                amount: 1_000 * USD_SCALE as i128,
                nonce: 1,
            },
            &alice,
        );
        let evs = eng.ingest(w).unwrap();
        assert!(evs.iter().any(|e| matches!(e, ExecEvent::Applied { .. })));
        assert_eq!(
            eng.state.accounts.get(&account).unwrap().collateral,
            9_000 * USD_SCALE as i128
        );
    }

    #[test]
    fn liquidate_underwater() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        let alice = sk(1);
        let bob = sk(2);
        let d1 = deposit(vec![g], &alice, 15_000 * USD_SCALE as i128, 1);
        let id1 = unit_id(&d1);
        eng.ingest(d1).unwrap();
        let d2 = deposit(vec![id1], &bob, 1_000_000 * USD_SCALE as i128, 2);
        let id2 = unit_id(&d2);
        eng.ingest(d2).unwrap();
        let px = 100_000 * PRICE_SCALE as i64;
        let ask = place(
            vec![id2],
            &bob,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE,
            1,
        );
        let id3 = unit_id(&ask);
        eng.ingest(ask).unwrap();
        let bid = place(
            vec![id3],
            &alice,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE,
            1,
        );
        let id4 = unit_id(&bid);
        eng.ingest(bid).unwrap();
        eng.state.marks.insert(BTC_USD, PRICE_SCALE as i64);
        let a = acct_of(&alice);
        assert!(
            eng.state
                .accounts
                .get(&a)
                .unwrap()
                .snapshot(&eng.state.marks, &eng.state.markets)
                .liquidatable
        );
        let ask2 = place(
            vec![id4],
            &bob,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            PRICE_SCALE as i64,
            QTY_SCALE,
            2,
        );
        let id5 = unit_id(&ask2);
        eng.ingest(ask2).unwrap();
        let liq = sign_unit(
            vec![id5],
            Op::Liquidate {
                caller: acct_of(&bob),
                target: a,
                market: BTC_USD,
            },
            &bob,
        );
        let evs = eng.ingest(liq).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Applied { fills, .. } if !fills.is_empty()
        )));
    }

    /// Empty book: the liquidation IOC fills nothing, so the still-
    /// liquidatable remainder is ADL'd onto the opposite holder in the
    /// same unit — its maker is that counterparty, never
    /// INSURANCE_ACCOUNT, priced at the current mark.
    #[test]
    fn liquidate_adl_remainder_uses_counterparty() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        let alice = sk(1);
        let bob = sk(2);
        let keeper = sk(3);
        let d1 = deposit(vec![g], &alice, 15_000 * USD_SCALE as i128, 1);
        let id1 = unit_id(&d1);
        eng.ingest(d1).unwrap();
        let d2 = deposit(vec![id1], &bob, 1_000_000 * USD_SCALE as i128, 2);
        let id2 = unit_id(&d2);
        eng.ingest(d2).unwrap();
        let px = 100_000 * PRICE_SCALE as i64;
        // Bob rests the ask; alice crosses it: alice long 1 @ 100k, bob
        // short 1 @ 100k — both orders consumed, book empty afterwards.
        let ask = place(
            vec![id2],
            &bob,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE,
            1,
        );
        let id3 = unit_id(&ask);
        eng.ingest(ask).unwrap();
        let bid = place(
            vec![id3],
            &alice,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE,
            1,
        );
        let id4 = unit_id(&bid);
        eng.ingest(bid).unwrap();
        assert_eq!(
            eng.state
                .books
                .get(&BTC_USD)
                .map(|b| b.live_orders().count())
                .unwrap_or(0),
            0,
            "book is empty"
        );
        // Crash the mark: alice is liquidatable with nothing to trade into.
        eng.state.marks.insert(BTC_USD, PRICE_SCALE as i64);
        let a = acct_of(&alice);
        let b = acct_of(&bob);
        let liq = sign_unit(
            vec![id4],
            Op::Liquidate {
                caller: acct_of(&keeper),
                target: a,
                market: BTC_USD,
            },
            &keeper,
        );
        let evs = eng.ingest(liq).unwrap();
        let fills: Vec<Fill> = evs
            .iter()
            .filter_map(|e| match e {
                ExecEvent::Applied { fills, .. } => Some(fills.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert!(!fills.is_empty(), "ADL remainder fill expected");
        assert!(
            fills.iter().all(|f| f.maker != INSURANCE_ACCOUNT),
            "insurance is never the buyer of last resort"
        );
        assert_eq!(
            fills[0].maker, b,
            "remainder ADL'd onto the short counterparty"
        );
        assert_eq!(fills[0].kind, 2, "ADL fill kind");
        assert_eq!(
            fills[0].price, PRICE_SCALE as i64,
            "ADL closes at the current mark"
        );
        assert!(
            eng.state.accounts[&a].positions.is_empty(),
            "position fully ADL'd away"
        );
    }

    /// No opposite-sign holder exists: the ADL candidate list is empty, so
    /// the liquidatable position stays on the account — the target is not
    /// credited, nothing is printed, and insurance is unchanged.
    #[test]
    fn liquidate_remainder_stays_without_counterparty() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        let alice = sk(1);
        let keeper = sk(2);
        let d1 = deposit(vec![g], &alice, 15_000 * USD_SCALE as i128, 1);
        let id1 = unit_id(&d1);
        eng.ingest(d1).unwrap();
        let a = acct_of(&alice);
        // Lone long — synthetic state: a real fill would mint a short on
        // the counterparty, and this scenario needs none to exist.
        eng.state
            .account_mut(a)
            .apply_fill(
                Side::Bid,
                true,
                100_000 * PRICE_SCALE as i64,
                QTY_SCALE,
                BTC_USD,
                None,
                0,
                false,
            )
            .unwrap();
        eng.state.marks.insert(BTC_USD, PRICE_SCALE as i64);
        let ins_before = eng.state.accounts[&INSURANCE_ACCOUNT].collateral;
        let liq = sign_unit(
            vec![id1],
            Op::Liquidate {
                caller: acct_of(&keeper),
                target: a,
                market: BTC_USD,
            },
            &keeper,
        );
        let evs = eng.ingest(liq).unwrap();
        assert!(
            evs.iter().any(|e| matches!(e, ExecEvent::Applied { .. })),
            "{evs:?}"
        );
        assert_eq!(
            eng.state.accounts[&a]
                .positions
                .get(&BTC_USD)
                .map(|p| p.qty),
            Some(QTY_SCALE as i64),
            "position stays — nobody could take the other side"
        );
        assert_eq!(
            eng.state.accounts[&INSURANCE_ACCOUNT].collateral, ins_before,
            "insurance unchanged"
        );
    }

    #[test]
    fn overflow_place_rejected() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        let alice = sk(1);
        let d1 = deposit(vec![g], &alice, 10_000 * USD_SCALE as i128, 1);
        let id1 = unit_id(&d1);
        eng.ingest(d1).unwrap();
        // qty near u64::MAX: must be Rejected(Risk), never panic/wrap
        let p = place(
            vec![id1],
            &alice,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            i64::MAX / 2,
            u64::MAX,
            1,
        );
        let evs = eng.ingest(p).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::Risk,
                ..
            }
        )));
    }

    #[test]
    fn self_liquidate_rejected() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        let alice = sk(1);
        let d1 = deposit(vec![g], &alice, 15_000 * USD_SCALE as i128, 1);
        let id1 = unit_id(&d1);
        eng.ingest(d1).unwrap();
        let a = acct_of(&alice);
        let liq = sign_unit(
            vec![id1],
            Op::Liquidate {
                caller: a,
                target: a,
                market: BTC_USD,
            },
            &alice,
        );
        let evs = eng.ingest(liq).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::BadAccount,
                ..
            }
        )));
    }

    #[test]
    fn unbacked_deposit_rejected() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        eng.state.deposits_allowed.clear(); // simulate empty AA feed
        let g = genesis_id();
        let d = deposit(vec![g], &sk(3), 1_000 * USD_SCALE as i128, 9);
        let evs = eng.ingest(d).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::UnbackedDeposit,
                ..
            }
        )));
    }

    #[test]
    fn duplicate_withdraw_nonce_rejected() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        let alice = sk(1);
        let d1 = deposit(vec![g], &alice, 10_000 * USD_SCALE as i128, 1);
        let id1 = unit_id(&d1);
        eng.ingest(d1).unwrap();
        let account = acct_of(&alice);
        // first withdraw with nonce 7 applies
        let w1 = sign_unit(
            vec![id1],
            Op::Withdraw {
                account,
                amount: 100 * USD_SCALE as i128,
                nonce: 7,
            },
            &alice,
        );
        let id2 = unit_id(&w1);
        let evs1 = eng.ingest(w1).unwrap();
        assert!(evs1.iter().any(|e| matches!(e, ExecEvent::Applied { .. })));
        // second withdraw with the SAME nonce is classified DuplicateNonce
        let w2 = sign_unit(
            vec![id2],
            Op::Withdraw {
                account,
                amount: 100 * USD_SCALE as i128,
                nonce: 7,
            },
            &alice,
        );
        let evs2 = eng.ingest(w2).unwrap();
        assert!(evs2.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::DuplicateNonce,
                ..
            }
        )));
    }

    #[test]
    fn keeper_reward_paid_on_liquidation() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        let alice = sk(1);
        let bob = sk(2);
        let keeper = sk(3);
        let d1 = deposit(vec![g], &alice, 15_000 * USD_SCALE as i128, 1);
        let id1 = unit_id(&d1);
        eng.ingest(d1).unwrap();
        let d2 = deposit(vec![id1], &bob, 1_000_000 * USD_SCALE as i128, 2);
        let id2 = unit_id(&d2);
        eng.ingest(d2).unwrap();
        let px = 100_000 * PRICE_SCALE as i64;
        let ask = place(
            vec![id2],
            &bob,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE,
            1,
        );
        let id3 = unit_id(&ask);
        eng.ingest(ask).unwrap();
        let bid = place(
            vec![id3],
            &alice,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE,
            1,
        );
        let id4 = unit_id(&bid);
        eng.ingest(bid).unwrap();
        // Crash to 89k: alice (long 1 @ 100k, 15k deposit) still has 4k
        // collateral and 4k equity against mm 4.45k → liquidatable. The
        // closing fill realizes -11k and pays a 5 bps taker fee (44.5 USD),
        // leaving 3,955.5 USD — comfortably above the 1% keeper reward of
        // 890 USD, which must come out of HER collateral, not the fund's.
        eng.state.marks.insert(BTC_USD, 89_000 * PRICE_SCALE as i64);
        let a = acct_of(&alice);
        let ask2 = place(
            vec![id4],
            &bob,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            89_000 * PRICE_SCALE as i64,
            QTY_SCALE,
            2,
        );
        let id5 = unit_id(&ask2);
        eng.ingest(ask2).unwrap();
        let ins_before = eng
            .state
            .accounts
            .get(&INSURANCE_ACCOUNT)
            .unwrap()
            .collateral;
        let liq = sign_unit(
            vec![id5],
            Op::Liquidate {
                caller: acct_of(&keeper),
                target: a,
                market: BTC_USD,
            },
            &keeper,
        );
        let evs = eng.ingest(liq).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Applied { fills, .. } if !fills.is_empty()
        )));
        // Exact money trail: opening taker fee 50 (5 bps of 100k), realize
        // -11k, closing taker fee 44.5 (5 bps of 89k), seize 890.
        let fee = 44_500_000i128; // 5 bps of 89k USD
        let open_fee = 50 * USD_SCALE as i128; // 5 bps of 100k USD
        let reward = 890 * USD_SCALE as i128; // 100 bps of 89k USD
        let alice_acct = acct_of(&alice);
        let target_bal = eng.state.accounts[&alice_acct].collateral;
        assert_eq!(
            target_bal,
            15_000 * USD_SCALE as i128 - open_fee - 11_000 * USD_SCALE as i128 - fee - reward
        );
        // Pre-reward balance (3,955.5 after open fee) exceeded the reward:
        // the seizure was capped at exactly the keeper bps, not at some
        // fund balance.
        assert!(3_955_500_000i128 - open_fee > reward);
        let keeper_acct = acct_of(&keeper);
        let keeper_bal = eng
            .state
            .accounts
            .get(&keeper_acct)
            .map(|x| x.collateral)
            .unwrap_or(0);
        assert_eq!(keeper_bal, reward, "keeper paid exactly the reward bps");
        let ins_after = eng
            .state
            .accounts
            .get(&INSURANCE_ACCOUNT)
            .unwrap()
            .collateral;
        // Insurance gained only the taker fee: the reward line is absent
        // from its balance (fee income in, no payout out).
        assert_eq!(ins_after, ins_before + fee);
    }

    #[test]
    fn finalize_promotes_log_status() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        let alice = sk(1);
        let d1 = deposit(vec![g], &alice, 10_000 * operp_types::USD_SCALE as i128, 1);
        let id1 = unit_id(&d1);
        eng.ingest(d1).unwrap();
        // All applied events start Optimistic.
        assert!(eng.log.iter().all(
            |e| !matches!(e, ExecEvent::Applied { status, .. } if *status == ExecStatus::Final)
        ));
        // Operator observes the AA finalizing height 1 (containing id1).
        let promoted = eng.promote_finalized(&[id1]);
        assert_eq!(promoted, 1);
        assert!(eng
            .log
            .iter()
            .any(|e| matches!(e, ExecEvent::Applied { unit, status, .. }
                if *unit == id1 && *status == ExecStatus::Final)));
        // Idempotent: promoting again is a no-op.
        assert_eq!(eng.promote_finalized(&[id1]), 0);
    }
    #[test]
    fn unauthorized_oracle_rejected() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        // No bonds injected: any ReportPrice must bounce.
        let o = sign_unit(
            vec![genesis_id()],
            Op::ReportPrice {
                oracle: acct_of(&sk(5)),
                market: BTC_USD,
                price: 100_000 * PRICE_SCALE as i64,
            },
            &sk(5),
        );
        let evs = eng.ingest(o).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::BadAccount,
                ..
            }
        )));
    }

    #[test]
    fn bonded_oracle_median_and_fill_mark_gated() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let oa = acct_of(&sk(5));
        let ob = acct_of(&sk(6));
        eng.state
            .oracle_bonds
            .insert(oa, operp_types::ORACLE_BOND_PERP);
        eng.state
            .oracle_bonds
            .insert(ob, operp_types::ORACLE_BOND_PERP);
        let g = genesis_id();
        let mk = |secret: &[u8; 32], px: Price| {
            sign_unit(
                vec![g],
                Op::ReportPrice {
                    oracle: acct_of(secret),
                    market: BTC_USD,
                    price: px,
                },
                secret,
            )
        };
        eng.ingest(mk(&sk(5), 100_000 * PRICE_SCALE as i64))
            .unwrap();
        eng.ingest(mk(&sk(6), 110_000 * PRICE_SCALE as i64))
            .unwrap();
        // Effective mark = median across reporters; median of two is the
        // lower middle, i.e. 100_000 (which equals the genesis mark, so the
        // clamp keeps it).
        assert_eq!(
            eng.state.marks.get(&BTC_USD).copied().unwrap(),
            100_000 * PRICE_SCALE as i64
        );
        // Once an oracle has spoken, fills must NOT move the mark.
        let alice = sk(1);
        eng.state
            .accounts
            .entry(acct_of(&alice))
            .or_insert_with(|| operp_account::Account::new(acct_of(&alice)))
            .credit(10_000_000 * USD_SCALE as i128)
            .unwrap();
        let p = place(
            vec![g],
            &alice,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            150_000 * PRICE_SCALE as i64,
            QTY_SCALE,
            1,
        );
        eng.ingest(p).unwrap();
        assert_eq!(
            eng.state.marks.get(&BTC_USD).copied().unwrap(),
            100_000 * PRICE_SCALE as i64,
            "oracle-authoritative mark must ignore fills"
        );
    }

    fn gov_dep(parents: Vec<UnitId>, secret: &[u8; 32], amount: u128, aa: u8) -> Unit {
        sign_unit(
            parents,
            Op::GovDeposit {
                account: acct_of(secret),
                addr: test_addr(aa),
                amount,
                aa_unit: [aa; 32],
            },
            secret,
        )
    }

    fn gov_with(parents: Vec<UnitId>, secret: &[u8; 32], amount: u128, nonce: u64) -> Unit {
        sign_unit(
            parents,
            Op::GovWithdraw {
                account: acct_of(secret),
                amount,
                nonce,
            },
            secret,
        )
    }

    fn list_market(parents: Vec<UnitId>, secret: &[u8; 32]) -> Unit {
        let mut symbol = [0u8; 16];
        symbol[..6].copy_from_slice(b"ETHUSD");
        sign_unit(
            parents,
            Op::CreateMarket {
                creator: acct_of(secret),
                symbol,
                tick_size: 1,
                im_bps: 1000,
                mm_bps: 500,
                taker_fee_bps: 5,
                keeper_reward_bps: 100,
                spot_only: false,
                funding_rate: false,
                usd_per_unit: 0,
                funding_cap_bps: 0,
            },
            secret,
        )
    }
    /// Permissionless listing with an explicit `spot_only` flag; the new
    /// market takes the next id (2 on a fresh engine).
    fn list_market_with(parents: Vec<UnitId>, secret: &[u8; 32], spot_only: bool) -> Unit {
        let mut symbol = [0u8; 16];
        symbol[..6].copy_from_slice(b"MEMEUS");
        sign_unit(
            parents,
            Op::CreateMarket {
                creator: acct_of(secret),
                symbol,
                tick_size: 1,
                im_bps: 1000,
                mm_bps: 500,
                taker_fee_bps: 5,
                keeper_reward_bps: 100,
                spot_only,
                funding_rate: false,
                usd_per_unit: 0,
                funding_cap_bps: 0,
            },
            secret,
        )
    }

    fn propose(parents: Vec<UnitId>, secret: &[u8; 32], key: u8, value: u64) -> Unit {
        sign_unit(
            parents,
            Op::CreateProposal {
                creator: acct_of(secret),
                market: BTC_USD,
                key,
                value,
            },
            secret,
        )
    }

    fn cast_vote(parents: Vec<UnitId>, secret: &[u8; 32], proposal_id: u64, approve: bool) -> Unit {
        sign_unit(
            parents,
            Op::Vote {
                voter: acct_of(secret),
                proposal_id,
                approve,
            },
            secret,
        )
    }

    fn finalize(parents: Vec<UnitId>, secret: &[u8; 32], proposal_id: u64) -> Unit {
        sign_unit(
            parents,
            Op::FinalizeProposal {
                caller: acct_of(secret),
                proposal_id,
            },
            secret,
        )
    }

    #[test]
    fn gov_perp_deposit_withdraw_roundtrip() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        let d = gov_dep(vec![g], &sk(1), 5_000, 7);
        eng.ingest(d).unwrap();
        assert_eq!(eng.state.perp_balances[&acct_of(&sk(1))], 5_000);
        assert_eq!(eng.state.perp_supply, 5_000);
        // Unbacked PERP deposits bounce like unbacked collateral ones.
        eng.state.deposits_allowed.clear();
        let bad = gov_dep(vec![g], &sk(2), 1, 9);
        let evs = eng.ingest(bad).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::UnbackedDeposit,
                ..
            }
        )));
        eng.state.deposits_allowed = (0u8..=255)
            .flat_map(|b| [([b; 32], false), ([b; 32], true)])
            .collect();
        let w = gov_with(vec![g], &sk(1), 2_000, 1);
        eng.ingest(w).unwrap();
        assert_eq!(eng.state.perp_balances[&acct_of(&sk(1))], 3_000);
        assert_eq!(eng.state.perp_supply, 3_000);
        // A spent nonce cannot be replayed even with different amounts.
        let replay = gov_with(vec![g], &sk(1), 1_000, 1);
        let evs = eng.ingest(replay).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::DuplicateNonce,
                ..
            }
        )));
        // Over-withdrawal bounces.
        let over = gov_with(vec![g], &sk(1), 9_999, 2);
        let evs = eng.ingest(over).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::Insufficient,
                ..
            }
        )));
        assert_eq!(eng.state.perp_balances[&acct_of(&sk(1))], 3_000);
    }

    #[test]
    fn create_market_burns_exact_fee_and_allocates_ids() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        let d = gov_dep(vec![g], &sk(1), CREATE_MARKET_FEE_PERP, 7);
        let tip = unit_id(&d);
        eng.ingest(d).unwrap();
        let cm = list_market(vec![tip], &sk(1));
        let evs = eng.ingest(cm).unwrap();
        assert!(evs.iter().all(|e| matches!(e, ExecEvent::Applied { .. })));
        // Fee burned exactly: balance zeroed, supply shrunk, burned grown.
        assert_eq!(eng.state.perp_balances[&acct_of(&sk(1))], 0);
        assert_eq!(eng.state.perp_supply, 0);
        assert_eq!(eng.state.perp_burned, CREATE_MARKET_FEE_PERP);
        assert_eq!(eng.state.next_market_id, 3);
        let params = eng.state.markets[&MarketId(2)];
        assert_eq!(&params.symbol[..6], b"ETHUSD");
        assert!(!params.delisted);
        // Listing without balance fails and must not burn an id or fee.
        let cm2 = list_market(vec![tip], &sk(2));
        let evs = eng.ingest(cm2).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::Insufficient,
                ..
            }
        )));
        assert_eq!(eng.state.next_market_id, 3);
        assert_eq!(eng.state.perp_burned, CREATE_MARKET_FEE_PERP);
    }

    #[test]
    fn duplicate_vote_rejected() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        let d = gov_dep(vec![g], &sk(1), 2_000, 7);
        let tip = unit_id(&d);
        eng.ingest(d).unwrap();
        let p = propose(vec![tip], &sk(1), 2, 10);
        let tip = unit_id(&p);
        eng.ingest(p).unwrap();
        let v1 = cast_vote(vec![tip], &sk(1), 1, true);
        let tip = unit_id(&v1);
        eng.ingest(v1).unwrap();
        assert_eq!(eng.state.proposals[&1].yes, 2_000);
        // Second ballot from the same voter flips to a rejection.
        let v2 = cast_vote(vec![tip], &sk(1), 1, false);
        let evs = eng.ingest(v2).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::Risk,
                ..
            }
        )));
        assert_eq!(eng.state.proposals[&1].yes, 2_000);
        assert_eq!(eng.state.proposals[&1].no, 0);
        assert_eq!(eng.state.proposals[&1].voted.len(), 1);
    }

    #[test]
    fn pre_deadline_and_unknown_finalize_rejected() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        let d = gov_dep(vec![g], &sk(1), 2_000, 7);
        let tip = unit_id(&d);
        eng.ingest(d).unwrap();
        let p = propose(vec![tip], &sk(1), 2, 10);
        eng.ingest(p).unwrap();
        // Finalizing before the voting window closes bounces.
        let early = finalize(vec![g], &sk(2), 1);
        let evs = eng.ingest(early).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::Risk,
                ..
            }
        )));
        // Still open before the deadline — removal happens only at finalize.
        assert!(eng.state.proposals.contains_key(&1));
        // Unknown proposal id bounces with NoProposal.
        let ghost = finalize(vec![g], &sk(2), 99);
        let evs = eng.ingest(ghost).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::NoProposal,
                ..
            }
        )));
    }

    #[test]
    fn quorum_fail_keeps_params_intact() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        // Supply 100_000; only 1_000 (1%) votes yes — below the 10% quorum.
        let da = gov_dep(vec![g], &sk(1), 1_000, 7);
        let db = gov_dep(vec![g], &sk(2), 99_000, 8);
        eng.ingest(da).unwrap();
        eng.ingest(db).unwrap();
        let p = propose(vec![g], &sk(1), 0, 1500);
        eng.ingest(p).unwrap();
        let v = cast_vote(vec![g], &sk(1), 1, true);
        eng.ingest(v).unwrap();
        eng.state.seq = eng.state.proposals[&1].deadline_seq;
        let fin = finalize(vec![g], &sk(2), 1);
        let _evs = eng.ingest(fin).unwrap();
        // The failed proposal is removed at finalize; params stay intact.
        assert!(!eng.state.proposals.contains_key(&1));
        // Genesis im_bps untouched.
        assert_eq!(eng.state.markets[&BTC_USD].im_bps, 1000);
    }

    #[test]
    fn proposal_keeper_reward_respects_listing_cap() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        let da = gov_dep(vec![g], &sk(1), 1_000, 7);
        eng.ingest(da).unwrap();
        // 1000 bps keeper reward is above the 500 bps listing cap: the
        // proposal itself must be rejected, not merely dropped at finalize.
        let p = propose(vec![g], &sk(1), 3, 1_000);
        let evs = eng.ingest(p).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::Risk,
                ..
            }
        )));
        assert!(eng.state.proposals.is_empty());
        assert_eq!(eng.state.markets[&BTC_USD].keeper_reward_bps, 100);
    }

    #[test]
    fn zero_mark_market_order_rejected() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        // List market 2; it has no mark (genesis marks BTC_USD only).
        let d = gov_dep(vec![g], &sk(1), CREATE_MARKET_FEE_PERP, 7);
        let tip = unit_id(&d);
        eng.ingest(d).unwrap();
        let cm = list_market(vec![tip], &sk(1));
        let tip = unit_id(&cm);
        eng.ingest(cm).unwrap();
        let meme = MarketId(2);
        assert!(!eng.state.marks.contains_key(&meme));
        // Zero deposit: px_est = 0 would previously estimate IM as 0 and
        // pass the margin gate.
        let p = place_on(
            vec![tip],
            &sk(2),
            meme,
            Side::Bid,
            OrderType::Market,
            TimeInForce::Ioc,
            0,
            QTY_SCALE,
            1,
        );
        let evs = eng.ingest(p).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::Risk,
                ..
            }
        )));
        // With exactly MIN_OPEN_EQUITY ($1) deposited the same market order
        // must still bounce: the $1 deposit is not what blocks it — the
        // missing mark is.
        let d2 = deposit(vec![tip], &sk(2), MIN_OPEN_EQUITY, 2);
        let tip2 = unit_id(&d2);
        eng.ingest(d2).unwrap();
        let p2 = place_on(
            vec![tip2],
            &sk(2),
            meme,
            Side::Bid,
            OrderType::Market,
            TimeInForce::Ioc,
            0,
            QTY_SCALE,
            1,
        );
        let evs = eng.ingest(p2).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::Risk,
                ..
            }
        )));
        assert!(eng
            .state
            .accounts
            .get(&acct_of(&sk(2)))
            .map(|a| a.positions.is_empty())
            .unwrap_or(true));
    }

    #[test]
    fn live_order_cap() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        let alice = sk(1);
        let d = deposit(vec![g], &alice, 10_000 * USD_SCALE as i128, 1);
        let mut tip = unit_id(&d);
        eng.ingest(d).unwrap();
        // 64 small resting limits on the marked BTC market: bid under the
        // mark, so they rest without crossing.
        let px = 50_000 * PRICE_SCALE as i64;
        let qty = QTY_SCALE / 100;
        for seq in 1..=MAX_LIVE_ORDERS_PER_ACCOUNT as u64 {
            let o = place(
                vec![tip],
                &alice,
                Side::Bid,
                OrderType::Limit,
                TimeInForce::Gtc,
                px,
                qty,
                seq,
            );
            tip = unit_id(&o);
            let evs = eng.ingest(o).unwrap();
            assert!(evs.iter().all(|e| matches!(e, ExecEvent::Applied { .. })));
        }
        let live = |eng: &Engine| {
            eng.state
                .books
                .values()
                .map(|b| {
                    b.live_orders()
                        .filter(|o| o.account == acct_of(&alice))
                        .count()
                })
                .sum::<usize>()
        };
        assert_eq!(live(&eng), 64);
        // The 65th is Risk even though it would never rest (cap applies
        // before submission, not to resting state only).
        let o65 = place(
            vec![tip],
            &alice,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty,
            65,
        );
        let evs = eng.ingest(o65).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::Risk,
                ..
            }
        )));
        assert_eq!(live(&eng), 64);
    }

    #[test]
    fn passed_delist_blocks_place_but_not_cancel() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        let alice = sk(1);
        eng.state
            .accounts
            .entry(acct_of(&alice))
            .or_insert_with(|| operp_account::Account::new(acct_of(&alice)))
            .credit(1_000_000 * USD_SCALE as i128)
            .unwrap();
        // Resting limit bid far below the mark survives untouched.
        eng.ingest(place(
            vec![g],
            &alice,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            50_000 * PRICE_SCALE as i64,
            QTY_SCALE,
            1,
        ))
        .unwrap();
        // Full-supply yes vote passes the delist proposal.
        let d = gov_dep(vec![g], &alice, 100_000, 7);
        let tip = unit_id(&d);
        eng.ingest(d).unwrap();
        let p = propose(vec![tip], &alice, 4, 0);
        let tip = unit_id(&p);
        eng.ingest(p).unwrap();
        let v = cast_vote(vec![tip], &alice, 1, true);
        eng.ingest(v).unwrap();
        assert_eq!(eng.state.proposals[&1].supply_at_create, 100_000);
        eng.state.seq = eng.state.proposals[&1].deadline_seq;
        let fin = finalize(vec![g], &alice, 1);
        let evs = eng.ingest(fin).unwrap();
        assert!(evs.iter().all(|e| matches!(e, ExecEvent::Applied { .. })));
        // The passed proposal is consumed; the delist itself is applied.
        assert!(!eng.state.proposals.contains_key(&1));
        assert!(eng.state.markets[&BTC_USD].delisted);
        // New orders on a delisted market bounce.
        let reentry = place(
            vec![g],
            &alice,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            51_000 * PRICE_SCALE as i64,
            QTY_SCALE,
            2,
        );
        let evs = eng.ingest(reentry).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::Risk,
                ..
            }
        )));
        // Cancelling the pre-delist order still works.
        let c = sign_unit(
            vec![g],
            Op::Cancel {
                account: acct_of(&alice),
                order_id: order_id(acct_of(&alice), BTC_USD, 1),
            },
            &alice,
        );
        let evs = eng.ingest(c).unwrap();
        assert!(evs
            .iter()
            .all(|e| matches!(e, ExecEvent::Applied { fills, .. } if fills.is_empty())));
    }

    #[test]
    fn flip_position_requires_full_im() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        let alice = sk(1);
        let bob = sk(2);
        let d1 = deposit(vec![g], &alice, 15_000 * USD_SCALE as i128, 1);
        let mut tip = unit_id(&d1);
        eng.ingest(d1).unwrap();
        let d2 = deposit(vec![tip], &bob, 1_000_000 * USD_SCALE as i128, 2);
        tip = unit_id(&d2);
        eng.ingest(d2).unwrap();
        let px = 100_000 * PRICE_SCALE as i64;
        let ask = place(
            vec![tip],
            &bob,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE,
            1,
        );
        tip = unit_id(&ask);
        eng.ingest(ask).unwrap();
        // Alice is long 1 BTC with just enough margin for that position.
        let bid = place(
            vec![tip],
            &alice,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE,
            1,
        );
        tip = unit_id(&bid);
        eng.ingest(bid).unwrap();
        // Flipping to short 2 BTC opens 1 net BTC: it must post full IM for
        // the opened leg, which her ~15k equity cannot cover (10k IM on the
        // open + maintenance on the existing one) → Risk.
        let evs = eng
            .ingest(place(
                vec![tip],
                &alice,
                Side::Ask,
                OrderType::Limit,
                TimeInForce::Gtc,
                px,
                2 * QTY_SCALE,
                2,
            ))
            .unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::Risk,
                ..
            }
        )));
    }

    #[test]
    fn create_market_bps_over_cap_rejected() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        let d = gov_dep(vec![g], &sk(1), CREATE_MARKET_FEE_PERP, 7);
        let tip = unit_id(&d);
        eng.ingest(d).unwrap();
        let mut symbol = [0u8; 16];
        symbol[..6].copy_from_slice(b"ETHUSD");
        let cm = sign_unit(
            vec![tip],
            Op::CreateMarket {
                creator: acct_of(&sk(1)),
                symbol,
                tick_size: 1,
                im_bps: 1000,
                mm_bps: 500,
                taker_fee_bps: 5,
                keeper_reward_bps: 20_000, // 200% — unbounded keeper drain
                spot_only: false,
                funding_rate: false,
                usd_per_unit: 0,
                funding_cap_bps: 0,
            },
            &sk(1),
        );
        let evs = eng.ingest(cm).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::Risk,
                ..
            }
        )));
        assert_eq!(eng.state.next_market_id, 2);
        assert_eq!(
            eng.state.perp_balances[&acct_of(&sk(1))],
            CREATE_MARKET_FEE_PERP
        );
    }
    #[test]
    fn spot_only_market_rejects_all_price_reports() {
        let mut eng = activated_engine();
        let g = genesis_id();
        let d = gov_dep(vec![g], &sk(1), CREATE_MARKET_FEE_PERP, 7);
        let tip = unit_id(&d);
        eng.ingest(d).unwrap();
        let cm = list_market_with(vec![tip], &sk(1), true);
        let tip = unit_id(&cm);
        let evs = eng.ingest(cm).unwrap();
        assert!(!evs.iter().any(|e| matches!(e, ExecEvent::Rejected { .. })));
        let meme = MarketId(2);
        assert!(eng.state.markets[&meme].spot_only);
        // Bonded reporter: ReportPrice on the spot market bounces as NotFound.
        eng.state
            .oracle_bonds
            .insert(acct_of(&sk(5)), ORACLE_BOND_PERP);
        let r = sign_unit(
            vec![tip],
            Op::ReportPrice {
                oracle: acct_of(&sk(5)),
                market: meme,
                price: 100 * PRICE_SCALE as i64,
            },
            &sk(5),
        );
        let evs = eng.ingest(r).unwrap();
        assert!(matches!(
            evs.last(),
            Some(ExecEvent::Rejected {
                reason: RejectReason::NotFound,
                ..
            })
        ));
        // Same reporter on the genesis market still reports fine: the gate
        // is per-market, not per-reporter.
        let r2 = sign_unit(
            vec![tip],
            Op::ReportPrice {
                oracle: acct_of(&sk(5)),
                market: BTC_USD,
                price: 100_000 * PRICE_SCALE as i64,
            },
            &sk(5),
        );
        let evs2 = eng.ingest(r2).unwrap();
        assert!(!evs2.iter().any(|e| matches!(e, ExecEvent::Rejected { .. })));
        // Allowlisted keeper: UpdateExternalPrice on the spot market bounces
        // as NotFound once the external anchor is live.
        eng.state.height = operp_types::FUNDING_TWAP_ACTIVATION_HEIGHT;
        eng.state.funding_source = operp_types::FundingSourceKind::AggregatedExternal;
        eng.state.external_sources.insert(acct_of(&sk(9)));
        let x = sign_unit(
            vec![tip],
            Op::UpdateExternalPrice {
                source: acct_of(&sk(9)),
                market: meme,
                price: 100 * PRICE_SCALE as i64,
                source_id: 0,
            },
            &sk(9),
        );
        let evs3 = eng.ingest(x).unwrap();
        assert!(matches!(
            evs3.last(),
            Some(ExecEvent::Rejected {
                reason: RejectReason::NotFound,
                ..
            })
        ));
        assert!(eng.state.external_price_ring.is_empty());
    }

    #[test]
    fn spot_only_market_fill_sets_mark_without_funding() {
        let mut eng = activated_engine();
        let g = genesis_id();
        // Fresh creator (sk(3)): gov_dep binds its withdrawal address, so it
        // must not double as a collateral depositor below.
        let d = gov_dep(vec![g], &sk(3), CREATE_MARKET_FEE_PERP, 7);
        let mut tip = unit_id(&d);
        eng.ingest(d).unwrap();
        let cm = list_market_with(vec![tip], &sk(3), true);
        tip = unit_id(&cm);
        eng.ingest(cm).unwrap();
        let meme = MarketId(2);
        // Collateral for both sides, then crossing limit orders on the spot
        // market with notional far above the 100 USD mark-setting floor.
        let alice = sk(1);
        let bob = sk(2);
        let d1 = deposit(vec![tip], &alice, 1_000_000 * USD_SCALE as i128, 1);
        tip = unit_id(&d1);
        eng.ingest(d1).unwrap();
        let d2 = deposit(vec![tip], &bob, 1_000_000 * USD_SCALE as i128, 2);
        tip = unit_id(&d2);
        eng.ingest(d2).unwrap();
        let px = 100_000 * PRICE_SCALE as i64;
        let ask = place_on(
            vec![tip],
            &bob,
            meme,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE,
            1,
        );
        tip = unit_id(&ask);
        let ask_evs = eng.ingest(ask).unwrap();
        assert!(
            ask_evs
                .iter()
                .all(|e| !matches!(e, ExecEvent::Rejected { .. })),
            "ask rejected: {ask_evs:?}"
        );
        let bid = place_on(
            vec![tip],
            &alice,
            meme,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE,
            1,
        );
        tip = unit_id(&bid);
        let evs = eng.ingest(bid).unwrap();
        assert!(
            evs.iter().any(|e| matches!(
                e,
                ExecEvent::Applied { fills, .. } if !fills.is_empty()
            )),
            "no fill; events={evs:?}"
        );
        // First qualifying fill writes the mark even though no oracle ever
        // speaks for this market.
        assert_eq!(eng.state.marks.get(&meme).copied(), Some(px));
        // No funding index exists for the market: with every report
        // rejected, `prices.len() >= 2` can never hold, so funding stays
        // silent by construction.
        assert!(!eng.state.last_index.contains_key(&meme));
        // A rejected report moves neither mark nor funding state.
        eng.state
            .oracle_bonds
            .insert(acct_of(&sk(5)), ORACLE_BOND_PERP);
        let r = sign_unit(
            vec![tip],
            Op::ReportPrice {
                oracle: acct_of(&sk(5)),
                market: meme,
                price: 200_000 * PRICE_SCALE as i64,
            },
            &sk(5),
        );
        eng.ingest(r).unwrap();
        assert_eq!(eng.state.marks.get(&meme).copied(), Some(px));
        assert!(!eng.state.last_index.contains_key(&meme));
    }
    #[test]
    fn negative_price_short_lifecycle_pnl_sign() {
        // Short 1 @ -100k, cover @ -110k: falling deeper-negative is a
        // profit for the short, +10k into the maker's collateral exactly
        // (maker pays no taker fee).
        let mut eng = activated_engine();
        let g = genesis_id();
        // Fresh plain market (id 2, no genesis mark): the first negative
        // fill sets the mark unconditionally; stepping from the +100k
        // mkt genesis mark would need dozens of capped reports.
        let gd = gov_dep(vec![g], &sk(3), CREATE_MARKET_FEE_PERP, 7);
        let mut tip = unit_id(&gd);
        eng.ingest(gd).unwrap();
        let cm = list_market_with(vec![tip], &sk(3), false);
        tip = unit_id(&cm);
        eng.ingest(cm).unwrap();
        let mkt = MarketId(2);
        let alice = sk(1);
        let bob = sk(2);
        let d1 = deposit(vec![tip], &alice, 1_000_000 * USD_SCALE as i128, 1);
        tip = unit_id(&d1);
        eng.ingest(d1).unwrap();
        let d2 = deposit(vec![tip], &bob, 1_000_000 * USD_SCALE as i128, 2);
        tip = unit_id(&d2);
        eng.ingest(d2).unwrap();
        let open = -100_000 * PRICE_SCALE as i64;
        let ask = place_on(
            vec![tip],
            &bob,
            mkt,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            open,
            QTY_SCALE,
            1,
        );
        tip = unit_id(&ask);
        eng.ingest(ask).unwrap();
        let bid = place_on(
            vec![tip],
            &alice,
            mkt,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            open,
            QTY_SCALE,
            1,
        );
        tip = unit_id(&bid);
        eng.ingest(bid).unwrap();
        assert_eq!(eng.state.marks.get(&mkt).copied(), Some(open));
        // Cover leg 10k lower (more negative).
        let cover = -110_000 * PRICE_SCALE as i64;
        // Bob rests the cover bid first so he stays maker on both legs;
        // alice takes twice.
        let bid2 = place_on(
            vec![tip],
            &bob,
            mkt,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            cover,
            QTY_SCALE,
            2,
        );
        tip = unit_id(&bid2);
        eng.ingest(bid2).unwrap();
        let ask2 = place_on(
            vec![tip],
            &alice,
            mkt,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            cover,
            QTY_SCALE,
            2,
        );
        eng.ingest(ask2).unwrap();
        // Unoracled freeze: once a non-zero mark exists with no reporter
        // index, a further fill must not walk it — the mark stays at the
        // first print. Realization uses fill price, not mark, so PnL below
        // is unaffected.
        assert_eq!(eng.state.marks.get(&mkt).copied(), Some(open));
        assert!(eng.state.accounts[&acct_of(&bob)].positions.is_empty());
        assert!(eng.state.accounts[&acct_of(&alice)].positions.is_empty());
        // Bob (maker both legs): 1M + 10k realized, no fee legs.
        assert_eq!(
            eng.state.accounts[&acct_of(&bob)].collateral,
            1_010_000 * USD_SCALE as i128
        );
        // Alice (taker both legs): 1M - 10k PnL - both taker fees.
        assert!(eng.state.accounts[&acct_of(&alice)].collateral < 990_000 * USD_SCALE as i128);
    }

    #[test]
    fn spot_only_negative_fill_sets_mark_without_funding() {
        // Joint regression: spot_only gate × signed prices. A negative fill
        // on a spot market writes a negative mark and still accrues no
        // funding index.
        let mut eng = activated_engine();
        let g = genesis_id();
        let d = gov_dep(vec![g], &sk(3), CREATE_MARKET_FEE_PERP, 7);
        let mut tip = unit_id(&d);
        eng.ingest(d).unwrap();
        let cm = list_market_with(vec![tip], &sk(3), true);
        tip = unit_id(&cm);
        eng.ingest(cm).unwrap();
        let meme = MarketId(2);
        let alice = sk(1);
        let bob = sk(2);
        let d1 = deposit(vec![tip], &alice, 1_000_000 * USD_SCALE as i128, 1);
        tip = unit_id(&d1);
        eng.ingest(d1).unwrap();
        let d2 = deposit(vec![tip], &bob, 1_000_000 * USD_SCALE as i128, 2);
        tip = unit_id(&d2);
        eng.ingest(d2).unwrap();
        let px = -100_000 * PRICE_SCALE as i64;
        let ask = place_on(
            vec![tip],
            &bob,
            meme,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE,
            1,
        );
        tip = unit_id(&ask);
        eng.ingest(ask).unwrap();
        let bid = place_on(
            vec![tip],
            &alice,
            meme,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE,
            1,
        );
        let evs = eng.ingest(bid).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Applied { fills, .. } if !fills.is_empty()
        )));
        assert_eq!(eng.state.marks.get(&meme).copied(), Some(px));
        assert!(!eng.state.last_index.contains_key(&meme));
    }

    #[test]
    fn misaligned_tick_limit_rejected() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        eng.state.markets.insert(
            BTC_USD,
            operp_types::MarketParams {
                symbol: [0u8; 16],
                tick_size: 100 * operp_types::PRICE_SCALE as i64,
                im_bps: operp_types::IM_RATE_BPS,
                mm_bps: operp_types::MM_RATE_BPS,
                taker_fee_bps: operp_types::TAKER_FEE_BPS,
                keeper_reward_bps: operp_types::KEEPER_REWARD_BPS,
                delisted: false,
                spot_only: false,
                funding_rate: false,
                usd_per_unit: 0,
                funding_cap_bps: 0,
            },
        );
        eng.state
            .accounts
            .entry(acct_of(&sk(1)))
            .or_insert_with(|| operp_account::Account::new(acct_of(&sk(1))))
            .credit(1_000_000 * USD_SCALE as i128)
            .unwrap();
        // 150.5 is off the 100-grid → Risk; Market orders stay exempt.
        let evs = eng
            .ingest(place(
                vec![genesis_id()],
                &sk(1),
                Side::Bid,
                OrderType::Limit,
                TimeInForce::Gtc,
                150_500 * PRICE_SCALE as i64 / 1000,
                QTY_SCALE,
                1,
            ))
            .unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::Risk,
                ..
            }
        )));
    }

    #[test]
    fn rejected_unit_does_not_consume_seq() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        let alice = sk(1);
        let d = deposit(vec![g], &alice, 10_000 * USD_SCALE as i128, 1);
        let mut tip = unit_id(&d);
        eng.ingest(d).unwrap();
        let applied_before = eng.state.seq;
        // A place with a stale client_seq is rejected...
        let bad = sign_unit(
            vec![tip],
            Op::Place {
                account: acct_of(&alice),
                market: BTC_USD,
                side: Side::Bid,
                typ: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: 90_000 * PRICE_SCALE as i64,
                qty: QTY_SCALE,
                client_seq: 99,
                isolated: false,
                margin: 0,
            },
            &alice,
        );
        tip = unit_id(&bad);
        let evs = eng.ingest(bad).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::DuplicateClientSeq,
                ..
            }
        )));
        // ...and must not advance the sequence counter.
        assert_eq!(eng.state.seq, applied_before);
        // The next valid unit still gets exactly the next seq number.
        let good = place(
            vec![tip],
            &alice,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            90_000 * PRICE_SCALE as i64,
            QTY_SCALE,
            1,
        );
        eng.ingest(good).unwrap();
        assert_eq!(eng.state.seq, applied_before + 1);
    }

    #[test]
    fn vote_uses_creation_weight_snapshot() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        let d = gov_dep(vec![g], &sk(1), 2_000, 7);
        let tip = unit_id(&d);
        eng.ingest(d).unwrap();
        let p = propose(vec![tip], &sk(1), 2, 10);
        let tip = unit_id(&p);
        eng.ingest(p).unwrap();
        // The creator burns her whole balance AFTER proposal creation.
        let burn = gov_with(vec![tip], &sk(1), 2_000, 1);
        eng.ingest(burn).unwrap();
        assert_eq!(eng.state.perp_balances[&acct_of(&sk(1))], 0);
        // Her ballot still carries the snapshot weight of 2_000 PERP.
        let v = cast_vote(vec![tip], &sk(1), 1, true);
        eng.ingest(v).unwrap();
        assert_eq!(eng.state.proposals[&1].yes, 2_000);
        // Finalize consumes the proposal entirely.
        eng.state.seq = eng.state.proposals[&1].deadline_seq;
        let fin = finalize(vec![g], &sk(2), 1);
        let fin_id = unit_id(&fin);
        eng.ingest(fin).unwrap();
        assert!(!eng.state.proposals.contains_key(&1));
        // A second finalize finds nothing and bounces. Its parent set includes
        // the consumed finalize so it is a distinct unit, not a DAG duplicate.
        let mut ps = vec![g, fin_id];
        ps.sort();
        let again = finalize(ps, &sk(2), 1);
        let evs = eng.ingest(again).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::NoProposal,
                ..
            }
        )));
    }

    #[test]
    fn deposit_kinds_are_endorsed_separately() {
        let mut eng = Engine::new();
        // Only a collateral endorsement for unit 5 exists — no PERP one.
        eng.state.deposits_allowed = [([5u8; 32], false)].into_iter().collect();
        eng.state
            .markets
            .insert(BTC_USD, operp_types::genesis_params());
        let g = genesis_id();
        eng.ingest(deposit(vec![g], &sk(1), 1_000 * USD_SCALE as i128, 5))
            .unwrap();
        assert_eq!(
            eng.state.accounts[&acct_of(&sk(1))].collateral,
            1_000 * USD_SCALE as i128
        );
        // The same unit must NOT be reusable as a PERP endorsement: the
        // shared seen-unit ledger rejects the exact replay first...
        let evs = eng.ingest(gov_dep(vec![g], &sk(1), 5_000, 5)).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::DuplicateDeposit,
                ..
            }
        )));
        assert_eq!(eng.state.perp_supply, 0);
        // ...and a fresh unit endorsed only for collateral is not PERP-backed
        // either: the (unit, kind) pair binds endorsements to one asset.
        let evs = eng.ingest(gov_dep(vec![g], &sk(2), 5_000, 6)).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::UnbackedDeposit,
                ..
            }
        )));
        assert_eq!(eng.state.perp_supply, 0);
    }

    #[test]
    fn deposit_addr_binding_enforced() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        let account = acct_of(&sk(1));
        // Malformed address bounces outright.
        let bad_addr = sign_unit(
            vec![g],
            Op::Deposit {
                account,
                addr: "NOT_AN_OBYTE_ADDR".to_string(),
                amount: 100 * USD_SCALE as i128,
                aa_unit: [1; 32],
            },
            &sk(1),
        );
        let evs = eng.ingest(bad_addr).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::BadAccount,
                ..
            }
        )));
        // First valid deposit binds B...
        eng.ingest(deposit(vec![g], &sk(1), 1_000 * USD_SCALE as i128, 1))
            .unwrap();
        assert_eq!(eng.state.aa_addresses.get(&account).unwrap(), &test_addr(1));
        // ...and rebinding to a different address is refused.
        let rebind = sign_unit(
            vec![g],
            Op::Deposit {
                account,
                addr: test_addr(2),
                amount: 100 * USD_SCALE as i128,
                aa_unit: [2; 32],
            },
            &sk(1),
        );
        let evs = eng.ingest(rebind).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::BadAccount,
                ..
            }
        )));
        assert_eq!(eng.state.aa_addresses.get(&account).unwrap(), &test_addr(1));
    }

    #[test]
    fn gov_withdraw_nonce_watermark_is_strict() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        eng.ingest(gov_dep(vec![g], &sk(1), 10_000, 7)).unwrap();
        // nonce 3 applies and lifts the watermark to 3...
        eng.ingest(gov_with(vec![g], &sk(1), 1_000, 3)).unwrap();
        // ...so nonces 1 and 2 (below the watermark) are replays even though
        // they were never used, while nonce 4 is fine.
        for stale in [1u64, 2u64, 3u64] {
            let evs = eng.ingest(gov_with(vec![g], &sk(1), 100, stale)).unwrap();
            assert!(evs.iter().any(|e| matches!(
                e,
                ExecEvent::Rejected {
                    reason: RejectReason::DuplicateNonce,
                    ..
                }
            )));
        }
        eng.ingest(gov_with(vec![g], &sk(1), 100, 4)).unwrap();
        assert_eq!(eng.state.seen_gov_nonces[&acct_of(&sk(1))], 4);
    }

    /// Gap 11 acceptance: the gov-nonce watermark survives a node restart
    /// via the WAL, so replays below it keep bouncing.
    #[test]
    fn gov_nonce_watermark_survives_restart() {
        let dir = std::env::temp_dir().join(format!("operp-g11-wal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut eng = Engine::load_or_genesis(&dir).unwrap();
        allow_all(&mut eng);
        let g = genesis_id();
        eng.ingest(gov_dep(vec![g], &sk(1), 10_000, 7)).unwrap();
        // WAL record is fsynced inside gov_withdraw before the watermark moves.
        eng.ingest(gov_with(vec![g], &sk(1), 1_000, 5)).unwrap();
        assert_eq!(eng.state.seen_gov_nonces[&acct_of(&sk(1))], 5);

        // Snapshot balances/dedup maps, then crash: the journal alone covers
        // the watermark, the snapshot covers everything else.
        eng.flush_snapshot().unwrap();
        let mut eng2 = Engine::load_or_genesis(&dir).unwrap();
        allow_all(&mut eng2);
        assert_eq!(eng2.state.seen_gov_nonces[&acct_of(&sk(1))], 5);
        // Lower nonce still rejected; higher nonce applies and re-journals.
        let evs = eng2.ingest(gov_with(vec![g], &sk(1), 50, 4)).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::DuplicateNonce,
                ..
            }
        )));
        eng2.ingest(gov_with(vec![g], &sk(1), 50, 6)).unwrap();
        assert_eq!(eng2.state.seen_gov_nonces[&acct_of(&sk(1))], 6);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Gap 11 acceptance: collateral withdrawals and PERP deposits deduped by
    /// `withdrawals` / `seen_aa_units` survive a restart via snapshot load.
    #[test]
    fn withdraw_and_deposit_dedup_survive_restart() {
        let dir = std::env::temp_dir().join(format!("operp-g11-snap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut eng = Engine::load_or_genesis(&dir).unwrap();
        allow_all(&mut eng);
        let g = genesis_id();
        let alice = sk(1);
        let account = acct_of(&alice);
        eng.ingest(deposit(vec![g], &alice, 10_000 * USD_SCALE as i128, 1))
            .unwrap();
        // Withdraw collateral (nonce 7) and deposit PERP (distinct aa unit,
        // same bound address).
        let wd = sign_unit(
            vec![g],
            Op::Withdraw {
                account,
                amount: 100 * USD_SCALE as i128,
                nonce: 7,
            },
            &alice,
        );
        eng.ingest(wd).unwrap();
        let gd = sign_unit(
            vec![g],
            Op::GovDeposit {
                account,
                addr: test_addr(1), // must match the account's bound address
                amount: 500,
                aa_unit: [9u8; 32],
            },
            &alice,
        );
        let evs_gd = eng.ingest(gd).unwrap();
        assert!(evs_gd
            .iter()
            .any(|e| matches!(e, ExecEvent::Applied { .. })));

        // Snapshot + restart.
        eng.flush_snapshot().unwrap();
        let mut eng2 = Engine::load_or_genesis(&dir).unwrap();
        allow_all(&mut eng2);
        assert!(eng2.state.withdrawals.contains_key(&(account, 7)));

        // Same withdraw nonce after restart → DuplicateNonce.
        let dup = sign_unit(
            vec![g],
            Op::Withdraw {
                account,
                amount: 100 * USD_SCALE as i128,
                nonce: 7,
            },
            &alice,
        );
        let evs = eng2.ingest(dup).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::DuplicateNonce,
                ..
            }
        )));
        // Reused aa_unit after restart → DuplicateDeposit (collateral kind).
        let dep2 = deposit(vec![g], &sk(3), 100 * USD_SCALE as i128, 9);
        let evs = eng2.ingest(dep2).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::DuplicateDeposit,
                ..
            }
        )));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Reference implementation of the Phase-2 salt derivation contract:
    /// sha256(ORDERING_SALT_DOMAIN || finalized_root || epoch_le).
    fn derived_salt(root: [u8; 32], height: u64) -> [u8; 32] {
        let epoch = (height / operp_types::ORDERING_EPOCH_UNITS).to_le_bytes();
        let mut buf = Vec::with_capacity(operp_types::ORDERING_SALT_DOMAIN.len() + 64);
        buf.extend_from_slice(operp_types::ORDERING_SALT_DOMAIN);
        buf.extend_from_slice(&root);
        buf.extend_from_slice(&epoch);
        operp_types::sha256(&buf)
    }

    #[test]
    fn note_finalized_salt_stable_per_root_and_epoch() {
        // Same root + same epoch → same salt (stability).
        let mut e1 = Engine::new();
        let mut e2 = Engine::new();
        let root = [0xABu8; 32];
        e1.note_finalized(root, 0);
        e2.note_finalized(root, operp_types::ORDERING_EPOCH_UNITS - 1);
        assert_eq!(e1.dag.eviction_salt(), derived_salt(root, 0));
        assert_eq!(e2.dag.eviction_salt(), derived_salt(root, 0));
        assert_eq!(e1.dag.eviction_salt(), e2.dag.eviction_salt());

        // Different epoch (same root) → different salt (rotation).
        let mut e3 = Engine::new();
        e3.note_finalized(root, operp_types::ORDERING_EPOCH_UNITS);
        assert_ne!(e1.dag.eviction_salt(), e3.dag.eviction_salt());
        assert_eq!(
            e3.dag.eviction_salt(),
            derived_salt(root, operp_types::ORDERING_EPOCH_UNITS)
        );

        // Different root → different salt.
        let mut e4 = Engine::new();
        e4.note_finalized([0xCDu8; 32], 0);
        assert_ne!(e1.dag.eviction_salt(), e4.dag.eviction_salt());
    }

    #[test]
    fn eviction_rotation_is_deterministic_and_epoch_bound() {
        use operp_dag::{genesis_id, unit_id};
        // Build an engine holding several ready units, then check that the
        // post-finalization ordering is a pure function of (root, epoch):
        // two engines with the same finalize inputs produce identical order,
        // and crossing an epoch boundary rotates it deterministically.
        let mk = |eng: &mut Engine| -> Vec<operp_types::UnitId> {
            allow_all(eng);
            let g = genesis_id();
            let mut ids = Vec::new();
            let mut prev = g;
            for n in 1u8..=6 {
                let secret = [n; 32];
                let account = acct_of(&secret);
                let u = sign_unit(
                    vec![prev],
                    Op::Place {
                        account,
                        market: BTC_USD,
                        side: Side::Bid,
                        typ: OrderType::Limit,
                        tif: TimeInForce::Gtc,
                        price: operp_types::PRICE_SCALE as i64 * i64::from(n),
                        qty: QTY_SCALE,
                        client_seq: u64::from(n),
                        isolated: false,
                        margin: 0,
                    },
                    &secret,
                );
                prev = unit_id(&u);
                ids.push(prev);
                eng.ingest(u).unwrap();
            }
            eng.apply_ready();
            ids
        };
        let mut a = Engine::new();
        let _ = mk(&mut a);
        let mut b = Engine::new();
        let _ = mk(&mut b);
        let root = [7u8; 32];
        a.note_finalized(root, 10);
        b.note_finalized(root, 10);
        let ord_a = a.apply_ready();
        let ord_b = b.apply_ready();
        assert_eq!(ord_a, ord_b, "same (root, epoch) must give same order");
        assert_eq!(a.dag.eviction_salt(), derived_salt(root, 10));

        // Same root, next epoch: deterministic rotation.
        let mut c = Engine::new();
        let _ = mk(&mut c);
        c.note_finalized(root, 10 + operp_types::ORDERING_EPOCH_UNITS);
        let ord_c1 = c.apply_ready();
        let mut d = Engine::new();
        let _ = mk(&mut d);
        d.note_finalized(root, 10 + operp_types::ORDERING_EPOCH_UNITS);
        assert_eq!(ord_c1, d.apply_ready());
    }

    // -------------------------------------------------------------------
    // Commit-reveal ordering v2 (doc 03 §2.3) — reveal semantics

    fn commit_unit(
        parents: Vec<UnitId>,
        secret: &[u8; 32],
        commit: [u8; 32],
        ttl_height: Height,
    ) -> Unit {
        sign_unit(
            parents,
            Op::Commit {
                account: acct_of(secret),
                commit,
                ttl_height,
            },
            secret,
        )
    }

    /// Engine past the v2 activation gate with deposit admission open.
    fn activated_engine() -> Engine {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        eng.state.height = operp_types::COMMIT_REVEAL_ACTIVATION_HEIGHT;
        eng
    }

    #[test]
    fn commit_then_reveal_executes_inner_place() {
        let mut eng = activated_engine();
        let alice = sk(1);
        let acct = acct_of(&alice);
        let d = deposit(vec![genesis_id()], &alice, 10_000 * USD_SCALE as i128, 1);
        let mut tip = unit_id(&d);
        eng.ingest(d).unwrap();

        let inner = Op::Place {
            account: acct,
            market: BTC_USD,
            side: Side::Bid,
            typ: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: 100 * PRICE_SCALE as i64,
            qty: QTY_SCALE / 1000,
            client_seq: 1,
            isolated: false,
            margin: 0,
        };
        let salt = [7u8; 32];
        let commit_hash = operp_dag::reveal_commit_hash(&inner, &salt);
        let c = commit_unit(
            vec![tip],
            &alice,
            commit_hash,
            eng.state.height + operp_types::COMMIT_TTL_HEIGHTS,
        );
        tip = unit_id(&c);
        let events = eng.ingest(c).unwrap();
        assert!(matches!(events.last(), Some(ExecEvent::Applied { .. })));
        assert_eq!(eng.state.commits[&commit_hash].commit_unit, tip);

        // Reveal parented on the Commit unit (doc §2.3.4) executes the inner
        // op through the normal path.
        let r = sign_unit(
            vec![tip],
            Op::Reveal {
                account: acct,
                commit_ref: commit_hash,
                op: Box::new(inner.clone()),
                salt,
            },
            &alice,
        );
        let events = eng.ingest(r).unwrap();
        assert!(matches!(events.last(), Some(ExecEvent::Applied { .. })));
        // A resting bid proves the inner Place went through the normal
        // intake path (client-seq watermark advanced, order accepted).
        assert_eq!(eng.state.seen_client_seq.get(&acct), Some(&1));
        assert!(eng.state.commits[&commit_hash].revealed);
    }

    #[test]
    fn reveal_without_commit_parent_rejected() {
        let mut eng = activated_engine();
        let alice = sk(1);
        let acct = acct_of(&alice);
        let d = deposit(vec![genesis_id()], &alice, 10_000 * USD_SCALE as i128, 1);
        let tip = unit_id(&d);
        eng.ingest(d).unwrap();
        let inner = Op::Place {
            account: acct,
            market: BTC_USD,
            side: Side::Bid,
            typ: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: 100 * PRICE_SCALE as i64,
            qty: QTY_SCALE / 1000,
            client_seq: 1,
            isolated: false,
            margin: 0,
        };
        let salt = [7u8; 32];
        let commit_hash = operp_dag::reveal_commit_hash(&inner, &salt);
        let c = commit_unit(
            vec![tip],
            &alice,
            commit_hash,
            eng.state.height + operp_types::COMMIT_TTL_HEIGHTS,
        );
        eng.ingest(c).unwrap();
        // Parent is the deposit tip, not the Commit unit → BadCommit and no
        // execution (doc §2.3.4 parent-edge constraint).
        let r = sign_unit(
            vec![tip],
            Op::Reveal {
                account: acct,
                commit_ref: commit_hash,
                op: Box::new(inner),
                salt,
            },
            &alice,
        );
        let events = eng.ingest(r).unwrap();
        assert!(
            matches!(
                events.last(),
                Some(ExecEvent::Rejected {
                    reason: RejectReason::BadCommit,
                    ..
                })
            ),
            "reveal must parent its commit"
        );
        assert!(!eng.state.accounts[&acct].positions.contains_key(&BTC_USD));
    }

    #[test]
    fn reveal_preimage_mismatch_rejected() {
        let mut eng = activated_engine();
        let alice = sk(1);
        let acct = acct_of(&alice);
        let d = deposit(vec![genesis_id()], &alice, 10_000 * USD_SCALE as i128, 1);
        let tip = unit_id(&d);
        eng.ingest(d).unwrap();
        let inner = Op::Place {
            account: acct,
            market: BTC_USD,
            side: Side::Bid,
            typ: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: 100 * PRICE_SCALE as i64,
            qty: QTY_SCALE / 1000,
            client_seq: 1,
            isolated: false,
            margin: 0,
        };
        let salt = [7u8; 32];
        let commit_hash = operp_dag::reveal_commit_hash(&inner, &salt);
        let c = commit_unit(
            vec![tip],
            &alice,
            commit_hash,
            eng.state.height + operp_types::COMMIT_TTL_HEIGHTS,
        );
        let cid = unit_id(&c);
        eng.ingest(c).unwrap();
        // Wrong salt: sha256(op_bytes || salt') != commit_ref.
        let r = sign_unit(
            vec![cid],
            Op::Reveal {
                account: acct,
                commit_ref: commit_hash,
                op: Box::new(inner),
                salt: [8u8; 32],
            },
            &alice,
        );
        let events = eng.ingest(r).unwrap();
        assert!(matches!(
            events.last(),
            Some(ExecEvent::Rejected {
                reason: RejectReason::BadCommit,
                ..
            })
        ));
        assert!(!eng.state.commits[&commit_hash].revealed);
    }

    #[test]
    fn expired_commit_rejected_and_pruned() {
        let mut eng = activated_engine();
        let alice = sk(1);
        let acct = acct_of(&alice);
        let d = deposit(vec![genesis_id()], &alice, 10_000 * USD_SCALE as i128, 1);
        let tip = unit_id(&d);
        eng.ingest(d).unwrap();
        let inner = Op::Place {
            account: acct,
            market: BTC_USD,
            side: Side::Bid,
            typ: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: 100 * PRICE_SCALE as i64,
            qty: QTY_SCALE / 1000,
            client_seq: 1,
            isolated: false,
            margin: 0,
        };
        let salt = [7u8; 32];
        let commit_hash = operp_dag::reveal_commit_hash(&inner, &salt);
        let c = commit_unit(
            vec![tip],
            &alice,
            commit_hash,
            eng.state.height + operp_types::COMMIT_TTL_HEIGHTS,
        );
        let cid = unit_id(&c);
        eng.ingest(c).unwrap();
        // Past the TTL window the slot is wasted: reject and prune at batch
        // commit (doc §2.3.3 rule 4 + §2.3.5).
        eng.state.height += operp_types::COMMIT_TTL_HEIGHTS + 1;
        let r = sign_unit(
            vec![cid],
            Op::Reveal {
                account: acct,
                commit_ref: commit_hash,
                op: Box::new(inner),
                salt,
            },
            &alice,
        );
        let events = eng.ingest(r).unwrap();
        assert!(matches!(
            events.last(),
            Some(ExecEvent::Rejected {
                reason: RejectReason::BadCommit,
                ..
            })
        ));
        eng.state.prune_commits(eng.state.height);
        assert!(!eng.state.commits.contains_key(&commit_hash));
    }

    #[test]
    fn duplicate_commit_and_pending_cap_enforced() {
        let mut eng = activated_engine();
        let alice = sk(1);
        let acct = acct_of(&alice);
        let d = deposit(vec![genesis_id()], &alice, 10_000 * USD_SCALE as i128, 1);
        let mut tip = unit_id(&d);
        eng.ingest(d).unwrap();
        let mk_inner = |seq: u64| Op::Place {
            account: acct,
            market: BTC_USD,
            side: Side::Bid,
            typ: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: 100 * PRICE_SCALE as i64,
            qty: QTY_SCALE / 1000,
            client_seq: seq,
            isolated: false,
            margin: 0,
        };
        // Duplicate commit hash bounces (rule 1); distinct commits up to the
        // per-account cap of 8 are admitted; the 9th bounces (§2.3.5).
        for i in 0..9u64 {
            let inner = mk_inner(i + 1);
            let hash = operp_dag::reveal_commit_hash(&inner, &[i as u8; 32]);
            let c = commit_unit(
                vec![tip],
                &alice,
                hash,
                eng.state.height + operp_types::COMMIT_TTL_HEIGHTS,
            );
            tip = unit_id(&c);
            let events = eng.ingest(c).unwrap();
            if i < 8 {
                assert!(matches!(events.last(), Some(ExecEvent::Applied { .. })));
            } else {
                assert!(matches!(
                    events.last(),
                    Some(ExecEvent::Rejected {
                        reason: RejectReason::BadCommit,
                        ..
                    })
                ));
            }
        }
        // Same hash a second time even below cap → rejected.
        let inner = mk_inner(1);
        let hash = operp_dag::reveal_commit_hash(&inner, &[0u8; 32]);
        let dup = commit_unit(
            vec![tip],
            &alice,
            hash,
            eng.state.height + operp_types::COMMIT_TTL_HEIGHTS,
        );
        let events = eng.ingest(dup).unwrap();
        assert!(matches!(
            events.last(),
            Some(ExecEvent::Rejected {
                reason: RejectReason::BadCommit,
                ..
            })
        ));
    }

    #[test]
    fn genesis_commit_is_accepted() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let alice = sk(1);
        let c = commit_unit(
            vec![genesis_id()],
            &alice,
            [9u8; 32],
            operp_types::COMMIT_TTL_HEIGHTS,
        );
        let events = eng.ingest(c).unwrap();
        assert!(matches!(events.last(), Some(ExecEvent::Applied { .. })));
    }

    #[test]
    fn commit_reveal_deterministic_across_replicas() {
        let build = |arrival_swap: bool| {
            let mut eng = activated_engine();
            let alice = sk(1);
            let acct = acct_of(&alice);
            let d = deposit(vec![genesis_id()], &alice, 10_000 * USD_SCALE as i128, 1);
            let tip = unit_id(&d);
            eng.ingest(d).unwrap();
            let inner = Op::Place {
                account: acct,
                market: BTC_USD,
                side: Side::Bid,
                typ: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: 100 * PRICE_SCALE as i64,
                qty: QTY_SCALE / 1000,
                client_seq: 1,
                isolated: false,
                margin: 0,
            };
            let salt = [3u8; 32];
            let hash = operp_dag::reveal_commit_hash(&inner, &salt);
            let c = commit_unit(
                vec![tip],
                &alice,
                hash,
                eng.state.height + operp_types::COMMIT_TTL_HEIGHTS,
            );
            let cid = unit_id(&c);
            let r = sign_unit(
                vec![cid],
                Op::Reveal {
                    account: acct,
                    commit_ref: hash,
                    op: Box::new(inner),
                    salt,
                },
                &alice,
            );
            if arrival_swap {
                eng.ingest(r).unwrap_err(); // buffered as orphan (parent unknown)
                eng.ingest(c).unwrap();
                // Orphans unblocked by execution become ready on the next
                // drain (engine contract): run it so the reveal executes.
                eng.apply_ready();
            } else {
                eng.ingest(c).unwrap();
                eng.ingest(r).unwrap();
            }
            eng.state.state_root()
        };
        assert_eq!(build(false), build(false), "replicas must agree");
        assert_eq!(
            build(true),
            build(false),
            "orphan-buffered arrival must converge to the same state"
        );
    }

    // -------------------------------------------------------------------
    // Funding external-anchor wiring (doc 06 §2.6/§2.7)

    fn report_unit(parents: Vec<UnitId>, secret: &[u8; 32], px: Price) -> Unit {
        sign_unit(
            parents,
            Op::ReportPrice {
                oracle: acct_of(secret),
                market: BTC_USD,
                price: px,
            },
            secret,
        )
    }

    fn report_on_market(
        parents: Vec<UnitId>,
        secret: &[u8; 32],
        market: MarketId,
        px: Price,
    ) -> Unit {
        sign_unit(
            parents,
            Op::ReportPrice {
                oracle: acct_of(secret),
                market,
                price: px,
            },
            secret,
        )
    }

    fn external_price_unit(
        parents: Vec<UnitId>,
        secret: &[u8; 32],
        px: Price,
        source_id: u8,
    ) -> Unit {
        external_price_on(parents, secret, BTC_USD, px, source_id)
    }

    fn external_price_on(
        parents: Vec<UnitId>,
        secret: &[u8; 32],
        market: MarketId,
        px: Price,
        source_id: u8,
    ) -> Unit {
        sign_unit(
            parents,
            Op::UpdateExternalPrice {
                source: acct_of(secret),
                market,
                price: px,
                source_id,
            },
            secret,
        )
    }

    /// Two bonded reporters primed at `px` across distinct heights so the
    /// bonded-median funding TWAP converges to `px`.
    fn prime_bonded_twap(
        eng: &mut Engine,
        tip: &mut UnitId,
        oa: &[u8; 32],
        ob: &[u8; 32],
        px: Price,
        heights: u64,
    ) {
        for _ in 0..heights {
            eng.state.height += 1;
            let r1 = report_unit(vec![*tip], oa, px);
            *tip = unit_id(&r1);
            eng.ingest(r1).unwrap();
            let r2 = report_unit(vec![*tip], ob, px);
            *tip = unit_id(&r2);
            eng.ingest(r2).unwrap();
        }
    }

    #[test]
    fn external_anchor_wiring_overrides_funding_index_when_active() {
        let mut eng = activated_engine();
        eng.state.height = operp_types::FUNDING_TWAP_ACTIVATION_HEIGHT;
        eng.state.funding_source = operp_types::FundingSourceKind::AggregatedExternal;
        let oa = sk(5);
        let ob = sk(6);
        let keeper = sk(9);
        // Bond reporters so funding ticks fire; allowlist the keeper.
        eng.state
            .oracle_bonds
            .insert(acct_of(&oa), ORACLE_BOND_PERP);
        eng.state
            .oracle_bonds
            .insert(acct_of(&ob), ORACLE_BOND_PERP);
        eng.state.external_sources.insert(acct_of(&keeper));

        let mut tip = genesis_id();
        prime_bonded_twap(&mut eng, &mut tip, &oa, &ob, 90_000 * PRICE_SCALE as i64, 4);
        assert_eq!(
            eng.state.funding_index_twap[&BTC_USD],
            90_000 * PRICE_SCALE as i64
        );

        // Keeper posts an external anchor at 95k through the real dispatch
        // path; it lands in the ring but needs >= MIN_SAMPLES to drive index.
        let e1 = external_price_unit(vec![tip], &keeper, 95_000 * PRICE_SCALE as i64, 0);
        tip = unit_id(&e1);
        let events = eng.ingest(e1).unwrap();
        assert!(matches!(events.last(), Some(ExecEvent::Applied { .. })));
        let e2 = external_price_unit(vec![tip], &keeper, 95_000 * PRICE_SCALE as i64, 0);
        let _ = unit_id(&e2);
        eng.ingest(e2).unwrap();
        assert_eq!(
            eng.state.external_twap(BTC_USD),
            Some(95_000 * PRICE_SCALE as i64)
        );
        assert_eq!(
            eng.state
                .effective_funding_index(BTC_USD, 90_000 * PRICE_SCALE as i64),
            95_000 * PRICE_SCALE as i64,
            "fresh external ring must override the bonded-median TWAP"
        );

        // Feed dies: after MAX_STALENESS heights the index falls back to the
        // bonded TWAP so funding never freezes (doc §2.6 rule 2).
        eng.state.height += operp_types::FUNDING_EXTERNAL_MAX_STALENESS + 1;
        assert_eq!(
            eng.state
                .effective_funding_index(BTC_USD, 90_000 * PRICE_SCALE as i64),
            90_000 * PRICE_SCALE as i64
        );
    }

    #[test]
    fn unallowlisted_or_gate_blocked_external_prices_rejected() {
        let mut eng = activated_engine();
        eng.state.height = operp_types::FUNDING_TWAP_ACTIVATION_HEIGHT;
        eng.state.funding_source = operp_types::FundingSourceKind::AggregatedExternal;
        let keeper = sk(9);
        let stranger = sk(11);
        eng.state.external_sources.insert(acct_of(&keeper));
        // Not on the allowlist.
        let u = external_price_unit(
            vec![genesis_id()],
            &stranger,
            95_000 * PRICE_SCALE as i64,
            0,
        );
        let events = eng.ingest(u).unwrap();
        assert!(matches!(
            events.last(),
            Some(ExecEvent::Rejected {
                reason: RejectReason::BadAccount,
                ..
            })
        ));
        // BondedMedianTwap (default source): UpdateExternalPrice rejected so
        // v1 replay stays byte-identical.
        let mut eng2 = activated_engine();
        eng2.state.height = operp_types::FUNDING_TWAP_ACTIVATION_HEIGHT;
        eng2.state.external_sources.insert(acct_of(&keeper));
        let u2 = external_price_unit(vec![genesis_id()], &keeper, 95_000 * PRICE_SCALE as i64, 0);
        let events2 = eng2.ingest(u2).unwrap();
        assert!(matches!(
            events2.last(),
            Some(ExecEvent::Rejected {
                reason: RejectReason::NotFound,
                ..
            })
        ));
        assert!(eng2.state.external_price_ring.is_empty());
    }

    #[test]
    fn e2e_funding_pays_via_external_anchored_index_through_units() {
        let mut eng = activated_engine();
        eng.state.height = operp_types::FUNDING_TWAP_ACTIVATION_HEIGHT;
        eng.state.funding_source = operp_types::FundingSourceKind::AggregatedExternal;
        let alice = sk(1);
        let bob = sk(2);
        let oa = sk(5);
        let ob = sk(6);
        let keeper = sk(9);
        eng.state
            .oracle_bonds
            .insert(acct_of(&oa), ORACLE_BOND_PERP);
        eng.state
            .oracle_bonds
            .insert(acct_of(&ob), ORACLE_BOND_PERP);
        eng.state.external_sources.insert(acct_of(&keeper));
        // Collateral + opposite positions via deposits/places.
        let d1 = deposit(vec![genesis_id()], &alice, 1_000_000 * USD_SCALE as i128, 1);
        let mut tip = unit_id(&d1);
        eng.ingest(d1).unwrap();
        let d2 = deposit(vec![tip], &bob, 1_000_000 * USD_SCALE as i128, 2);
        tip = unit_id(&d2);
        eng.ingest(d2).unwrap();
        let px = 100_000 * PRICE_SCALE as i64;
        let ask = place(
            vec![tip],
            &bob,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE / 1000,
            1,
        );
        tip = unit_id(&ask);
        eng.ingest(ask).unwrap();
        let bid = place(
            vec![tip],
            &alice,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE / 1000,
            1,
        );
        tip = unit_id(&bid);
        eng.ingest(bid).unwrap();

        // External keepers anchor the index at 50k while bonded reports push
        // medians (and thus the capped mark) to 100k: longs must pay shorts.
        let e1 = external_price_unit(vec![tip], &keeper, 50_000 * PRICE_SCALE as i64, 0);
        tip = unit_id(&e1);
        eng.ingest(e1).unwrap();
        let e2 = external_price_unit(vec![tip], &keeper, 50_000 * PRICE_SCALE as i64, 0);
        tip = unit_id(&e2);
        eng.ingest(e2).unwrap();
        prime_bonded_twap(
            &mut eng,
            &mut tip,
            &oa,
            &ob,
            100_000 * PRICE_SCALE as i64,
            3,
        );

        let pre_long = eng.state.accounts[&acct_of(&alice)].collateral;
        let pre_short = eng.state.accounts[&acct_of(&bob)].collateral;
        // One more report tick fires funding against the external index.
        eng.state.height += 1;
        let r = report_unit(vec![tip], &oa, 100_000 * PRICE_SCALE as i64);
        let _ = unit_id(&r);
        let events = eng.ingest(r).unwrap();
        assert!(matches!(events.last(), Some(ExecEvent::Applied { .. })));
        assert!(
            eng.state.accounts[&acct_of(&alice)].collateral < pre_long,
            "long pays when capped mark > external-anchored index"
        );
        assert!(
            eng.state.accounts[&acct_of(&bob)].collateral > pre_short,
            "short receives when capped mark > external-anchored index"
        );
        let moved = pre_long - eng.state.accounts[&acct_of(&alice)].collateral;
        // Per-tick cap: 50 bps of notional(qty, 50k).
        let cap = operp_types::bps(
            i128::from(QTY_SCALE / 1000) * (50_000 * PRICE_SCALE as i64 as i128),
            operp_types::FUNDING_CAP_BPS as u64,
        );
        assert!(moved <= cap as i128 + USD_SCALE as i128, "cap holds");
    }

    #[test]
    fn funding_pays_once_per_height() {
        let mut eng = activated_engine();
        eng.state.height = operp_types::FUNDING_TWAP_ACTIVATION_HEIGHT;
        eng.state.funding_source = operp_types::FundingSourceKind::AggregatedExternal;
        let alice = sk(1);
        let bob = sk(2);
        let oa = sk(5);
        let ob = sk(6);
        let keeper = sk(9);
        eng.state
            .oracle_bonds
            .insert(acct_of(&oa), ORACLE_BOND_PERP);
        eng.state
            .oracle_bonds
            .insert(acct_of(&ob), ORACLE_BOND_PERP);
        eng.state.external_sources.insert(acct_of(&keeper));
        let d1 = deposit(vec![genesis_id()], &alice, 1_000_000 * USD_SCALE as i128, 1);
        let mut tip = unit_id(&d1);
        eng.ingest(d1).unwrap();
        let d2 = deposit(vec![tip], &bob, 1_000_000 * USD_SCALE as i128, 2);
        tip = unit_id(&d2);
        eng.ingest(d2).unwrap();
        // Open a long/short pair at 100k.
        let px = 100_000 * PRICE_SCALE as i64;
        let ask = place(
            vec![tip],
            &bob,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE / 1000,
            1,
        );
        tip = unit_id(&ask);
        eng.ingest(ask).unwrap();
        let bid = place(
            vec![tip],
            &alice,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE / 1000,
            1,
        );
        tip = unit_id(&bid);
        eng.ingest(bid).unwrap();
        // External index 50k vs bonded reports 100k: non-zero premium.
        let e1 = external_price_unit(vec![tip], &keeper, 50_000 * PRICE_SCALE as i64, 0);
        tip = unit_id(&e1);
        eng.ingest(e1).unwrap();
        let e2 = external_price_unit(vec![tip], &keeper, 50_000 * PRICE_SCALE as i64, 0);
        tip = unit_id(&e2);
        eng.ingest(e2).unwrap();
        prime_bonded_twap(&mut eng, &mut tip, &oa, &ob, px, 3);

        // Fresh height: the first report with prices.len() >= 2 pays…
        eng.state.height += 1;
        let h = eng.state.height;
        let pre_long = eng.state.accounts[&acct_of(&alice)].collateral;
        let r1 = report_unit(vec![tip], &oa, px);
        tip = unit_id(&r1);
        eng.ingest(r1).unwrap();
        let after_first = eng.state.accounts[&acct_of(&alice)].collateral;
        assert!(
            after_first < pre_long,
            "first same-height report with prices.len() >= 2 pays"
        );
        assert_eq!(
            eng.state.last_funding_height.get(&BTC_USD).copied(),
            Some(h)
        );
        // …the second report at the same height must not pay again.
        let r2 = report_unit(vec![tip], &ob, px);
        eng.ingest(r2).unwrap();
        assert_eq!(
            eng.state.accounts[&acct_of(&alice)].collateral,
            after_first,
            "second report at the same height does not move collateral"
        );
        assert_eq!(
            eng.state.last_funding_height.get(&BTC_USD).copied(),
            Some(h)
        );
    }

    #[test]
    fn funding_rate_market_peg_settles_on_interval() {
        let mut eng = activated_engine();
        let g = genesis_id();
        // Fresh creator (sk(1)) pays the listing fee; alice/bob deposit
        // collateral separately below.
        let d = gov_dep(vec![g], &sk(1), CREATE_MARKET_FEE_PERP, 7);
        let mut tip = unit_id(&d);
        eng.ingest(d).unwrap();
        let mut symbol = [0u8; 16];
        symbol[..6].copy_from_slice(b"FUNDUS");
        let cm = sign_unit(
            vec![tip],
            Op::CreateMarket {
                creator: acct_of(&sk(1)),
                symbol,
                tick_size: 1,
                im_bps: 1000,
                mm_bps: 500,
                taker_fee_bps: 5,
                keeper_reward_bps: 100,
                spot_only: false,
                funding_rate: true,
                usd_per_unit: 10_000,
                funding_cap_bps: 50,
            },
            &sk(1),
        );
        tip = unit_id(&cm);
        eng.ingest(cm).unwrap();
        let mkt = MarketId(2);
        assert!(eng.state.markets[&mkt].funding_rate);
        let alice = sk(2);
        let bob = sk(3);
        let oa = sk(5);
        let ob = sk(6);
        eng.state
            .oracle_bonds
            .insert(acct_of(&oa), ORACLE_BOND_PERP);
        eng.state
            .oracle_bonds
            .insert(acct_of(&ob), ORACLE_BOND_PERP);
        let d1 = deposit(vec![tip], &alice, 1_000_000 * USD_SCALE as i128, 1);
        tip = unit_id(&d1);
        eng.ingest(d1).unwrap();
        let d2 = deposit(vec![tip], &bob, 1_000_000 * USD_SCALE as i128, 2);
        tip = unit_id(&d2);
        eng.ingest(d2).unwrap();

        // Pair 1: reporters set the index at encode(12). No fill has set a
        // mark yet: no payment, no collateral move, clock not armed.
        let idx = operp_types::encode_funding_price(12);
        let mark_px = operp_types::encode_funding_price(20);
        // `report_unit` hardcodes BTC_USD; the peg market needs its reports
        // to land on mkt.
        let report_mkt = |parents: Vec<UnitId>, secret: &[u8; 32]| {
            sign_unit(
                parents,
                Op::ReportPrice {
                    oracle: acct_of(secret),
                    market: mkt,
                    price: idx,
                },
                secret,
            )
        };
        let pre_long = eng.state.accounts[&acct_of(&alice)].collateral;
        let pre_short = eng.state.accounts[&acct_of(&bob)].collateral;
        for secret in [&oa, &ob] {
            let r = report_mkt(vec![tip], secret);
            tip = unit_id(&r);
            eng.ingest(r).unwrap();
        }
        assert_eq!(eng.state.last_index.get(&mkt).copied(), Some(idx));
        assert!(
            !eng.state.marks.contains_key(&mkt),
            "reports must not write the mark"
        );
        // Bootstrap print: the first fill anchors its mark against a fresh
        // external index, so the feed must speak before it.
        let ep0 = external_price_on(vec![tip], &sk(1), mkt, idx, 0);
        tip = unit_id(&ep0);
        eng.ingest(ep0).unwrap();
        assert!(
            !eng.state.last_funding_height.contains_key(&mkt),
            "missing mark must not arm the peg clock"
        );
        assert_eq!(eng.state.accounts[&acct_of(&alice)].collateral, pre_long);
        assert_eq!(eng.state.accounts[&acct_of(&bob)].collateral, pre_short);

        // Fill at encode(20), qty exactly QTY_SCALE/100: sets the mark
        // despite bonded reporters (the ±10% band and oracle lock are
        // skipped) and arms the peg clock.
        let ask = place_on(
            vec![tip],
            &bob,
            mkt,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            mark_px,
            QTY_SCALE / 100,
            1,
        );
        tip = unit_id(&ask);
        let evs = eng.ingest(ask).unwrap();
        assert!(
            evs.iter().all(|e| !matches!(e, ExecEvent::Rejected { .. })),
            "ask rejected: {evs:?}"
        );
        let bid = place_on(
            vec![tip],
            &alice,
            mkt,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            mark_px,
            QTY_SCALE / 100,
            1,
        );
        tip = unit_id(&bid);
        let evs = eng.ingest(bid).unwrap();
        assert!(
            evs.iter().any(|e| matches!(
                e,
                ExecEvent::Applied { fills, .. } if !fills.is_empty()
            )),
            "no fill; events={evs:?}"
        );
        assert_eq!(eng.state.marks.get(&mkt).copied(), Some(mark_px));
        assert_eq!(
            eng.state.last_funding_height.get(&mkt).copied(),
            Some(eng.state.height),
            "the fill must arm the peg clock at its own height"
        );

        // After a full peg interval, a fresh external print of the index
        // (the creator is this market's allowlisted feed — no
        // AggregatedExternal needed) plus the report pair settles.
        eng.state.height += operp_types::FUNDING_PEG_INTERVAL_HEIGHTS;
        let pay_height = eng.state.height;
        let pre_long = eng.state.accounts[&acct_of(&alice)].collateral;
        let pre_short = eng.state.accounts[&acct_of(&bob)].collateral;
        let ep = external_price_on(vec![tip], &sk(1), mkt, idx, 0);
        tip = unit_id(&ep);
        eng.ingest(ep).unwrap();
        for secret in [&oa, &ob] {
            let r = report_mkt(vec![tip], secret);
            tip = unit_id(&r);
            eng.ingest(r).unwrap();
        }
        let cap = eng.state.markets[&mkt].funding_cap_bps as i64;
        let diff_bps = (operp_types::funding_rate_bps(mark_px)
            - operp_types::funding_rate_bps(idx))
        .clamp(-cap, cap);
        assert_eq!(diff_bps, 8, "rate-domain diff: (20-12) bps");
        let expected = operp_types::funding_rate_cash((QTY_SCALE / 100) as i64, diff_bps, 10_000);
        // Delta = change in collateral (post − pre): mark > index → long pays.
        let long_delta = eng.state.accounts[&acct_of(&alice)].collateral - pre_long;
        let short_delta = eng.state.accounts[&acct_of(&bob)].collateral - pre_short;
        assert_eq!(long_delta, -expected, "long pays when mark > index");
        assert_eq!(short_delta, expected, "short receives the negation");
        assert_eq!(
            eng.state.last_funding_height.get(&mkt).copied(),
            Some(pay_height),
            "the interval window advances the clock"
        );

        // One height later: no payment, no clock movement.
        eng.state.height += 1;
        let pre_long = eng.state.accounts[&acct_of(&alice)].collateral;
        let pre_short = eng.state.accounts[&acct_of(&bob)].collateral;
        for secret in [&oa, &ob] {
            let r = report_mkt(vec![tip], secret);
            tip = unit_id(&r);
            eng.ingest(r).unwrap();
        }
        assert_eq!(eng.state.accounts[&acct_of(&alice)].collateral, pre_long);
        assert_eq!(eng.state.accounts[&acct_of(&bob)].collateral, pre_short);
        assert_eq!(
            eng.state.last_funding_height.get(&mkt).copied(),
            Some(pay_height),
            "clock must not advance before the next interval"
        );
    }

    #[test]
    fn create_market_both_flags_risk_without_burn() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let g = genesis_id();
        let d = gov_dep(vec![g], &sk(1), CREATE_MARKET_FEE_PERP, 7);
        let tip = unit_id(&d);
        eng.ingest(d).unwrap();
        let mut symbol = [0u8; 16];
        symbol[..6].copy_from_slice(b"BOTHFL");
        let cm = sign_unit(
            vec![tip],
            Op::CreateMarket {
                creator: acct_of(&sk(1)),
                symbol,
                tick_size: 1,
                im_bps: 1000,
                mm_bps: 500,
                taker_fee_bps: 5,
                keeper_reward_bps: 100,
                spot_only: true,
                funding_rate: true,
                usd_per_unit: 10_000,
                funding_cap_bps: 50,
            },
            &sk(1),
        );
        let evs = eng.ingest(cm).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected {
                reason: RejectReason::Risk,
                ..
            }
        )));
        assert_eq!(eng.state.next_market_id, 2, "no market id allocated");
        assert_eq!(
            eng.state.perp_balances[&acct_of(&sk(1))],
            CREATE_MARKET_FEE_PERP,
            "listing fee must not burn"
        );
        assert_eq!(eng.state.perp_burned, 0);
    }

    #[test]
    fn funding_peg_rate_series_pays_caps_and_keeps_clock() {
        // Realistic funding-rate series through the peg: normal gap (long
        // pays), zero gap (money frozen, clock still advances), peg break
        // (diff clamped to ±FUNDING_CAP_BPS), and negative index rates.
        let mut eng = activated_engine();
        let g = genesis_id();
        let d = gov_dep(vec![g], &sk(1), CREATE_MARKET_FEE_PERP, 7);
        let mut tip = unit_id(&d);
        eng.ingest(d).unwrap();
        let mut symbol = [0u8; 16];
        symbol[..6].copy_from_slice(b"DEMOFR");
        let cm = sign_unit(
            vec![tip],
            Op::CreateMarket {
                creator: acct_of(&sk(1)),
                symbol,
                tick_size: 1,
                im_bps: 1000,
                mm_bps: 500,
                taker_fee_bps: 5,
                keeper_reward_bps: 100,
                spot_only: false,
                funding_rate: true,
                usd_per_unit: 10_000,
                funding_cap_bps: 50,
            },
            &sk(1),
        );
        tip = unit_id(&cm);
        eng.ingest(cm).unwrap();
        let mkt = MarketId(2);
        let alice = sk(2);
        let bob = sk(3);
        let oa = sk(5);
        let ob = sk(6);
        eng.state
            .oracle_bonds
            .insert(acct_of(&oa), ORACLE_BOND_PERP);
        eng.state
            .oracle_bonds
            .insert(acct_of(&ob), ORACLE_BOND_PERP);
        let d1 = deposit(vec![tip], &alice, 1_000_000 * USD_SCALE as i128, 1);
        tip = unit_id(&d1);
        eng.ingest(d1).unwrap();
        let d2 = deposit(vec![tip], &bob, 1_000_000 * USD_SCALE as i128, 2);
        tip = unit_id(&d2);
        eng.ingest(d2).unwrap();
        let mark_px = operp_types::encode_funding_price(20);
        let qty = (QTY_SCALE / 100) as i64;
        let report_on = |tip: UnitId, secret: &[u8; 32], px: Price| {
            sign_unit(
                vec![tip],
                Op::ReportPrice {
                    oracle: acct_of(secret),
                    market: mkt,
                    price: px,
                },
                secret,
            )
        };
        // Seed index at 12 bps (no mark yet), then fill at 20 bps → arm.
        for s in [&oa, &ob] {
            let r = report_on(tip, s, operp_types::encode_funding_price(12));
            tip = unit_id(&r);
            eng.ingest(r).unwrap();
        }
        // Bootstrap print: the first fill anchors its mark against a fresh
        // external index (creator sk(1) is the allowlisted feed).
        let ep0 = external_price_on(
            vec![tip],
            &sk(1),
            mkt,
            operp_types::encode_funding_price(12),
            0,
        );
        tip = unit_id(&ep0);
        eng.ingest(ep0).unwrap();
        let ask = place_on(
            vec![tip],
            &bob,
            mkt,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            mark_px,
            QTY_SCALE / 100,
            1,
        );
        tip = unit_id(&ask);
        eng.ingest(ask).unwrap();
        let bid = place_on(
            vec![tip],
            &alice,
            mkt,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            mark_px,
            QTY_SCALE / 100,
            1,
        );
        tip = unit_id(&bid);
        eng.ingest(bid).unwrap();
        assert_eq!(eng.state.marks.get(&mkt).copied(), Some(mark_px));
        println!(
            "armed: mark=20bps, index=12bps, height={}",
            eng.state.height
        );
        for (i, idx_bps) in [12i64, 20, 520, -3].into_iter().enumerate() {
            eng.state.height += operp_types::FUNDING_PEG_INTERVAL_HEIGHTS;
            let h = eng.state.height;
            let idx = operp_types::encode_funding_price(idx_bps);
            let pre_long = eng.state.accounts[&acct_of(&alice)].collateral;
            let pre_short = eng.state.accounts[&acct_of(&bob)].collateral;
            // Fresh external print of the index first (creator sk(1) is the
            // allowlisted feed): the peg pays only off a fresh external
            // sample, never off the reporter median.
            let ep = external_price_on(vec![tip], &sk(1), mkt, idx, 0);
            tip = unit_id(&ep);
            eng.ingest(ep).unwrap();
            for s in [&oa, &ob] {
                let r = report_on(tip, s, idx);
                tip = unit_id(&r);
                eng.ingest(r).unwrap();
            }
            let cap = eng.state.markets[&mkt].funding_cap_bps as i64;
            let diff = (operp_types::funding_rate_bps(mark_px)
                - operp_types::funding_rate_bps(idx))
            .clamp(-cap, cap);
            let expected = operp_types::funding_rate_cash(qty, diff, 10_000);
            let long_delta = eng.state.accounts[&acct_of(&alice)].collateral - pre_long;
            let short_delta = eng.state.accounts[&acct_of(&bob)].collateral - pre_short;
            println!(
                "round {i}: index={idx_bps:>4}bps  diff={diff:>3}bps  expected={expected:>8}  long_delta={long_delta:>8}  short_delta={short_delta:>8}  clock={:?}",
                eng.state.last_funding_height.get(&mkt)
            );
            assert_eq!(long_delta, -expected, "round {i}: long delta vs formula");
            assert_eq!(short_delta, expected, "round {i}: short delta vs formula");
            assert_eq!(
                eng.state.last_funding_height.get(&mkt).copied(),
                Some(h),
                "round {i}: clock must land on this height"
            );
        }
    }

    #[test]
    fn funding_place_rejects_out_of_band_rate() {
        // #7: an encoded rate beyond ±100% (funding_rate_bps.abs() >
        // 10_000) is a broken feed — Risk before any match, on opens AND
        // closes. Funded account so the only Risk source is the band.
        let mut eng = activated_engine();
        let creator = acct_of(&sk(1));
        eng.state
            .perp_balances
            .insert(creator, CREATE_MARKET_FEE_PERP);
        eng.state.perp_supply += CREATE_MARKET_FEE_PERP;
        let mut symbol = [0u8; 16];
        symbol[..4].copy_from_slice(b"BAND");
        eng.create_market(creator, symbol, 1, 100, 50, 5, 10, false, true, 10_000, 10)
            .unwrap();
        let m = MarketId(2);
        let alice = sk(2);
        let d = deposit(vec![genesis_id()], &alice, 1_000_000 * USD_SCALE as i128, 2);
        let mut tip = unit_id(&d);
        eng.ingest(d).unwrap();
        let over = operp_types::encode_funding_price(10_001); // +10001 bps
        assert!(funding_rate_bps(over).abs() > 10_000);
        // Open at the out-of-band limit → Risk.
        let open = place_on(
            vec![tip],
            &alice,
            m,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            over,
            QTY_SCALE,
            1,
        );
        tip = unit_id(&open);
        let evs = eng.ingest(open).unwrap();
        assert!(
            evs.iter().any(|e| matches!(
                e,
                ExecEvent::Rejected {
                    reason: RejectReason::Risk,
                    ..
                }
            )),
            "out-of-band funding open must be Risk: {evs:?}"
        );
        // Close at an out-of-band limit → Risk too (band runs before the
        // open/reduce split).
        {
            use operp_account::Position;
            eng.state.account_mut(acct_of(&alice)).positions.insert(
                m,
                Position {
                    market: m,
                    qty: -(QTY_SCALE as i64),
                    entry_price: operp_types::encode_funding_price(12),
                    isolated: false,
                },
            );
        }
        let close = place_on(
            vec![tip],
            &alice,
            m,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            over,
            QTY_SCALE,
            1, // rejected places never advance the watermark
        );
        let evs = eng.ingest(close).unwrap();
        assert!(
            evs.iter().any(|e| matches!(
                e,
                ExecEvent::Rejected {
                    reason: RejectReason::Risk,
                    ..
                }
            )),
            "out-of-band funding close must be Risk: {evs:?}"
        );
    }

    #[test]
    fn funding_rate_lists_at_100x() {
        let mut eng = activated_engine();
        let creator = acct_of(&sk(1));
        eng.state
            .perp_balances
            .insert(creator, CREATE_MARKET_FEE_PERP);
        let mut symbol = [0u8; 16];
        symbol[..6].copy_from_slice(b"HUNDRD");
        eng.state.perp_supply += CREATE_MARKET_FEE_PERP;
        // 100x gate: im 100 / mm 50 / cap 10 / usd 10_000 / keeper 10 applies.
        let applied =
            eng.create_market(creator, symbol, 1, 100, 50, 5, 10, false, true, 10_000, 10);
        assert!(
            applied.is_ok(),
            "100x funding listing must apply: {applied:?}"
        );
        let m = MarketId(2);
        let p = eng.state.markets[&m];
        assert!(p.funding_rate);
        assert_eq!(p.im_bps, 100);
        assert_eq!(p.mm_bps, 50);
        assert_eq!(p.funding_cap_bps, 10);
        assert_eq!(p.usd_per_unit, 10_000);
        // The creator is the market's external feed from listing onward.
        assert!(eng.state.external_sources.contains(&creator));
        // 200x (im 50) is Risk — every other conjunct passes.
        assert!(matches!(
            eng.create_market(creator, symbol, 1, 50, 40, 5, 5, false, true, 10_000, 5),
            Err(RejectReason::Risk)
        ));
        // A regular market keeps the mm 500 floor: mm 50 is Risk.
        assert!(matches!(
            eng.create_market(creator, symbol, 1, 1000, 50, 5, 100, false, false, 0, 0),
            Err(RejectReason::Risk)
        ));
        // A regular market may not carry a money multiplier: usd 1 is Risk.
        assert!(matches!(
            eng.create_market(creator, symbol, 1, 1000, 500, 5, 100, false, false, 1, 0),
            Err(RejectReason::Risk)
        ));
        // Rejected listings burned no fee and allocated no id.
        assert_eq!(eng.state.perp_balances[&creator], 0);
        assert_eq!(eng.state.next_market_id, 3);
    }
    #[test]
    fn peg_skips_pay_without_external() {
        let mut eng = activated_engine();
        // Funding source stays BondedMedianTwap on purpose: posting an
        // external print must not require AggregatedExternal.
        assert_eq!(
            eng.state.funding_source,
            operp_types::FundingSourceKind::BondedMedianTwap
        );
        let g = genesis_id();
        let d = gov_dep(vec![g], &sk(1), CREATE_MARKET_FEE_PERP, 7);
        let mut tip = unit_id(&d);
        eng.ingest(d).unwrap();
        let mut symbol = [0u8; 16];
        symbol[..5].copy_from_slice(b"PEGSK");
        let cm = sign_unit(
            vec![tip],
            Op::CreateMarket {
                creator: acct_of(&sk(1)),
                symbol,
                tick_size: 1,
                im_bps: 1000,
                mm_bps: 500,
                taker_fee_bps: 5,
                keeper_reward_bps: 100,
                spot_only: false,
                funding_rate: true,
                usd_per_unit: 10_000,
                funding_cap_bps: 50,
            },
            &sk(1),
        );
        tip = unit_id(&cm);
        eng.ingest(cm).unwrap();
        let mkt = MarketId(2);
        let alice = sk(2);
        let bob = sk(3);
        let oa = sk(5);
        // Bonded reporter: its report is the settle trigger that must not
        // pay without an external print.
        eng.state
            .oracle_bonds
            .insert(acct_of(&oa), ORACLE_BOND_PERP);
        let d1 = deposit(vec![tip], &alice, 1_000_000 * USD_SCALE as i128, 1);
        tip = unit_id(&d1);
        eng.ingest(d1).unwrap();
        let d2 = deposit(vec![tip], &bob, 1_000_000 * USD_SCALE as i128, 2);
        tip = unit_id(&d2);
        eng.ingest(d2).unwrap();
        // Bootstrap the mark: external index 12, fill at mark 20.
        let idx = operp_types::encode_funding_price(12);
        let mark_px = operp_types::encode_funding_price(20);
        let ep = external_price_on(vec![tip], &sk(1), mkt, idx, 0);
        tip = unit_id(&ep);
        eng.ingest(ep).unwrap();
        let qty = QTY_SCALE / 100;
        for (secret, side) in [(&bob, Side::Ask), (&alice, Side::Bid)] {
            let o = place_on(
                vec![tip],
                secret,
                mkt,
                side,
                OrderType::Limit,
                TimeInForce::Gtc,
                mark_px,
                qty,
                1,
            );
            tip = unit_id(&o);
            let evs = eng.ingest(o).unwrap();
            assert!(
                evs.iter().all(|e| !matches!(e, ExecEvent::Rejected { .. })),
                "{evs:?}"
            );
        }
        assert_eq!(eng.state.marks.get(&mkt).copied(), Some(mark_px));
        let armed = eng.state.last_funding_height[&mkt];

        // Window elapses with no external print: no payment at all, but the
        // clock still advances so the feed cannot stall the schedule.
        eng.state.height = armed + operp_types::FUNDING_PEG_INTERVAL_HEIGHTS;
        let pre_long = eng.state.accounts[&acct_of(&alice)].collateral;
        let pre_short = eng.state.accounts[&acct_of(&bob)].collateral;
        let r = report_on_market(vec![tip], &oa, mkt, idx);
        tip = unit_id(&r);
        eng.ingest(r).unwrap();
        assert_eq!(
            eng.state.accounts[&acct_of(&alice)].collateral,
            pre_long,
            "no print pays nothing"
        );
        assert_eq!(
            eng.state.accounts[&acct_of(&bob)].collateral,
            pre_short,
            "no print pays nothing"
        );
        assert_eq!(
            eng.state.last_funding_height[&mkt], eng.state.height,
            "clock advances anyway"
        );
        let paid_height = eng.state.last_funding_height[&mkt];

        // Same window shape after an allowlisted print of encode(12):
        // mark 20 vs index 12 → long pays funding_rate_cash(qty, 8, 10_000),
        // clamped at the market cap (50 bps; 8 is under it).
        eng.state.height = paid_height + operp_types::FUNDING_PEG_INTERVAL_HEIGHTS;
        let ep2 = external_price_on(vec![tip], &sk(1), mkt, idx, 0);
        eng.ingest(ep2).unwrap();
        let expected = operp_types::funding_rate_cash((QTY_SCALE / 100) as i64, 8, 10_000);
        let long_delta = eng.state.accounts[&acct_of(&alice)].collateral - pre_long;
        let short_delta = eng.state.accounts[&acct_of(&bob)].collateral - pre_short;
        assert_eq!(long_delta, -expected, "long pays the rate gap");
        assert_eq!(short_delta, expected, "short receives it");
        assert_eq!(eng.state.last_funding_height[&mkt], eng.state.height);
    }
    #[test]
    fn funding_oi_capped_by_insurance() {
        let mut eng = activated_engine();
        let creator = acct_of(&sk(1));
        eng.state
            .perp_balances
            .insert(creator, CREATE_MARKET_FEE_PERP);
        let mut symbol = [0u8; 16];
        symbol[..5].copy_from_slice(b"OICAP");
        eng.state.perp_supply += CREATE_MARKET_FEE_PERP;
        // notional(1.0) = $10_000, cap 10 bps → worst payout $10.
        eng.create_market(creator, symbol, 1, 100, 50, 5, 10, false, true, 10_000, 10)
            .unwrap();
        let mkt = MarketId(2);
        let alice = acct_of(&sk(2));
        eng.state
            .account_mut(alice)
            .credit(1_000_000 * USD_SCALE as i128)
            .unwrap();
        let mark = operp_types::encode_funding_price(20);
        // Insurance below the worst-case payout: opening order is Risk and
        // the rejection moves no collateral.
        eng.state.account_mut(INSURANCE_ACCOUNT).collateral = 9 * USD_SCALE as i128;
        let p1 = place_on(
            vec![genesis_id()],
            &sk(2),
            mkt,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            mark,
            QTY_SCALE,
            1,
        );
        let p1_id = unit_id(&p1);
        let evs = eng.ingest(p1).unwrap();
        assert!(
            evs.iter().any(|e| matches!(
                e,
                ExecEvent::Rejected {
                    reason: RejectReason::Risk,
                    ..
                }
            )),
            "opening past the insurance cap must be Risk: {evs:?}"
        );
        assert_eq!(
            eng.state.accounts[&INSURANCE_ACCOUNT].collateral,
            9 * USD_SCALE as i128,
            "a rejected opening moves no collateral"
        );
        // Fund exactly to the payout bound: the same order now passes.
        eng.state.account_mut(INSURANCE_ACCOUNT).collateral = 10 * USD_SCALE as i128;
        let p2 = place_on(
            vec![p1_id],
            &sk(2),
            mkt,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            mark,
            QTY_SCALE,
            1,
        );
        let evs = eng.ingest(p2).unwrap();
        assert!(
            evs.iter().any(|e| matches!(e, ExecEvent::Applied { .. }))
                && evs.iter().all(|e| !matches!(e, ExecEvent::Rejected { .. })),
            "opening within the insurance cap must apply: {evs:?}"
        );
        // No counterparty crossed (the bid rests); the only insurance move
        // is the taker-fee leg of any fill — there was none, so it is
        // untouched. Insurance funding itself is not a trade here.
        assert_eq!(
            eng.state.accounts[&INSURANCE_ACCOUNT].collateral,
            10 * USD_SCALE as i128
        );
    }
    #[test]
    fn adl_haircut_share_caps_and_conserves() {
        // #9: hole 150 over deltas [40, 60]. First share = 150*40/100 = 60
        // → capped to 40 (the old code debited 60 — 20 more than the
        // counterparty gained); the last takes min(110, 60) = 60. Every
        // debited unit is credited to the target by the same `share`
        // value, so debits and credits sum equal.
        let hole = 150i128;
        let deltas = [40i128, 60i128];
        let total: i128 = deltas.iter().sum();
        let mut left = hole;
        let mut debits = Vec::new();
        let mut credited = 0i128;
        for (i, d) in deltas.iter().enumerate() {
            let share = adl_haircut_share(left, *d, total, i == deltas.len() - 1);
            assert!(share <= *d, "share {share} exceeds delta {d}");
            debits.push(share);
            credited += share; // the loop credits exactly what it debits
            left -= share;
        }
        assert_eq!(debits, vec![40, 60]);
        let debited: i128 = debits.iter().sum();
        assert_eq!(debited, credited, "credits to target must equal debits");
        assert_eq!(left, hole - debited);
    }

    #[test]
    fn funding_liq_off_book_adl() {
        use operp_account::Position;
        let mut eng = activated_engine();
        let creator = acct_of(&sk(1));
        eng.state
            .perp_balances
            .insert(creator, CREATE_MARKET_FEE_PERP);
        let mut symbol = [0u8; 16];
        symbol[..6].copy_from_slice(b"FUNDLQ");
        eng.state.perp_supply += CREATE_MARKET_FEE_PERP;
        eng.create_market(creator, symbol, 1, 100, 50, 5, 10, false, true, 10_000, 10)
            .unwrap();
        let mkt = MarketId(2);
        let alice = acct_of(&sk(2));
        let bob = acct_of(&sk(3));
        let keeper = acct_of(&sk(4));
        let entry = operp_types::encode_funding_price(40);
        {
            let a = eng.state.account_mut(alice);
            a.positions.insert(
                mkt,
                Position {
                    market: mkt,
                    qty: QTY_SCALE as i64,
                    entry_price: entry,
                    isolated: false,
                },
            );
        }
        {
            let a = eng.state.account_mut(bob);
            a.positions.insert(
                mkt,
                Position {
                    market: mkt,
                    qty: -(QTY_SCALE as i64),
                    entry_price: entry,
                    isolated: false,
                },
            );
        }
        // Mark 30 vs entry 40: the long is $10 underwater on $0 collateral
        // → equity -10, mm $50 → liquidatable.
        let mark = operp_types::encode_funding_price(30);
        eng.state.marks.insert(mkt, mark);
        // Fresh external index 50: off-book close happens there, not at the
        // mark and not in the book.
        eng.state
            .external_price_ring
            .entry(mkt)
            .or_default()
            .push_back(operp_types::ExternalSample {
                seq: 0,
                height: eng.state.height,
                price: operp_types::encode_funding_price(50),
                source_id: 0,
            });
        eng.state.account_mut(INSURANCE_ACCOUNT).collateral = 10_000 * USD_SCALE as i128;

        let books_before: Vec<(MarketId, usize)> = eng
            .state
            .books
            .values()
            .map(|b| (b.market(), b.live_orders().count()))
            .collect();
        let alice_before =
            eng.state.accounts[&alice].snapshot(&eng.state.marks, &eng.state.markets);
        assert!(alice_before.liquidatable, "target must start liquidatable");
        let bob_abs_before = eng.state.accounts[&bob].positions[&mkt].qty.unsigned_abs();
        let ins_before = eng.state.accounts[&INSURANCE_ACCOUNT].collateral;

        let fills = eng
            .liquidate(UnitId([9u8; 32]), eng.state.seq, keeper, alice, mkt)
            .expect("off-book liquidation applies");
        assert!(!fills.is_empty(), "ADL produced at least one fill");

        // Off-book: no book order appeared, no mark moved.
        let books_after: Vec<(MarketId, usize)> = eng
            .state
            .books
            .values()
            .map(|b| (b.market(), b.live_orders().count()))
            .collect();
        assert_eq!(books_before, books_after, "books untouched");
        assert_eq!(
            eng.state.marks.get(&mkt).copied(),
            Some(mark),
            "marks untouched"
        );

        // Partial close: same-sign remainder on the target, opposite side
        // shrinks by exactly the closed amount.
        let alice_qty = eng.state.accounts[&alice]
            .positions
            .get(&mkt)
            .map(|p| p.qty)
            .unwrap_or(0);
        assert!(alice_qty > 0, "remainder stays long, got {alice_qty}");
        let bob_abs = eng.state.accounts[&bob].positions[&mkt].qty.unsigned_abs();
        assert_eq!(
            bob_abs_before - bob_abs,
            QTY_SCALE - alice_qty.unsigned_abs(),
            "the opposite side absorbed exactly the closed qty"
        );
        assert!(alice_qty < QTY_SCALE as i64, "close was partial");

        // Insurance never went negative.
        assert!(
            eng.state.accounts[&INSURANCE_ACCOUNT].collateral >= 0,
            "insurance stays non-negative"
        );
        assert!(
            eng.state.accounts[&INSURANCE_ACCOUNT].collateral <= ins_before,
            "insurance only pays, never gains, here"
        );
    }

    #[test]
    fn adl_haircut_credits_target_and_caps_debits() {
        // #9 end-to-end: insurance exhausted, target ends the off-book
        // close at -8; the residual hole haircuts bob's +10 delta by 8
        // (<= delta) and every debited unit lands on the target — money
        // moves, it never vanishes.
        use operp_account::Position;
        let mut eng = activated_engine();
        let creator = acct_of(&sk(1));
        eng.state
            .perp_balances
            .insert(creator, CREATE_MARKET_FEE_PERP);
        let mut symbol = [0u8; 16];
        symbol[..5].copy_from_slice(b"HAIRC");
        eng.state.perp_supply += CREATE_MARKET_FEE_PERP;
        eng.create_market(creator, symbol, 1, 100, 50, 5, 10, false, true, 10_000, 10)
            .unwrap();
        let mkt = MarketId(2);
        let alice = acct_of(&sk(2));
        let bob = acct_of(&sk(3));
        let keeper = acct_of(&sk(4));
        let entry = operp_types::encode_funding_price(40);
        {
            let a = eng.state.account_mut(alice);
            a.positions.insert(
                mkt,
                Position {
                    market: mkt,
                    qty: QTY_SCALE as i64,
                    entry_price: entry,
                    isolated: false,
                },
            );
            a.collateral = 2 * USD_SCALE as i128;
        }
        {
            let a = eng.state.account_mut(bob);
            a.positions.insert(
                mkt,
                Position {
                    market: mkt,
                    qty: -(QTY_SCALE as i64),
                    entry_price: entry,
                    isolated: false,
                },
            );
        }
        // Mark 20 vs entry 40: the long is $20 underwater on $2 → equity
        // -18 <= mm*0.5 → liquidatable.
        eng.state
            .marks
            .insert(mkt, operp_types::encode_funding_price(20));
        // Fresh external index 30: the off-book close realizes -10 for the
        // target (2 - 10 = -8) and +10 for bob.
        eng.state
            .external_price_ring
            .entry(mkt)
            .or_default()
            .push_back(operp_types::ExternalSample {
                seq: 0,
                height: eng.state.height,
                price: operp_types::encode_funding_price(30),
                source_id: 0,
            });
        // Insurance exhausted: the top-up cannot cover the -8 hole.
        eng.state.account_mut(INSURANCE_ACCOUNT).collateral = 0;

        eng.liquidate(UnitId([9u8; 32]), eng.state.seq, keeper, alice, mkt)
            .expect("off-book liquidation applies");

        let alice_col = eng.state.accounts[&alice].collateral;
        let bob_col = eng.state.accounts[&bob].collateral;
        // Bob gained 10 in the close; the haircut took exactly the target's
        // 8-unit hole — never more than the 10 he gained.
        assert_eq!(bob_col, 2 * USD_SCALE as i128, "10 gained - 8 haircut");
        // The target's -8 hole was transferred, not burned.
        assert_eq!(alice_col, 0, "-8 + 8 haircut credit == 0");
        let bob_debit = 10 * USD_SCALE as i128 - bob_col;
        let target_credit = alice_col - (-8 * USD_SCALE as i128);
        assert_eq!(bob_debit, target_credit, "debits equal target credits");
    }

    /// Escrow lifecycle: collateral + buckets + live order margin only move
    /// between the three pots, never out of them (no fills' PnL here).
    #[test]
    fn isolated_escrow_conserved() {
        let usd = |v: i128| v * USD_SCALE as i128;
        let mut eng = activated_engine();
        let g = genesis_id();
        let alice = sk(1);
        let bob = sk(2);
        let a = acct_of(&alice);
        let pots = |eng: &Engine, who: AccountId| -> i128 {
            let acct = &eng.state.accounts[&who];
            let bucket: i128 = acct.isolated_margin.values().sum();
            let live: i128 = eng
                .state
                .books
                .values()
                .flat_map(|b| b.live_orders())
                .filter(|o| o.account == who)
                .map(|o| i128::from(o.margin_left))
                .sum();
            acct.collateral + bucket + live
        };

        let d1 = deposit(vec![g], &alice, usd(10_000), 1);
        let mut tip = unit_id(&d1);
        eng.ingest(d1).unwrap();
        let d2 = deposit(vec![tip], &bob, usd(1_000_000), 2);
        tip = unit_id(&d2);
        eng.ingest(d2).unwrap();
        assert_eq!(pots(&eng, a), usd(10_000));

        // Isolated open escrows the margin out of collateral.
        let px = 100_000 * PRICE_SCALE as i64;
        let qty = QTY_SCALE / 1000;
        let p1 = place_iso(
            vec![tip],
            &alice,
            BTC_USD,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty,
            1,
            4_000 * USD_SCALE,
        );
        tip = unit_id(&p1);
        let evs = eng.ingest(p1).unwrap();
        assert!(
            evs.iter().any(|e| matches!(e, ExecEvent::Applied { .. })),
            "{evs:?}"
        );
        assert_eq!(eng.state.accounts[&a].collateral, usd(6_000));
        assert_eq!(pots(&eng, a), usd(10_000));

        // Cancel refunds the whole escrow.
        let c = sign_unit(
            vec![tip],
            Op::Cancel {
                account: a,
                order_id: order_id(a, BTC_USD, 1),
            },
            &alice,
        );
        tip = unit_id(&c);
        let evs = eng.ingest(c).unwrap();
        assert!(
            evs.iter().any(|e| matches!(e, ExecEvent::Applied { .. })),
            "{evs:?}"
        );
        assert_eq!(eng.state.accounts[&a].collateral, usd(10_000));
        assert_eq!(pots(&eng, a), usd(10_000));

        // Re-place: escrow leaves collateral again.
        let p2 = place_iso(
            vec![tip],
            &alice,
            BTC_USD,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty,
            2,
            4_000 * USD_SCALE,
        );
        tip = unit_id(&p2);
        eng.ingest(p2).unwrap();
        assert_eq!(eng.state.accounts[&a].collateral, usd(6_000));
        assert_eq!(pots(&eng, a), usd(10_000));

        // Counter-taker fills it completely: escrow moves into the bucket.
        let t = place(
            vec![tip],
            &bob,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty,
            1,
        );
        let evs = eng.ingest(t).unwrap();
        assert!(
            evs.iter().any(|e| matches!(
                e,
                ExecEvent::Applied { fills, .. } if !fills.is_empty()
            )),
            "{evs:?}"
        );
        let acct = &eng.state.accounts[&a];
        assert_eq!(acct.collateral, usd(6_000));
        assert_eq!(
            acct.isolated_margin.get(&BTC_USD).copied().unwrap_or(0),
            usd(4_000)
        );
        assert_eq!(pots(&eng, a), usd(10_000));
    }

    /// Pins the dispute AA's taker collateral identity against the engine
    /// for an honest isolated open, both fill shapes:
    ///
    ///   post = old_col - taker_post - still - tfee
    ///     (release = pnl = post_back = 0 for an open)
    ///
    /// where `taker_post` is the fill's escrow share (into the bucket) and
    /// `still` the taker order's post-unit margin_left. The escrow `margin`
    /// itself cancels algebraically: net = -taker_post - still = -margin
    /// when the order fully fills, -margin when it rests (still holds the
    /// remainder), -taker_post on a non-resting partial (refund returns
    /// margin - taker_post). The plan's shorthand `old - margin + still`
    /// only coincides at full fill; this test pins the engine so the AA
    /// formula is never guessed.
    #[test]
    fn isolated_open_collateral_identity() {
        let usd = |v: i128| v * USD_SCALE as i128;
        let taker_fee = |notional_usd: i128| notional_usd * 5 / 10_000; // 5 bps

        // --- Shape A: full fill — order consumed, no post ord leaf -------
        let mut eng = activated_engine();
        let g = genesis_id();
        let alice = sk(1);
        let bob = sk(2);
        let a = acct_of(&alice);
        let px = 100_000 * PRICE_SCALE as i64;
        let qty = QTY_SCALE / 1000; // 0.001 BTC = $100 notional
        let margin = 40 * USD_SCALE; // >= extra_im (10% of $100)
        let d1 = deposit(vec![g], &alice, usd(10_000), 1);
        let mut tip = unit_id(&d1);
        eng.ingest(d1).unwrap();
        let d2 = deposit(vec![tip], &bob, usd(1_000_000), 2);
        tip = unit_id(&d2);
        eng.ingest(d2).unwrap();
        let old_col = eng.state.accounts[&a].collateral;
        let ask = place(
            vec![tip],
            &bob,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty,
            1,
        );
        tip = unit_id(&ask);
        eng.ingest(ask).unwrap();
        let bid = place_iso(
            vec![tip],
            &alice,
            BTC_USD,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty,
            1,
            margin,
        );
        let evs = eng.ingest(bid).unwrap();
        let fills = evs
            .iter()
            .find_map(|e| match e {
                ExecEvent::Applied { fills, .. } if !fills.is_empty() => Some(fills.clone()),
                _ => None,
            })
            .expect("isolated open filled");
        assert_eq!(fills.len(), 1, "single fill");
        let fee = taker_fee(100 * USD_SCALE as i128); // $100 notional, 5 bps
                                                      // still: the taker order is gone (full fill, not resting) -> 0.
        let still = 0;
        assert_eq!(
            eng.state.accounts[&a].collateral,
            old_col - fills[0].taker_post - still - fee,
            "A: full fill — identity old - taker_post - still - fee"
        );
        assert_eq!(
            eng.state.accounts[&a]
                .isolated_margin
                .get(&BTC_USD)
                .copied()
                .unwrap_or(0),
            fills[0].taker_post,
            "A: taker_post moved to the bucket (produced_open)"
        );
        // Plan shorthand coincidence at full fill: taker_post == margin.
        assert_eq!(fills[0].taker_post, i128::from(margin));
        assert_eq!(
            eng.state.accounts[&a].collateral,
            old_col - i128::from(margin) - fee
        );

        // --- Shape B: partial fill, order rests — still > 0 ---------------
        let mut eng = activated_engine();
        let mut tip = {
            let d1 = deposit(vec![g], &alice, usd(10_000), 1);
            let id = unit_id(&d1);
            eng.ingest(d1).unwrap();
            id
        };
        let d2 = deposit(vec![tip], &bob, usd(1_000_000), 2);
        tip = unit_id(&d2);
        eng.ingest(d2).unwrap();
        let old_col = eng.state.accounts[&a].collateral;
        let qty_small = QTY_SCALE / 2000; // resting ask: 0.0005 BTC
        let qty_big = QTY_SCALE / 1000; // crossing bid: 0.001 BTC -> rests
        let ask = place(
            vec![tip],
            &bob,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty_small,
            1,
        );
        tip = unit_id(&ask);
        eng.ingest(ask).unwrap();
        let bid = place_iso(
            vec![tip],
            &alice,
            BTC_USD,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty_big,
            1,
            margin,
        );
        let evs = eng.ingest(bid).unwrap();
        let fills = evs
            .iter()
            .find_map(|e| match e {
                ExecEvent::Applied { fills, .. } if !fills.is_empty() => Some(fills.clone()),
                _ => None,
            })
            .expect("partial isolated fill");
        assert_eq!(fills.len(), 1, "single fill");
        let taker_post = fills[0].taker_post;
        // pro-rata: margin * fill/remaining = 40 * (0.0005/0.001) = 20.
        assert_eq!(taker_post, 20 * USD_SCALE as i128);
        let still: i128 = eng
            .state
            .books
            .values()
            .flat_map(|b| b.live_orders())
            .filter(|o| o.account == a)
            .map(|o| i128::from(o.margin_left))
            .sum();
        assert_eq!(
            still,
            20 * USD_SCALE as i128,
            "resting remainder stays escrowed"
        );
        let fee = taker_fee(50 * USD_SCALE as i128); // fill notional $50
        assert_eq!(
            eng.state.accounts[&a].collateral,
            old_col - taker_post - still - fee,
            "B: partial resting — identity old - taker_post - still - fee"
        );
        assert_eq!(
            eng.state.accounts[&a]
                .isolated_margin
                .get(&BTC_USD)
                .copied()
                .unwrap_or(0),
            taker_post,
            "B: only the fill's escrow share reached the bucket"
        );
        // The plan's literal `old - margin + still` disagrees here
        // (old - 40 + 20 != old - 20 - 20): -taker_post - still is the
        // engine-exact net escrow effect the AA must use.
        assert_ne!(
            eng.state.accounts[&a].collateral,
            old_col - i128::from(margin) + still - fee
        );
    }

    /// Place-path self-trade against an ESCROWED own order is rejected
    /// outright: canceling that maker would refund its margin_left into
    /// collateral inside the same fill-bearing unit — a cash leg no fill
    /// predicate can model, so the dispute's exact identity would
    /// false-verdict the honest batch. Cross self-trades still take the
    /// cancel-maker-continue path (book tests pin both modes), and
    /// liquidation keeps it.
    #[test]
    fn isolated_self_trade_place_rejected() {
        let usd = |v: i128| v * USD_SCALE as i128;
        let mut eng = activated_engine();
        let g = genesis_id();
        let alice = sk(1);
        let a = acct_of(&alice);
        let px = 100_000 * PRICE_SCALE as i64;
        let qty = QTY_SCALE / 1000;
        let margin = 40 * USD_SCALE;
        let pots = |eng: &Engine| -> i128 {
            let acct = &eng.state.accounts[&a];
            let bucket: i128 = acct.isolated_margin.values().sum();
            let live: i128 = eng
                .state
                .books
                .values()
                .flat_map(|b| b.live_orders())
                .filter(|o| o.account == a)
                .map(|o| i128::from(o.margin_left))
                .sum();
            acct.collateral + bucket + live
        };
        let d1 = deposit(vec![g], &alice, usd(10_000), 1);
        let mut tip = unit_id(&d1);
        eng.ingest(d1).unwrap();
        // Rest an isolated bid (escrowed own maker).
        let bid = place_iso(
            vec![tip],
            &alice,
            BTC_USD,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty,
            1,
            margin,
        );
        tip = unit_id(&bid);
        eng.ingest(bid).unwrap();
        let col_before = eng.state.accounts[&a].collateral;
        let pots_before = pots(&eng);
        assert_eq!(col_before, usd(10_000) - i128::from(margin));
        // The same account now crosses its own isolated bid with an
        // isolated ask at the same price: place must reject.
        let ask = place_iso(
            vec![tip],
            &alice,
            BTC_USD,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty,
            2,
            margin,
        );
        let evs = eng.ingest(ask).unwrap();
        assert!(
            evs.iter().any(|e| matches!(
                e,
                ExecEvent::Rejected {
                    reason: RejectReason::Book(BookError::SelfTrade),
                    ..
                }
            )),
            "escrowed self-trade must reject: {evs:?}"
        );
        // The rejection unwound the new escrow before touching the book:
        // collateral, the live maker and the pots are as before the try.
        assert_eq!(eng.state.accounts[&a].collateral, col_before);
        assert_eq!(pots(&eng), pots_before);
        let live: Vec<_> = eng
            .state
            .books
            .values()
            .flat_map(|b| b.live_orders())
            .filter(|o| o.account == a)
            .collect();
        assert_eq!(live.len(), 1, "own maker untouched");
        assert_eq!(i128::from(live[0].margin_left), i128::from(margin));
    }

    #[test]
    fn place_reject_after_prior_maker_match_is_atomic() {
        let mut eng = activated_engine();
        let alice = AccountId([1; 32]);
        let bob = AccountId([2; 32]);
        let px = 100_000 * PRICE_SCALE as i64;
        let qty = QTY_SCALE / 1000;
        let maker_margin = 40 * USD_SCALE;
        for id in [alice, bob] {
            eng.state
                .account_mut(id)
                .credit(10_000 * USD_SCALE as i128)
                .unwrap();
        }

        // Bob is first in the ask queue; Alice's escrowed ask follows it.
        eng.place(
            bob,
            BTC_USD,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty,
            1,
            operp_types::UnitId([11; 32]),
            1,
            false,
            0,
        )
        .unwrap();
        eng.place(
            alice,
            BTC_USD,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty,
            1,
            operp_types::UnitId([12; 32]),
            2,
            true,
            maker_margin,
        )
        .unwrap();
        let before = eng.state.state_root();

        let err = eng.place(
            alice,
            BTC_USD,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            2 * qty,
            2,
            operp_types::UnitId([13; 32]),
            3,
            true,
            80 * USD_SCALE,
        );
        assert_eq!(err, Err(RejectReason::Book(BookError::SelfTrade)));
        assert_eq!(eng.state.state_root(), before);
        assert_eq!(eng.state.books[&BTC_USD].order_count(), 2);
    }

    #[test]
    fn place_maker_account_error_rolls_back_book_and_taker() {
        let mut eng = activated_engine();
        let taker = AccountId([3; 32]);
        let maker = AccountId([4; 32]);
        let px = 100_000 * PRICE_SCALE as i64;
        let qty = QTY_SCALE / 1000;
        eng.state
            .account_mut(taker)
            .credit(10_000 * USD_SCALE as i128)
            .unwrap();

        // Construct an otherwise-valid resting ask whose maker position
        // overflows when selling even one additional unit.
        let mut maker_account = operp_state::Account::new(maker);
        maker_account.positions.insert(
            BTC_USD,
            operp_account::Position {
                market: BTC_USD,
                qty: i64::MIN,
                entry_price: px,
                isolated: false,
            },
        );
        eng.state.accounts.insert(maker, maker_account);
        eng.state
            .book_mut(BTC_USD)
            .submit(operp_book::Order {
                id: order_id(maker, BTC_USD, 1),
                account: maker,
                market: BTC_USD,
                side: Side::Ask,
                typ: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: px,
                qty,
                remaining: qty,
                seq: 1,
                isolated: false,
                margin_left: 0,
            })
            .unwrap();
        let before = eng.state.state_root();

        let err = eng.place(
            taker,
            BTC_USD,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty,
            1,
            operp_types::UnitId([14; 32]),
            2,
            false,
            0,
        );
        assert_eq!(err, Err(RejectReason::Risk));
        assert_eq!(eng.state.state_root(), before);
        assert_eq!(eng.state.books[&BTC_USD].order_count(), 1);
        assert!(!eng.state.accounts[&taker].positions.contains_key(&BTC_USD));
    }

    /// A bleeding isolated bucket is liquidatable on its own risk while the
    /// cross snapshot stays healthy: market B liquidates, market A refuses,
    /// and B's mark-down never moves cross collateral.
    #[test]
    fn isolated_shields_cross() {
        let usd = |v: i128| v * USD_SCALE as i128;
        let mut eng = activated_engine();
        let g = genesis_id();
        let creator = sk(1);
        let alice = sk(2);
        let bob = sk(3);
        let a = acct_of(&alice);
        let bk = acct_of(&bob);

        // Second market (MarketId 2) via permissionless listing.
        let d0 = gov_dep(vec![g], &creator, CREATE_MARKET_FEE_PERP, 7);
        let mut tip = unit_id(&d0);
        eng.ingest(d0).unwrap();
        let lm = list_market(vec![tip], &creator);
        tip = unit_id(&lm);
        eng.ingest(lm).unwrap();
        let mkt2 = MarketId(2);

        let d1 = deposit(vec![tip], &alice, usd(1_000_000), 1);
        tip = unit_id(&d1);
        eng.ingest(d1).unwrap();
        let d2 = deposit(vec![tip], &bob, usd(1_000_000), 2);
        tip = unit_id(&d2);
        eng.ingest(d2).unwrap();

        // Cross long 1 BTC in market A: bob rests the ask, alice crosses.
        let px = 100_000 * PRICE_SCALE as i64;
        let ask = place(
            vec![tip],
            &bob,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE,
            1,
        );
        tip = unit_id(&ask);
        eng.ingest(ask).unwrap();
        let bid = place(
            vec![tip],
            &alice,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE,
            1,
        );
        tip = unit_id(&bid);
        eng.ingest(bid).unwrap();
        let pos_a = &eng.state.accounts[&a].positions[&BTC_USD];
        assert!(pos_a.qty > 0 && !pos_a.isolated);

        // Isolated long in market B with a $100 bucket: alice rests, bob crosses.
        let px2 = 1_000 * PRICE_SCALE as i64;
        let iso = place_iso(
            vec![tip],
            &alice,
            mkt2,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            px2,
            QTY_SCALE,
            2,
            100 * USD_SCALE,
        );
        tip = unit_id(&iso);
        eng.ingest(iso).unwrap();
        let cross2 = place_on(
            vec![tip],
            &bob,
            mkt2,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px2,
            QTY_SCALE,
            2,
        );
        eng.ingest(cross2).unwrap();
        let pos_b = &eng.state.accounts[&a].positions[&mkt2];
        assert!(pos_b.qty > 0 && pos_b.isolated);
        assert_eq!(eng.state.accounts[&a].isolated_margin[&mkt2], usd(100));

        // Mark A healthy, then drive B's mark from 1000 to 500: the bucket's
        // uPnL (-500) swallows the $100 bucket → isolated risk liquidatable.
        eng.state.marks.insert(BTC_USD, px);
        eng.state.marks.insert(mkt2, px2);
        let collateral_before = eng.state.accounts[&a].collateral;
        eng.state.marks.insert(mkt2, 500 * PRICE_SCALE as i64);

        let iso_risk =
            eng.state.accounts[&a].isolated_risk(mkt2, &eng.state.marks, &eng.state.markets);
        assert!(
            iso_risk.liquidatable,
            "isolated B must be liquidatable: {iso_risk:?}"
        );
        let cross_snap = eng.state.accounts[&a].snapshot(&eng.state.marks, &eng.state.markets);
        assert!(
            !cross_snap.liquidatable,
            "cross snapshot must stay healthy: {cross_snap:?}"
        );
        // B's bleeding never touched cross collateral.
        assert_eq!(eng.state.accounts[&a].collateral, collateral_before);

        // Cross market A refuses to liquidate...
        let r = eng.liquidate(UnitId([9u8; 32]), eng.state.seq, bk, a, BTC_USD);
        assert!(
            matches!(r, Err(RejectReason::NotLiquidatable)),
            "cross market must not liquidate: {r:?}"
        );

        // ...while isolated market B applies (empty book → insurance force-close).
        let fills = eng
            .liquidate(UnitId([8u8; 32]), eng.state.seq, bk, a, mkt2)
            .expect("isolated liquidation applies");
        assert!(!fills.is_empty(), "force-close fill expected");
        assert!(
            !eng.state.accounts[&a].positions.contains_key(&mkt2),
            "B position closed"
        );
        assert_eq!(
            eng.state.accounts[&a].isolated_margin[&mkt2], 0,
            "bucket emptied into collateral"
        );
        assert!(
            eng.state.accounts[&a].collateral >= 0,
            "A's collateral covers B's realized loss"
        );
    }

    /// Every mode/margin rejection from the plan.
    #[test]
    fn isolated_mode_gates() {
        let usd = |v: i128| v * USD_SCALE as i128;
        let mut eng = activated_engine();
        let g = genesis_id();
        let bob = sk(9);
        let px = 100_000 * PRICE_SCALE as i64;
        let qty = QTY_SCALE / 1000;
        let mut tip = g;
        for (i, secret) in [sk(10), sk(11), sk(12), sk(13), sk(14)].iter().enumerate() {
            let d = deposit(vec![tip], secret, usd(10_000), (i + 10) as u8);
            tip = unit_id(&d);
            eng.ingest(d).unwrap();
        }
        let db = deposit(vec![tip], &bob, usd(1_000_000), 20);
        tip = unit_id(&db);
        eng.ingest(db).unwrap();

        let expect_risk = |eng: &mut Engine, tip: UnitId, u: Unit| -> UnitId {
            let id = unit_id(&u);
            let evs = eng.ingest(u).unwrap();
            assert!(
                evs.iter().any(|e| matches!(
                    e,
                    ExecEvent::Rejected {
                        reason: RejectReason::Risk,
                        ..
                    }
                )),
                "expected Risk rejection: {evs:?} (parent {tip:?})"
            );
            id
        };

        // (a) cross order carrying margin → Risk.
        let bad_margin = sign_unit(
            vec![tip],
            Op::Place {
                account: acct_of(&sk(10)),
                market: BTC_USD,
                side: Side::Bid,
                typ: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: px,
                qty,
                client_seq: 1,
                isolated: false,
                margin: 1,
            },
            &sk(10),
        );
        tip = expect_risk(&mut eng, tip, bad_margin);

        // (c) isolated open with margin = extra_im - 1 → Risk.
        // extra_im = 10% of $100 notional = $10 → margin one unit short.
        let short_margin = sign_unit(
            vec![tip],
            Op::Place {
                account: acct_of(&sk(12)),
                market: BTC_USD,
                side: Side::Bid,
                typ: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: px,
                qty,
                client_seq: 1,
                isolated: true,
                margin: 10 * USD_SCALE - 1,
            },
            &sk(12),
        );
        tip = expect_risk(&mut eng, tip, short_margin);

        // (b) needs a filled isolated position: sk(11) rests an isolated bid,
        // bob crosses it.
        let iso_open = place_iso(
            vec![tip],
            &sk(11),
            BTC_USD,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty,
            1,
            1_000 * USD_SCALE,
        );
        tip = unit_id(&iso_open);
        let evs = eng.ingest(iso_open).unwrap();
        assert!(
            evs.iter().any(|e| matches!(e, ExecEvent::Applied { .. })),
            "{evs:?}"
        );
        let cross_ask = place(
            vec![tip],
            &bob,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty,
            1,
        );
        tip = unit_id(&cross_ask);
        let evs = eng.ingest(cross_ask).unwrap();
        assert!(
            evs.iter().any(|e| matches!(e, ExecEvent::Applied { .. })),
            "{evs:?}"
        );
        // isolated pure-reduce with margin = 1 → Risk.
        let reduce_margin = place_iso(
            vec![tip],
            &sk(11),
            BTC_USD,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty,
            2,
            1,
        );
        tip = expect_risk(&mut eng, tip, reduce_margin);

        // (d) live isolated order, then a cross order on the same market → Risk.
        let iso_rest = place_iso(
            vec![tip],
            &sk(13),
            BTC_USD,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            90_000 * PRICE_SCALE as i64,
            qty,
            1,
            1_000 * USD_SCALE,
        );
        tip = unit_id(&iso_rest);
        let evs = eng.ingest(iso_rest).unwrap();
        assert!(
            evs.iter().any(|e| matches!(e, ExecEvent::Applied { .. })),
            "{evs:?}"
        );
        let cross_over_iso = place(
            vec![tip],
            &sk(13),
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            91_000 * PRICE_SCALE as i64,
            qty,
            2,
        );
        tip = expect_risk(&mut eng, tip, cross_over_iso);

        // (e) cross position, then an isolated order on the same market → Risk.
        // Bob rests an ask that does NOT cross sk(13)'s 90k bid (90k < 100k).
        let bob_ask = place(
            vec![tip],
            &bob,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty,
            2,
        );
        tip = unit_id(&bob_ask);
        let evs = eng.ingest(bob_ask).unwrap();
        assert!(
            evs.iter().any(|e| matches!(e, ExecEvent::Applied { .. })),
            "{evs:?}"
        );
        let carol_cross = place(
            vec![tip],
            &sk(14),
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty,
            1,
        );
        tip = unit_id(&carol_cross);
        let evs = eng.ingest(carol_cross).unwrap();
        assert!(
            evs.iter().any(|e| matches!(e, ExecEvent::Applied { .. })),
            "{evs:?}"
        );
        assert!(eng.state.accounts[&acct_of(&sk(14))]
            .positions
            .get(&BTC_USD)
            .map(|p| !p.isolated)
            .unwrap_or(false));
        let iso_over_cross = place_iso(
            vec![tip],
            &sk(14),
            BTC_USD,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            99_000 * PRICE_SCALE as i64,
            qty,
            2,
            1_000 * USD_SCALE,
        );
        expect_risk(&mut eng, tip, iso_over_cross);
    }

    /// An isolated close that realizes more than its bucket leaves negative
    /// collateral mid-fill; the fill claw takes the hole from the winning
    /// counterparty. Insurance never pays it — the fund only gains the
    /// taker fee.
    #[test]
    fn isolated_blowthrough_insurance() {
        let usd = |v: i128| v * USD_SCALE as i128;
        let mut eng = activated_engine();
        let g = genesis_id();
        let alice = sk(1);
        let bob = sk(2);
        let a = acct_of(&alice);

        // Alice's entire deposit is the $10 IM-floor margin; bob is the
        // counterparty. Genesis seeds BTC's mark at $100k.
        let d1 = deposit(vec![g], &alice, usd(10), 1);
        let mut tip = unit_id(&d1);
        eng.ingest(d1).unwrap();
        let d2 = deposit(vec![tip], &bob, usd(1_000), 2);
        tip = unit_id(&d2);
        eng.ingest(d2).unwrap();

        // Bob rests an ask at $100k for 0.001 BTC ($100 notional → extra_im
        // $10); alice's isolated bid (margin = $10 = extra_im exactly)
        // crosses and opens the long with a $10 bucket.
        let px = 100_000 * PRICE_SCALE as i64;
        let qty = QTY_SCALE / 1000;
        let ask = place(
            vec![tip],
            &bob,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty,
            1,
        );
        tip = unit_id(&ask);
        let evs = eng.ingest(ask).unwrap();
        assert!(
            evs.iter().any(|e| matches!(e, ExecEvent::Applied { .. })),
            "{evs:?}"
        );
        let iso = place_iso(
            vec![tip],
            &alice,
            BTC_USD,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty,
            1,
            10 * USD_SCALE,
        );
        tip = unit_id(&iso);
        let evs = eng.ingest(iso).unwrap();
        assert!(
            evs.iter().any(|e| matches!(e, ExecEvent::Applied { .. })),
            "{evs:?}"
        );
        assert_eq!(eng.state.accounts[&a].collateral, 0);
        assert_eq!(eng.state.accounts[&a].isolated_margin[&BTC_USD], usd(10));

        let ins_before = eng.state.accounts[&INSURANCE_ACCOUNT].collateral;
        let b = acct_of(&bob);
        let bob_before = eng.state.accounts[&b].collateral;
        // Bob rests the closing bid at $50k; alice's isolated market ask
        // sells into it: release $10, realize −$50 → collateral −$40 (and
        // the $0.025 taker fee on top) before the fill claw.
        let bid = place(
            vec![tip],
            &bob,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            50_000 * PRICE_SCALE as i64,
            qty,
            2,
        );
        tip = unit_id(&bid);
        let evs = eng.ingest(bid).unwrap();
        assert!(
            evs.iter().any(|e| matches!(e, ExecEvent::Applied { .. })),
            "{evs:?}"
        );
        let close = place_iso(
            vec![tip],
            &alice,
            BTC_USD,
            Side::Ask,
            OrderType::Market,
            TimeInForce::Ioc,
            0,
            qty,
            2,
            0,
        );
        tip = unit_id(&close);
        let evs = eng.ingest(close).unwrap();
        assert!(
            evs.iter().any(|e| matches!(e, ExecEvent::Applied { .. })),
            "{evs:?}"
        );

        let acct = &eng.state.accounts[&a];
        assert_eq!(acct.collateral, 0, "hole clawed in full, never printed");
        assert!(acct.positions.is_empty(), "position fully closed");
        assert_eq!(acct.isolated_margin[&BTC_USD], 0, "bucket emptied");
        // Hole = $50 loss − $10 bucket + $0.025 taker fee = $40.025: it
        // is clawed from bob (the fill's winner). Insurance must not fall
        // by it — the fund only gains the close's fee.
        let close_fee = 25_000i128; // 5 bps of $50 notional
        assert_eq!(
            eng.state.accounts[&INSURANCE_ACCOUNT].collateral,
            ins_before + close_fee,
            "insurance gains only the fee; the $40 hole is clawed instead"
        );
        assert_eq!(
            eng.state.accounts[&b].collateral,
            bob_before + 50 * USD_SCALE as i128 - (40 * USD_SCALE as i128 + close_fee),
            "bob paid the whole hole"
        );
        let _ = tip;
    }
}
