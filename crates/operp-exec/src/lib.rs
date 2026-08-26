use operp_account::AccountError;
use operp_book::{BookError, Fill, Order};
use operp_dag::{unit_id, Dag, DagError, Op, SigVerifier, Unit};
use operp_state::journal::{GovNonceJournal, GovNonceRecord};
use operp_state::persist;
use operp_state::{ChainState, Proposal};
use operp_types::{
    bps, genesis_params, liq_order_id, notional_usd, order_id, valid_obyte_addr, AccountId, Bps,
    ExecStatus, Height, MarketId, MarketParams, OrderId, OrderType, ParamKey, Price, Qty, Seq,
    Side, TimeInForce, UnitId, Usd, BTC_USD, CREATE_MARKET_FEE_PERP, INSURANCE_ACCOUNT,
    ORACLE_BOND_PERP, PROPOSAL_DURATION_SEQS, PROPOSAL_MIN_STAKE_PERP, PROPOSAL_QUORUM_DEN,
    PROPOSAL_QUORUM_NUM,
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
        })
    }

    /// Write a snapshot of the current state to the store dir. No-op for
    /// ephemeral engines. Compacts the gov-nonce WAL into the same atomic
    /// checkpoint.
    pub fn flush_snapshot(&mut self) -> std::io::Result<Option<PathBuf>> {
        let Some(dir) = self.store_dir.clone() else { return Ok(None) };
        persist::save_snapshot(&dir, &self.state).map(Some)
    }

    /// Cadence wrapper: flush every [`persist::SNAPSHOT_EVERY`] heights.
    /// Returns whether a snapshot was written this call.
    pub fn maybe_flush_snapshot(&mut self) -> std::io::Result<bool> {
        if self.store_dir.is_none() || self.state.height == 0 || self.state.height % persist::SNAPSHOT_EVERY != 0 {
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
        let Some(dir) = self.store_dir.clone() else { return Ok(()) };
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
        self.log.retain(|e| match e {
            ExecEvent::Applied { unit, .. } => !gone.contains(unit),
            ExecEvent::Rejected { unit, .. } => !gone.contains(unit),
        });
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
            } => self.place(
                *account, *market, *side, *typ, *tif, *price, *qty, *client_seq, seq,
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
            } => self.create_market(
                *creator,
                *symbol,
                *tick_size,
                *im_bps,
                *mm_bps,
                *taker_fee_bps,
                *keeper_reward_bps,
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
        seq: Seq,
    ) -> Result<Vec<Fill>, RejectReason> {
        let last = self.state.seen_client_seq.get(&account).copied().unwrap_or(0);
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
        let px_est = px_for_notional.max(mark);
        if (px_est as u128)
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


        let snap = {
            let acct = self.state.accounts.get(&account);
            match acct {
                Some(a) => a.snapshot(&self.state.marks),
                None => operp_account::Account::new(account).snapshot(&self.state.marks),
            }
        };
        let pos_qty = self
            .state
            .accounts
            .get(&account)
            .and_then(|a| a.positions.get(&market))
            .map(|p| p.qty)
            .unwrap_or(0);
        if snap.reduce_only {
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
        if open_qty != 0 {
            let extra_im = bps(
                notional_usd(open_qty.unsigned_abs(), px_est),
                self.state.market_params(market).im_bps,
            );
            if snap.equity < snap.im + extra_im {
                return Err(RejectReason::Risk);
            }
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
        };
        let result = self
            .state
            .book_mut(market)
            .submit(order)
            .map_err(RejectReason::Book)?;
        for fill in &result.fills {
            // Invariant: AccountError from apply_fill_pair is unreachable here
            // by construction — intake guards above bound qty·price <
            // i128::MAX and positions fit i64, so its checked arithmetic
            // cannot overflow. Should it ever fire anyway, this unit would
            // surface as Rejected with partially-applied state; that is a
            // documented known limitation, not a handled case.
            self.state.apply_fill_pair(fill).map_err(map_acct)?;
        }
        self.state.seen_client_seq.insert(account, client_seq);
        Ok(result.fills)
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
        self.state
            .book_mut(market)
            .cancel(order_id)
            .map_err(RejectReason::Book)?;
        Ok(Vec::new())
    }

    fn deposit(
        &mut self,
        account: AccountId,
        addr: &str,
        amount: Usd,
        aa_unit: [u8; 32],
    ) -> Result<Vec<Fill>, RejectReason> {
        if self.state.seen_aa_units.get(&aa_unit).is_some() {
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
        self.state
            .account_mut(account)
            .debit(amount, &marks)
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

    fn liquidate(
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
        let snap = self
            .state
            .accounts
            .get(&target)
            .ok_or(RejectReason::NotFound)?
            .snapshot(&self.state.marks);
        if !snap.liquidatable {
            return Err(RejectReason::NotLiquidatable);
        }
        let pos_qty = self
            .state
            .accounts
            .get(&target)
            .and_then(|a| a.positions.get(&market))
            .map(|p| p.qty)
            .unwrap_or(0);
        if pos_qty == 0 {
            return Err(RejectReason::NotLiquidatable);
        }
        let side = if pos_qty > 0 { Side::Ask } else { Side::Bid };
        let qty = pos_qty.unsigned_abs() as u64;
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
        };
        let result = self
            .state
            .book_mut(market)
            .submit(order)
            .map_err(RejectReason::Book)?;
        let mut fills = result.fills;
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
        let still = self
            .state
            .accounts
            .get(&target)
            .map(|a| a.snapshot(&self.state.marks).liquidatable)
            .unwrap_or(false);
        let remaining_pos = self
            .state
            .accounts
            .get(&target)
            .and_then(|a| a.positions.get(&market))
            .map(|p| p.qty)
            .unwrap_or(0);
        let mut keeper_paid = Usd::from(0u64);
        if still && remaining_pos != 0 {
            let ins = INSURANCE_ACCOUNT;
            let mark = *self.state.marks.get(&market).unwrap_or(&0);
            let close_qty = remaining_pos.unsigned_abs() as u64;
            let close_side = if remaining_pos > 0 { Side::Ask } else { Side::Bid };
            let fill = Fill {
                taker_id: oid,
                maker_id: OrderId([0u8; 32]),
                taker: target,
                maker: ins,
                market,
                price: mark,
                qty: close_qty,
                seq,
                taker_side: close_side,
            };
            self.state.apply_fill_pair(&fill).map_err(map_acct)?;
            fills.push(fill);
        }
        // Keeper reward: bps of filled notional, paid from the insurance fund.
        for f in &fills {
            let keeper_bps = self.state.market_params(market).keeper_reward_bps;
            keeper_paid += bps(notional_usd(f.qty, f.price), keeper_bps);
        }
        if keeper_paid > 0 {
            // Realized PnL settles into collateral, so the fund's spendable
            // balance is just its collateral.
            let ins_bal = self
                .state
                .accounts
                .get(&INSURANCE_ACCOUNT)
                .map(|a| a.collateral)
                .unwrap_or(0);
            let pay = keeper_paid.min(ins_bal.max(0));
            if pay > 0 {
                if let Some(a) = self.state.accounts.get_mut(&INSURANCE_ACCOUNT) {
                    a.collateral -= pay;
                }
                self.state.account_mut(caller).credit(pay).map_err(map_acct)?;
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
        if self.state.seen_aa_units.get(&aa_unit).is_some() {
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
        let watermark = self.state.seen_gov_nonces.get(&account).copied().unwrap_or(0);
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

    fn create_market(
        &mut self,
        creator: AccountId,
        symbol: [u8; 16],
        tick_size: operp_types::Price,
        im_bps: Bps,
        mm_bps: Bps,
        taker_fee_bps: Bps,
        keeper_reward_bps: Bps,
    ) -> Result<Vec<Fill>, RejectReason> {
        if tick_size == 0
            || im_bps == 0
            || mm_bps == 0
            || taker_fee_bps == 0
            || keeper_reward_bps == 0
        {
            return Err(RejectReason::Risk);
        }
        // A bps parameter above 100% is nonsensical and lets a market creator
        // set, say, an unbounded keeper reward drained from the insurance fund.
        if im_bps > 10_000 || mm_bps > 10_000 || taker_fee_bps > 10_000 || keeper_reward_bps > 10_000 {
            return Err(RejectReason::Risk);
        }
        if im_bps <= mm_bps || mm_bps < 500 || im_bps > 5000 || taker_fee_bps > 200 || keeper_reward_bps > 500 {
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
                delisted: false,
            },
        );
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
        match key {
            // Delist carries no value; bps parameters are capped at 100%.
            ParamKey::Delist => {
                if value != 0 {
                    return Err(RejectReason::Risk);
                }
            }
            _ => {
                if value > 10_000 {
                    return Err(RejectReason::Risk);
                }
            }
        }
        if !self.state.markets.contains_key(&market) {
            return Err(RejectReason::NotFound);
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
            let pass =
                p.yes > p.no && p.yes * PROPOSAL_QUORUM_DEN >= p.supply_at_create * PROPOSAL_QUORUM_NUM;
            (pass, p.market, p.key, p.value)
        };
        if pass {
            if let Some(params) = self.state.markets.get_mut(&market) {
                match key {
                    ParamKey::ImBps => params.im_bps = value,
                    ParamKey::MmBps => params.mm_bps = value,
                    ParamKey::TakerFeeBps => params.taker_fee_bps = value,
                    ParamKey::KeeperRewardBps => params.keeper_reward_bps = value,
                    ParamKey::Delist => params.delisted = true,
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
        // Height-gated: before activation, treat as unknown op -> BadAccount
        if self.state.height < operp_types::ORACLE_SLASH_ACTIVATION_HEIGHT {
            return Err(RejectReason::BadAccount);
        }
        self.state.apply_stake(account).map_err(map_state)?;
        Ok(Vec::new())
    }

    fn unstake_oracle(&mut self, account: AccountId) -> Result<Vec<Fill>, RejectReason> {
        if self.state.height < operp_types::ORACLE_SLASH_ACTIVATION_HEIGHT {
            return Err(RejectReason::BadAccount);
        }
        self.state.apply_unstake(account).map_err(map_state)?;
        Ok(Vec::new())
    }

    fn slash_oracle(
        &mut self,
        challenger: AccountId,
        target: AccountId,
        market: MarketId,
    ) -> Result<Vec<Fill>, RejectReason> {
        if self.state.height < operp_types::ORACLE_SLASH_ACTIVATION_HEIGHT {
            return Err(RejectReason::BadAccount);
        }
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
        if self.state.height < operp_types::COMMIT_REVEAL_ACTIVATION_HEIGHT {
            return Err(RejectReason::BadCommit);
        }
        if self.state.commits.contains_key(&commit) {
            return Err(RejectReason::BadCommit);
        }
        // Bound the reveal deadline to COMMIT_TTL_HEIGHTS past creation so
        // the pending set is memory-bounded; TTL ~16 heights ≈ 32 s.
        let commit_height = self.state.height;
        if ttl_height <= commit_height || ttl_height > commit_height + operp_types::COMMIT_TTL_HEIGHTS {
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
        if self.state.height < operp_types::COMMIT_REVEAL_ACTIVATION_HEIGHT {
            return Err(RejectReason::BadCommit);
        }
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
        let parents = self.dag.get(id).map(|u| u.parents.clone()).unwrap_or_default();
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
        if self.state.height < operp_types::FUNDING_TWAP_ACTIVATION_HEIGHT
            || self.state.funding_source != operp_types::FundingSourceKind::AggregatedExternal
        {
            return Err(RejectReason::NotFound);
        }
        if !self.state.external_sources.contains(&source) {
            return Err(RejectReason::BadAccount);
        }
        if !self.state.markets.contains_key(&market) || price == 0 {
            return Err(RejectReason::NotFound);
        }
        self.state
            .apply_external_price(source, market, price, source_id, caller_seq);
        Ok(Vec::new())
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
    use operp_dag::{genesis_id, sign_unit, unit_id, Op};
    use operp_types::{
        account_id_from_pubkey, PRICE_SCALE, QTY_SCALE, USD_SCALE,
    };
    use ed25519_dalek::SigningKey;

    /// Tests/examples run standalone (no AA feed): admit every deposit of
    /// BOTH asset kinds and seed the BTC_USD market with genesis params.
    /// Production replay injects real sets via `ChainState::deposits_allowed`
    /// keyed by (unit, is_perp); markets are created permissionlessly via
    /// `Op::CreateMarket`.
    fn allow_all(eng: &mut Engine) {
        eng.state.deposits_allowed = (0u8..=255)
            .flat_map(|b| [([b; 32], false), ([b; 32], true)])
            .collect();
        eng.state.markets.insert(BTC_USD, operp_types::genesis_params());
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
        let px = 100_000 * PRICE_SCALE;
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
        let a = acct_of(&alice);
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
            90_000 * PRICE_SCALE,
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
            91_000 * PRICE_SCALE,
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
        let px = 100_000 * PRICE_SCALE;
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
        eng.state.marks.insert(BTC_USD, 1 * PRICE_SCALE);
        let a = acct_of(&alice);
        assert!(eng.state.accounts.get(&a).unwrap().snapshot(&eng.state.marks).liquidatable);
        let ask2 = place(
            vec![id4],
            &bob,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            1 * PRICE_SCALE,
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
            u64::MAX / 2,
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
        let px = 100_000 * PRICE_SCALE;
        let ask = place(vec![id2], &bob, Side::Ask, OrderType::Limit, TimeInForce::Gtc, px, QTY_SCALE, 1);
        let id3 = unit_id(&ask);
        eng.ingest(ask).unwrap();
        let bid = place(vec![id3], &alice, Side::Bid, OrderType::Limit, TimeInForce::Gtc, px, QTY_SCALE, 1);
        let id4 = unit_id(&bid);
        eng.ingest(bid).unwrap();
        // crash to 80k: alice goes underwater (shortfall 5k absorbed by the
        // 10k-seeded insurance) and the liq fill notional (80k USD) yields a
        // 1% keeper reward of 800 USD that the fund can actually pay.
        eng.state.marks.insert(BTC_USD, 80_000 * PRICE_SCALE);
        let a = acct_of(&alice);
        let ask2 = place(vec![id4], &bob, Side::Bid, OrderType::Limit, TimeInForce::Gtc, 80_000 * PRICE_SCALE, QTY_SCALE, 2);
        let id5 = unit_id(&ask2);
        eng.ingest(ask2).unwrap();
        let ins_before = eng.state.accounts.get(&INSURANCE_ACCOUNT).unwrap().collateral;
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
        let keeper_acct = acct_of(&keeper);
        let keeper_bal = eng.state.accounts.get(&keeper_acct).map(|x| x.collateral).unwrap_or(0);
        assert!(keeper_bal > 0, "keeper must be rewarded");
        let ins_after = eng.state.accounts.get(&INSURANCE_ACCOUNT).unwrap().collateral;
        assert!(ins_after < ins_before, "insurance pays the reward");
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
        assert!(eng.log.iter().any(
            |e| matches!(e, ExecEvent::Applied { unit, status, .. }
                if *unit == id1 && *status == ExecStatus::Final)
        ));
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
                price: 100_000 * PRICE_SCALE,
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
        eng.state.oracle_bonds.insert(oa, operp_types::ORACLE_BOND_PERP);
        eng.state.oracle_bonds.insert(ob, operp_types::ORACLE_BOND_PERP);
        let g = genesis_id();
        let mk = |secret: &[u8; 32], px: u64| {
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
        eng.ingest(mk(&sk(5), 100_000 * PRICE_SCALE)).unwrap();
        eng.ingest(mk(&sk(6), 110_000 * PRICE_SCALE)).unwrap();
        // Effective mark = median across reporters; median of two is the
        // lower middle, i.e. 100_000 (which equals the genesis mark, so the
        // clamp keeps it).
        assert_eq!(
            eng.state.marks.get(&BTC_USD).copied().unwrap(),
            100_000 * PRICE_SCALE
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
            150_000 * PRICE_SCALE,
            QTY_SCALE,
            1,
        );
        eng.ingest(p).unwrap();
        assert_eq!(
            eng.state.marks.get(&BTC_USD).copied().unwrap(),
            100_000 * PRICE_SCALE,
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
        eng.state.deposits_allowed =
            (0u8..=255).flat_map(|b| [([b; 32], false), ([b; 32], true)]).collect();
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
        let p = propose(vec![g], &sk(1), 0, 500);
        eng.ingest(p).unwrap();
        let v = cast_vote(vec![g], &sk(1), 1, true);
        eng.ingest(v).unwrap();
        eng.state.seq = eng.state.proposals[&1].deadline_seq;
        let fin = finalize(vec![g], &sk(2), 1);
        let evs = eng.ingest(fin).unwrap();
        // The failed proposal is removed at finalize; params stay intact.
        assert!(!eng.state.proposals.contains_key(&1));
        // Genesis im_bps untouched.
        assert_eq!(eng.state.markets[&BTC_USD].im_bps, 1000);
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
            50_000 * PRICE_SCALE,
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
            51_000 * PRICE_SCALE,
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
        assert!(evs.iter().all(|e| matches!(e, ExecEvent::Applied { ref fills, .. } if fills.is_empty())));
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
        let px = 100_000 * PRICE_SCALE;
        let ask = place(vec![tip], &bob, Side::Ask, OrderType::Limit, TimeInForce::Gtc, px, QTY_SCALE, 1);
        tip = unit_id(&ask);
        eng.ingest(ask).unwrap();
        // Alice is long 1 BTC with just enough margin for that position.
        let bid = place(vec![tip], &alice, Side::Bid, OrderType::Limit, TimeInForce::Gtc, px, QTY_SCALE, 1);
        tip = unit_id(&bid);
        eng.ingest(bid).unwrap();
        // Flipping to short 2 BTC opens 1 net BTC: it must post full IM for
        // the opened leg, which her ~15k equity cannot cover (10k IM on the
        // open + maintenance on the existing one) → Risk.
        let evs = eng.ingest(
            place(vec![tip], &alice, Side::Ask, OrderType::Limit, TimeInForce::Gtc, px, 2 * QTY_SCALE, 2),
        ).unwrap();
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
        assert_eq!(eng.state.perp_balances[&acct_of(&sk(1))], CREATE_MARKET_FEE_PERP);
    }

    #[test]
    fn misaligned_tick_limit_rejected() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        eng.state.markets.insert(BTC_USD, operp_types::MarketParams {
            symbol: [0u8; 16],
            tick_size: 100 * operp_types::PRICE_SCALE,
            im_bps: operp_types::IM_RATE_BPS,
            mm_bps: operp_types::MM_RATE_BPS,
            taker_fee_bps: operp_types::TAKER_FEE_BPS,
            keeper_reward_bps: operp_types::KEEPER_REWARD_BPS,
            delisted: false,
        });
        eng.state
            .accounts
            .entry(acct_of(&sk(1)))
            .or_insert_with(|| operp_account::Account::new(acct_of(&sk(1))))
            .credit(1_000_000 * USD_SCALE as i128)
            .unwrap();
        // 150.5 is off the 100-grid → Risk; Market orders stay exempt.
        let evs = eng.ingest(
            place(vec![genesis_id()], &sk(1), Side::Bid, OrderType::Limit, TimeInForce::Gtc, 150_500 * PRICE_SCALE / 1000, QTY_SCALE, 1),
        ).unwrap();
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
                price: 90_000 * PRICE_SCALE,
                qty: QTY_SCALE,
                client_seq: 99,
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
        let good = place(vec![tip], &alice, Side::Bid, OrderType::Limit, TimeInForce::Gtc, 90_000 * PRICE_SCALE, QTY_SCALE, 1);
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
        eng.state.markets.insert(BTC_USD, operp_types::genesis_params());
        let g = genesis_id();
        eng.ingest(deposit(vec![g], &sk(1), 1_000 * USD_SCALE as i128, 5)).unwrap();
        assert_eq!(eng.state.accounts[&acct_of(&sk(1))].collateral, 1_000 * USD_SCALE as i128);
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
        eng.ingest(deposit(vec![g], &sk(1), 1_000 * USD_SCALE as i128, 1)).unwrap();
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
            ExecEvent::Rejected { reason: RejectReason::DuplicateNonce, .. }
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
        eng.ingest(deposit(vec![g], &alice, 10_000 * USD_SCALE as i128, 1)).unwrap();
        // Withdraw collateral (nonce 7) and deposit PERP (distinct aa unit,
        // same bound address).
        let wd = sign_unit(
            vec![g],
            Op::Withdraw { account, amount: 100 * USD_SCALE as i128, nonce: 7 },
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
        assert!(evs_gd.iter().any(|e| matches!(e, ExecEvent::Applied { .. })));

        // Snapshot + restart.
        eng.flush_snapshot().unwrap();
        let mut eng2 = Engine::load_or_genesis(&dir).unwrap();
        allow_all(&mut eng2);
        assert!(eng2.state.withdrawals.contains_key(&(account, 7)));

        // Same withdraw nonce after restart → DuplicateNonce.
        let dup = sign_unit(
            vec![g],
            Op::Withdraw { account, amount: 100 * USD_SCALE as i128, nonce: 7 },
            &alice,
        );
        let evs = eng2.ingest(dup).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected { reason: RejectReason::DuplicateNonce, .. }
        )));
        // Reused aa_unit after restart → DuplicateDeposit (collateral kind).
        let dep2 = deposit(vec![g], &sk(3), 100 * USD_SCALE as i128, 9);
        let evs = eng2.ingest(dep2).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            ExecEvent::Rejected { reason: RejectReason::DuplicateDeposit, .. }
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
        assert_eq!(e3.dag.eviction_salt(), derived_salt(root, operp_types::ORDERING_EPOCH_UNITS));

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
                        price: operp_types::PRICE_SCALE * u64::from(n),
                        qty: QTY_SCALE,
                        client_seq: u64::from(n),
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
            price: 100 * PRICE_SCALE,
            qty: QTY_SCALE / 1000,
            client_seq: 1,
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
            price: 100 * PRICE_SCALE,
            qty: QTY_SCALE / 1000,
            client_seq: 1,
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
                Some(ExecEvent::Rejected { reason: RejectReason::BadCommit, .. })
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
            price: 100 * PRICE_SCALE,
            qty: QTY_SCALE / 1000,
            client_seq: 1,
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
            Some(ExecEvent::Rejected { reason: RejectReason::BadCommit, .. })
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
            price: 100 * PRICE_SCALE,
            qty: QTY_SCALE / 1000,
            client_seq: 1,
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
            Some(ExecEvent::Rejected { reason: RejectReason::BadCommit, .. })
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
            price: 100 * PRICE_SCALE,
            qty: QTY_SCALE / 1000,
            client_seq: seq,
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
                    Some(ExecEvent::Rejected { reason: RejectReason::BadCommit, .. })
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
            Some(ExecEvent::Rejected { reason: RejectReason::BadCommit, .. })
        ));
    }

    #[test]
    fn pre_activation_commits_rejected() {
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
        assert!(matches!(
            events.last(),
            Some(ExecEvent::Rejected { reason: RejectReason::BadCommit, .. })
        ));
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
                price: 100 * PRICE_SCALE,
                qty: QTY_SCALE / 1000,
                client_seq: 1,
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

    fn external_price_unit(
        parents: Vec<UnitId>,
        secret: &[u8; 32],
        px: Price,
        source_id: u8,
    ) -> Unit {
        sign_unit(
            parents,
            Op::UpdateExternalPrice {
                source: acct_of(secret),
                market: BTC_USD,
                price: px,
                source_id,
            },
            secret,
        )
    }

    /// Two bonded reporters primed at `px` across distinct heights so the
    /// bonded-median funding TWAP converges to `px`.
    fn prime_bonded_twap(eng: &mut Engine, tip: &mut UnitId, oa: &[u8; 32], ob: &[u8; 32], px: Price, heights: u64) {
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
        eng.state.oracle_bonds.insert(acct_of(&oa), ORACLE_BOND_PERP);
        eng.state.oracle_bonds.insert(acct_of(&ob), ORACLE_BOND_PERP);
        eng.state.external_sources.insert(acct_of(&keeper));

        let mut tip = genesis_id();
        prime_bonded_twap(&mut eng, &mut tip, &oa, &ob, 90_000 * PRICE_SCALE, 4);
        assert_eq!(
            eng.state.funding_index_twap[&BTC_USD],
            90_000 * PRICE_SCALE
        );

        // Keeper posts an external anchor at 95k through the real dispatch
        // path; it lands in the ring but needs >= MIN_SAMPLES to drive index.
        let e1 = external_price_unit(vec![tip], &keeper, 95_000 * PRICE_SCALE, 0);
        tip = unit_id(&e1);
        let events = eng.ingest(e1).unwrap();
        assert!(matches!(events.last(), Some(ExecEvent::Applied { .. })));
        let e2 = external_price_unit(vec![tip], &keeper, 95_000 * PRICE_SCALE, 0);
        tip = unit_id(&e2);
        eng.ingest(e2).unwrap();
        assert_eq!(
            eng.state.external_twap(BTC_USD),
            Some(95_000 * PRICE_SCALE)
        );
        assert_eq!(
            eng.state.effective_funding_index(BTC_USD, 90_000 * PRICE_SCALE),
            95_000 * PRICE_SCALE,
            "fresh external ring must override the bonded-median TWAP"
        );

        // Feed dies: after MAX_STALENESS heights the index falls back to the
        // bonded TWAP so funding never freezes (doc §2.6 rule 2).
        eng.state.height += operp_types::FUNDING_EXTERNAL_MAX_STALENESS + 1;
        assert_eq!(
            eng.state.effective_funding_index(BTC_USD, 90_000 * PRICE_SCALE),
            90_000 * PRICE_SCALE
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
        let u = external_price_unit(vec![genesis_id()], &stranger, 95_000 * PRICE_SCALE, 0);
        let events = eng.ingest(u).unwrap();
        assert!(matches!(
            events.last(),
            Some(ExecEvent::Rejected { reason: RejectReason::BadAccount, .. })
        ));
        // BondedMedianTwap (default source): UpdateExternalPrice rejected so
        // v1 replay stays byte-identical.
        let mut eng2 = activated_engine();
        eng2.state.height = operp_types::FUNDING_TWAP_ACTIVATION_HEIGHT;
        eng2.state.external_sources.insert(acct_of(&keeper));
        let u2 = external_price_unit(vec![genesis_id()], &keeper, 95_000 * PRICE_SCALE, 0);
        let events2 = eng2.ingest(u2).unwrap();
        assert!(matches!(
            events2.last(),
            Some(ExecEvent::Rejected { reason: RejectReason::NotFound, .. })
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
        eng.state.oracle_bonds.insert(acct_of(&oa), ORACLE_BOND_PERP);
        eng.state.oracle_bonds.insert(acct_of(&ob), ORACLE_BOND_PERP);
        eng.state.external_sources.insert(acct_of(&keeper));
        // Collateral + opposite positions via deposits/places.
        let d1 = deposit(vec![genesis_id()], &alice, 1_000_000 * USD_SCALE as i128, 1);
        let mut tip = unit_id(&d1);
        eng.ingest(d1).unwrap();
        let d2 = deposit(vec![tip], &bob, 1_000_000 * USD_SCALE as i128, 2);
        tip = unit_id(&d2);
        eng.ingest(d2).unwrap();
        let px = 100_000 * PRICE_SCALE;
        let ask = place(
            vec![tip], &bob, Side::Ask, OrderType::Limit, TimeInForce::Gtc, px, QTY_SCALE / 1000, 1,
        );
        tip = unit_id(&ask);
        eng.ingest(ask).unwrap();
        let bid = place(
            vec![tip], &alice, Side::Bid, OrderType::Limit, TimeInForce::Gtc, px, QTY_SCALE / 1000, 1,
        );
        tip = unit_id(&bid);
        eng.ingest(bid).unwrap();

        // External keepers anchor the index at 50k while bonded reports push
        // medians (and thus the capped mark) to 100k: longs must pay shorts.
        let e1 = external_price_unit(vec![tip], &keeper, 50_000 * PRICE_SCALE, 0);
        tip = unit_id(&e1);
        eng.ingest(e1).unwrap();
        let e2 = external_price_unit(vec![tip], &keeper, 50_000 * PRICE_SCALE, 0);
        tip = unit_id(&e2);
        eng.ingest(e2).unwrap();
        prime_bonded_twap(&mut eng, &mut tip, &oa, &ob, 100_000 * PRICE_SCALE, 3);

        let pre_long = eng.state.accounts[&acct_of(&alice)].collateral;
        let pre_short = eng.state.accounts[&acct_of(&bob)].collateral;
        // One more report tick fires funding against the external index.
        eng.state.height += 1;
        let r = report_unit(vec![tip], &oa, 100_000 * PRICE_SCALE);
        tip = unit_id(&r);
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
        let cap = operp_types::bps(i128::from(QTY_SCALE / 1000) * (50_000 * PRICE_SCALE as i128), operp_types::FUNDING_CAP_BPS as u64);
        assert!(moved <= cap as i128 + USD_SCALE as i128, "cap holds");
    }
}
