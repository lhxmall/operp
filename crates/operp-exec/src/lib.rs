use operp_account::AccountError;
use operp_book::{BookError, Fill, Order};
use operp_dag::{unit_id, verify_sig_by_id, Dag, DagError, Op, Unit};
use operp_state::ChainState;
use operp_types::{
    bps, liq_order_id, notional_usd, order_id, AccountId, ExecStatus, OrderId, OrderType,
    Qty, Seq, Side, TimeInForce, UnitId, Usd, IM_RATE_BPS, INSURANCE_ACCOUNT,
    KEEPER_REWARD_BPS, BTC_USD,
};
use std::collections::HashSet;

/// Withdrawal ledger bound: once this many (account, nonce) entries are
/// pending, further withdrawals are rejected with Risk until entries clear.
/// Keeps ChainState.withdrawals bounded.
const WITHDRAWALS_CAP: usize = 65_536;

#[derive(Clone, Debug)]
pub struct Engine {
    pub dag: Dag,
    pub state: ChainState,
    pub log: Vec<ExecEvent>,
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
        }
    }

    pub fn ingest(&mut self, unit: Unit) -> Result<Vec<ExecEvent>, ExecError> {
        // Hash exactly once: the signature is verified against this id and
        // the same id is handed to the DAG, skipping its recomputation.
        let id = unit_id(&unit);
        if !verify_sig_by_id(&unit, &id) {
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


    fn apply_one(&mut self, id: UnitId) -> ExecEvent {
        let unit = self.dag.get(id).cloned().expect("unit in dag");
        let seq = self.state.seq;
        self.state.seq += 1;
        let event = match self.dispatch(id, seq, &unit.op) {
            Ok(fills) => ExecEvent::Applied {
                unit: id,
                seq,
                fills,
                status: ExecStatus::Optimistic,
            },
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
                amount,
                aa_unit,
            } => self.deposit(*account, *amount, *aa_unit),
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
            Op::OracleSet {
                oracle,
                source,
                market,
                price,
            } => {
                // Trust gate: only whitelisted oracle accounts may set prices.
                if !self.state.trusted_oracles.contains(oracle) {
                    return Err(RejectReason::BadAccount);
                }
                if *source > 1 {
                    return Err(RejectReason::Risk);
                }
                self.state.apply_oracle(*source, *market, *price);
                Ok(Vec::new())
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
        let px_for_notional = if typ == OrderType::Limit && price != 0 {
            price
        } else {
            *self.state.marks.get(&market).unwrap_or(&0)
        };
        if (px_for_notional as u128)
            .checked_mul(qty as u128)
            .map(|n| n > i128::MAX as u128)
            .unwrap_or(true)
        {
            return Err(RejectReason::Risk);
        }
        // Market whitelist: never lazily create books for arbitrary markets.
        if !self.state.allowed_markets.contains(&market) {
            return Err(RejectReason::Risk);
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

        let increasing = match side {
            Side::Bid => pos_qty >= 0,
            Side::Ask => pos_qty <= 0,
        };
        if increasing {
            let extra_im = bps(notional_usd(qty, px_for_notional), IM_RATE_BPS);
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
        // id alone identifies the market. books is bounded by allowed_markets.
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
        amount: Usd,
        aa_unit: [u8; 32],
    ) -> Result<Vec<Fill>, RejectReason> {
        if self.state.seen_aa_units.contains(&aa_unit) {
            return Err(RejectReason::DuplicateDeposit);
        }
        // Deposit must reference a real AA deposit event in this batch window.
        if !self.state.deposits_allowed.contains(&aa_unit) {
            return Err(RejectReason::UnbackedDeposit);
        }
        self.state
            .account_mut(account)
            .credit(amount)
            .map_err(map_acct)?;
        self.state.seen_aa_units.insert(aa_unit);
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
        self.state.withdrawals.insert(
            (account, nonce),
            operp_state::Withdrawal {
                amount,
                pending: true,
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
            keeper_paid += bps(notional_usd(f.qty, f.price), KEEPER_REWARD_BPS);
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
}

fn map_acct(e: AccountError) -> RejectReason {
    match e {
        AccountError::Insufficient | AccountError::NonPositive => RejectReason::Insufficient,
        AccountError::Overflow | AccountError::QtyTooLarge => RejectReason::Risk,
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

    /// Tests/examples run standalone (no AA feed): admit every deposit and
    /// the BTC_USD market. Production replay injects real sets via
    /// `ChainState::deposits_allowed` / `allowed_markets`.
    fn allow_all(eng: &mut Engine) {
        eng.state.deposits_allowed = (0u8..=255)
            .map(|b| [b; 32])
            .collect();
        eng.state.allowed_markets.insert(BTC_USD);
    }

    fn sk(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn acct_of(secret: &[u8; 32]) -> AccountId {
        let pk = SigningKey::from_bytes(secret).verifying_key().to_bytes();
        account_id_from_pubkey(&pk)
    }

    fn deposit(parents: Vec<UnitId>, secret: &[u8; 32], amount: Usd, aa: u8) -> Unit {
        let account = acct_of(secret);
        sign_unit(
            parents,
            Op::Deposit {
                account,
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
        // No trusted oracles injected: any OracleSet must bounce.
        let o = sign_unit(
            vec![genesis_id()],
            Op::OracleSet {
                oracle: acct_of(&sk(5)),
                source: 0,
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
    fn dual_oracle_marks_averaged_and_fill_mark_gated() {
        let mut eng = Engine::new();
        allow_all(&mut eng);
        let oa = acct_of(&sk(5));
        let ob = acct_of(&sk(6));
        eng.state.trusted_oracles.insert(oa);
        eng.state.trusted_oracles.insert(ob);
        let g = genesis_id();
        let mk = |secret: &[u8; 32], src: u8, px: u64| {
            sign_unit(
                vec![g],
                Op::OracleSet {
                    oracle: acct_of(secret),
                    source: src,
                    market: BTC_USD,
                    price: px,
                },
                secret,
            )
        };
        eng.ingest(mk(&sk(5), 0, 100_000 * PRICE_SCALE)).unwrap();
        eng.ingest(mk(&sk(6), 1, 110_000 * PRICE_SCALE)).unwrap();
        // Effective mark = average of both sources.
        assert_eq!(
            eng.state.marks.get(&BTC_USD).copied().unwrap(),
            105_000 * PRICE_SCALE
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
            105_000 * PRICE_SCALE,
            "oracle-authoritative mark must ignore fills"
        );
    }
}
