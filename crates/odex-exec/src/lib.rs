use odex_account::AccountError;
use odex_book::{BookError, Fill, Order};
use odex_dag::{verify_sig, Dag, DagError, Op, Unit};
use odex_state::ChainState;
use odex_types::{
    bps, liq_order_id, notional_usd, order_id, AccountId, ExecStatus, OrderId,
    OrderType, Qty, Seq, Side, TimeInForce, UnitId, Usd, IM_RATE_BPS, BTC_USD,
};

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
        if !verify_sig(&unit) {
            return Err(ExecError::BadSig);
        }
        self.dag.insert(unit)?;
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
            Op::Liquidate { target, market } => self.liquidate(id, seq, *target, *market),
        }
    }

    fn place(
        &mut self,
        account: AccountId,
        market: odex_types::MarketId,
        side: Side,
        typ: OrderType,
        tif: TimeInForce,
        price: odex_types::Price,
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

        let snap = {
            let acct = self.state.accounts.get(&account);
            match acct {
                Some(a) => a.snapshot(&self.state.marks),
                None => odex_account::Account::new(account).snapshot(&self.state.marks),
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
            let px = if typ == OrderType::Limit && price != 0 {
                price
            } else {
                *self.state.marks.get(&market).unwrap_or(&0)
            };
            let extra_im = bps(notional_usd(qty, px), IM_RATE_BPS);
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
            self.state.apply_fill_pair(fill);
        }
        self.state.seen_client_seq.insert(account, client_seq);
        Ok(result.fills)
    }

    fn cancel(&mut self, account: AccountId, order_id: OrderId) -> Result<Vec<Fill>, RejectReason> {
        let market = BTC_USD;
        let book = self.state.books.get(&market).ok_or(RejectReason::NotFound)?;
        let order = book.get(order_id).ok_or(RejectReason::NotFound)?;
        if order.account != account {
            return Err(RejectReason::BadAccount);
        }
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
            return Err(RejectReason::DuplicateClientSeq);
        }
        let marks = self.state.marks.clone();
        self.state
            .account_mut(account)
            .debit(amount, &marks)
            .map_err(map_acct)?;
        self.state.withdrawals.insert(
            (account, nonce),
            odex_state::Withdrawal {
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
        target: AccountId,
        market: odex_types::MarketId,
    ) -> Result<Vec<Fill>, RejectReason> {
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
            self.state.apply_fill_pair(fill);
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
        if still && remaining_pos != 0 {
            let ins = AccountId([0u8; 32]);
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
            self.state.apply_fill_pair(&fill);
            fills.push(fill);
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
    use odex_dag::{genesis_id, sign_unit, unit_id, Op};
    use odex_types::{
        account_id_from_pubkey, PRICE_SCALE, QTY_SCALE, USD_SCALE,
    };
    use ed25519_dalek::SigningKey;

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
        price: odex_types::Price,
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
        assert_eq!(eng.state.accounts.get(&a).unwrap().positions[&BTC_USD].qty, qty as i64);
        assert_eq!(
            eng.state.accounts.get(&b).unwrap().positions[&BTC_USD].qty,
            -(qty as i64)
        );
    }

    #[test]
    fn duplicate_client_seq_rejected() {
        let mut eng = Engine::new();
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
}
