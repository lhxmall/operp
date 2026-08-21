use odex_types::{
    bps, notional_usd, signed_notional_usd, AccountId, MarketId, Price, Qty, Side, Usd,
    IM_RATE_BPS, LIQ_RATIO_BPS, MM_RATE_BPS, PRICE_SCALE, QTY_SCALE, REDUCE_ONLY_RATIO_BPS,
    USD_SCALE,
};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Position {
    pub market: MarketId,
    pub qty: i64,
    pub entry_price: Price,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub id: AccountId,
    pub collateral: Usd,
    pub realized_pnl: Usd,
    pub positions: BTreeMap<MarketId, Position>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RiskSnapshot {
    pub equity: Usd,
    pub mm: Usd,
    pub im: Usd,
    pub margin_ratio_bps: Option<u64>,
    pub liquidatable: bool,
    pub reduce_only: bool,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum AccountError {
    #[error("insufficient")]
    Insufficient,
    #[error("overflow")]
    Overflow,
    #[error("qty too large")]
    QtyTooLarge,
    #[error("non-positive amount")]
    NonPositive,
}

impl Account {
    pub fn new(id: AccountId) -> Self {
        Self {
            id,
            collateral: 0,
            realized_pnl: 0,
            positions: BTreeMap::new(),
        }
    }

    pub fn apply_fill(
        &mut self,
        side: Side,
        _is_taker: bool,
        price: Price,
        qty: Qty,
        market: MarketId,
    ) -> Result<(), AccountError> {
        if qty > i64::MAX as u64 {
            return Err(AccountError::QtyTooLarge);
        }
        let delta: i64 = match side {
            Side::Bid => qty as i64,
            Side::Ask => -(qty as i64),
        };
        let pos = self.positions.get(&market).cloned().unwrap_or(Position {
            market,
            qty: 0,
            entry_price: 0,
        });
        let old = pos.qty;
        if old == 0 || same_sign(old, delta) {
            let new_qty = old + delta;
            let entry = if old == 0 {
                price
            } else {
                vwap(old.unsigned_abs() as u64, pos.entry_price, qty, price)
            };
            self.positions.insert(
                market,
                Position {
                    market,
                    qty: new_qty,
                    entry_price: entry,
                },
            );
        } else {
            let close = old.unsigned_abs().min(delta.unsigned_abs()) as u64;
            let pnl = realize(old, pos.entry_price, price, close);
            self.realized_pnl += pnl;
            let leftover = (old.unsigned_abs() as i64) - (close as i64);
            if leftover == 0 {
                let open = delta.unsigned_abs() as u64 - close;
                if open == 0 {
                    self.positions.remove(&market);
                } else {
                    self.positions.insert(
                        market,
                        Position {
                            market,
                            qty: if delta > 0 { open as i64 } else { -(open as i64) },
                            entry_price: price,
                        },
                    );
                }
            } else {
                let signed = if old > 0 { leftover } else { -leftover };
                self.positions.insert(
                    market,
                    Position {
                        market,
                        qty: signed,
                        entry_price: pos.entry_price,
                    },
                );
            }
        }
        if let Some(p) = self.positions.get(&market) {
            if p.qty == 0 {
                self.positions.remove(&market);
            }
        }
        Ok(())
    }

    pub fn snapshot(&self, marks: &BTreeMap<MarketId, Price>) -> RiskSnapshot {
        let mut upnl: Usd = 0;
        let mut mm: Usd = 0;
        let mut im: Usd = 0;
        for (m, pos) in &self.positions {
            let mark = marks.get(m).copied().unwrap_or(0);
            upnl += signed_notional_usd(pos.qty, mark) - signed_notional_usd(pos.qty, pos.entry_price);
            let abs_n = notional_usd(pos.qty.unsigned_abs() as u64, mark);
            mm += bps(abs_n, MM_RATE_BPS);
            im += bps(abs_n, IM_RATE_BPS);
        }
        let equity = self.collateral + self.realized_pnl + upnl;
        let margin_ratio_bps = if mm == 0 {
            None
        } else if equity < 0 {
            Some(0)
        } else {
            Some((equity.saturating_mul(10_000) / mm) as u64)
        };
        let liquidatable = mm > 0 && equity * 10_000 <= mm * i128::from(LIQ_RATIO_BPS);
        let reduce_only = mm > 0 && equity * 10_000 <= mm * i128::from(REDUCE_ONLY_RATIO_BPS);
        RiskSnapshot {
            equity,
            mm,
            im,
            margin_ratio_bps,
            liquidatable,
            reduce_only,
        }
    }

    pub fn credit(&mut self, amount: Usd) -> Result<(), AccountError> {
        if amount < 0 {
            return Err(AccountError::NonPositive);
        }
        self.collateral = self
            .collateral
            .checked_add(amount)
            .ok_or(AccountError::Overflow)?;
        Ok(())
    }

    pub fn debit(&mut self, amount: Usd, marks: &BTreeMap<MarketId, Price>) -> Result<(), AccountError> {
        if amount <= 0 {
            return Err(AccountError::NonPositive);
        }
        if self.collateral < amount {
            return Err(AccountError::Insufficient);
        }
        self.collateral -= amount;
        let snap = self.snapshot(marks);
        if snap.reduce_only {
            self.collateral += amount;
            return Err(AccountError::Insufficient);
        }
        Ok(())
    }
}

fn same_sign(a: i64, b: i64) -> bool {
    (a > 0 && b > 0) || (a < 0 && b < 0)
}

fn vwap(old_qty: Qty, old_px: Price, fill_qty: Qty, fill_px: Price) -> Price {
    let num = u128::from(old_qty) * u128::from(old_px) + u128::from(fill_qty) * u128::from(fill_px);
    let den = u128::from(old_qty) + u128::from(fill_qty);
    (num / den) as Price
}

fn realize(old_qty: i64, entry: Price, exit: Price, reduce_qty: Qty) -> Usd {
    let signed = if old_qty > 0 {
        i128::from(exit) - i128::from(entry)
    } else {
        i128::from(entry) - i128::from(exit)
    };
    signed * i128::from(reduce_qty) / i128::from(PRICE_SCALE) * i128::from(USD_SCALE)
        / i128::from(QTY_SCALE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use odex_types::{BTC_USD, PRICE_SCALE, QTY_SCALE, USD_SCALE};

    fn marks(px: Price) -> BTreeMap<MarketId, Price> {
        let mut m = BTreeMap::new();
        m.insert(BTC_USD, px);
        m
    }

    #[test]
    fn long_then_mark_up_increases_equity() {
        let mut a = Account::new(AccountId([1; 32]));
        a.credit(10_000 * USD_SCALE as i128).unwrap();
        a.apply_fill(Side::Bid, true, 100_000 * PRICE_SCALE, QTY_SCALE, BTC_USD)
            .unwrap();
        let before = a.snapshot(&marks(100_000 * PRICE_SCALE)).equity;
        let after = a.snapshot(&marks(110_000 * PRICE_SCALE)).equity;
        assert!(after > before);
    }

    #[test]
    fn close_long_at_profit() {
        let mut a = Account::new(AccountId([1; 32]));
        a.credit(10_000 * USD_SCALE as i128).unwrap();
        a.apply_fill(Side::Bid, true, 100_000 * PRICE_SCALE, QTY_SCALE, BTC_USD)
            .unwrap();
        a.apply_fill(Side::Ask, true, 110_000 * PRICE_SCALE, QTY_SCALE, BTC_USD)
            .unwrap();
        assert!(a.positions.is_empty());
        assert!(a.realized_pnl > 0);
    }

    #[test]
    fn margin_ratio_liq_boundary() {
        let mut a = Account::new(AccountId([1; 32]));
        a.apply_fill(Side::Bid, true, 2_000 * PRICE_SCALE, QTY_SCALE, BTC_USD)
            .unwrap();
        let mark = 2_000 * PRICE_SCALE;
        let mm = a.snapshot(&marks(mark)).mm;
        assert_eq!(mm, 100 * USD_SCALE as i128);
        a.collateral = 105 * USD_SCALE as i128;
        a.realized_pnl = 0;
        let s = a.snapshot(&marks(mark));
        assert!(s.liquidatable);
        a.collateral = 104 * USD_SCALE as i128;
        let s = a.snapshot(&marks(mark));
        assert!(s.liquidatable);
        a.collateral = 106 * USD_SCALE as i128;
        let s = a.snapshot(&marks(mark));
        assert!(!s.liquidatable);
    }

    #[test]
    fn withdraw_blocked_in_reduce_only() {
        let mut a = Account::new(AccountId([1; 32]));
        a.credit(6 * USD_SCALE as i128).unwrap();
        a.apply_fill(Side::Bid, true, 100 * PRICE_SCALE, QTY_SCALE, BTC_USD)
            .unwrap();
        let m = marks(100 * PRICE_SCALE);
        let s = a.snapshot(&m);
        assert!(s.reduce_only);
        assert!(a.debit(1, &m).is_err());
    }
}
