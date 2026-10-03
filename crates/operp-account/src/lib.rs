use operp_types::{
    bps, funding_notional_usd, funding_rate_bps, funding_rate_cash, notional_usd,
    signed_notional_usd, AccountId, MarketId, MarketParams, Price, Qty, Side, Usd, IM_RATE_BPS,
    LIQ_RATIO_BPS, MM_RATE_BPS, PRICE_SCALE, QTY_SCALE, REDUCE_ONLY_RATIO_BPS, USD_SCALE,
};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Position {
    pub market: MarketId,
    pub qty: i64,
    pub entry_price: Price,
    /// Margin mode seeded from the opening fill's order. Once the position
    /// exists this flag is authoritative (mode cannot change mid-position).
    #[serde(default)]
    pub isolated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Account {
    pub id: AccountId,
    pub collateral: Usd,
    pub realized_pnl: Usd,
    pub positions: BTreeMap<MarketId, Position>,
    /// Per-market escrowed isolated margin (USD_SCALE units). Money here has
    /// already left `collateral`: `collateral + Σisolated_margin + Σlive
    /// order margin_left` only changes via deposit/withdraw/PnL.
    #[serde(default)]
    pub isolated_margin: BTreeMap<MarketId, Usd>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
            isolated_margin: BTreeMap::new(),
        }
    }

    /// `cash_per_bp` is `Some(usd_per_unit)` on funding-rate markets: the
    /// reducing fill then realizes rate-delta cash instead of the encoded
    /// price delta (whose dollar scale there is meaningless). `None` keeps
    /// today's `realize` path.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_fill(
        &mut self,
        side: Side,
        _is_taker: bool,
        price: Price,
        qty: Qty,
        market: MarketId,
        cash_per_bp: Option<u64>,
        post: Usd,
        isolated: bool,
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
            isolated,
        });
        let old = pos.qty;
        // Seed-only: a flat account takes the fill's order mode; an existing
        // position keeps its flag (Step 4's mode gate rejects mismatches).
        let seed = if old == 0 { isolated } else { pos.isolated };
        // Whether this fill creates or grows open quantity (as opposed to a
        // pure reduce). Decides where `post` lands: into the bucket when it
        // backs new exposure, back to collateral when it was escrow for a
        // reduce phase that never opened.
        let mut produced_open = false;
        if old == 0 || same_sign(old, delta) {
            produced_open = true;
            let new_qty = old.checked_add(delta).ok_or(AccountError::Overflow)?;
            let entry = if old == 0 {
                price
            } else {
                vwap(old.unsigned_abs(), pos.entry_price, qty, price)
            };
            self.positions.insert(
                market,
                Position {
                    market,
                    qty: new_qty,
                    entry_price: entry,
                    isolated: seed,
                },
            );
        } else {
            let close = old.unsigned_abs().min(delta.unsigned_abs());
            // Isolated close releases a proportional share of the bucket into
            // collateral BEFORE realized PnL settles, so a loss lands on
            // released margin first and the bucket never goes negative. A
            // full close (`close == old_abs`) empties the bucket exactly.
            if pos.isolated {
                let old_abs = old.unsigned_abs();
                if old_abs > 0 {
                    if let Some(bucket) = self.isolated_margin.get_mut(&market) {
                        let release = *bucket * i128::from(close) / i128::from(old_abs);
                        let release = release.clamp(0, *bucket);
                        *bucket -= release;
                        self.collateral = self
                            .collateral
                            .checked_add(release)
                            .ok_or(AccountError::Overflow)?;
                    }
                }
            }
            let pnl = match cash_per_bp {
                None => realize(old, pos.entry_price, price, close),
                // Sign follows the position: long profits when the exit
                // rate exceeds the entry rate, short the reverse.
                Some(usd) => funding_rate_cash(
                    if old > 0 {
                        close as i64
                    } else {
                        -(close as i64)
                    },
                    funding_rate_bps(price) - funding_rate_bps(pos.entry_price),
                    usd,
                ),
            };
            // Settle realized PnL into spendable collateral immediately so
            // winners can withdraw profits and the withdrawal-proof leaf
            // (which commits collateral only) reflects true solvency.
            // `realized_pnl` remains a cumulative statistic only.
            self.collateral = self
                .collateral
                .checked_add(pnl)
                .ok_or(AccountError::Overflow)?;
            self.realized_pnl = self.realized_pnl.saturating_add(pnl);
            let leftover = (old.unsigned_abs() as i64) - (close as i64);
            if leftover == 0 {
                let open = delta.unsigned_abs() - close;
                if open == 0 {
                    self.positions.remove(&market);
                } else {
                    produced_open = true;
                    self.positions.insert(
                        market,
                        Position {
                            market,
                            qty: if delta > 0 {
                                open as i64
                            } else {
                                -(open as i64)
                            },
                            entry_price: price,
                            isolated: seed,
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
                        isolated: seed,
                    },
                );
            }
        }
        if let Some(p) = self.positions.get(&market) {
            if p.qty == 0 {
                self.positions.remove(&market);
            }
        }
        // Post placement: open quantity escrows into the bucket (or tops up
        // an existing one); a pure-reduce post is returned escrow. Entries
        // are never deleted — a 0 entry is pending escrow for a live flip
        // order or a harmless zero.
        if post != 0 {
            if produced_open {
                *self.isolated_margin.entry(market).or_insert(0) += post;
            } else {
                self.collateral = self
                    .collateral
                    .checked_add(post)
                    .ok_or(AccountError::Overflow)?;
            }
        }
        Ok(())
    }

    pub fn snapshot(
        &self,
        marks: &BTreeMap<MarketId, Price>,
        params: &BTreeMap<MarketId, MarketParams>,
    ) -> RiskSnapshot {
        let mut upnl: Usd = 0;
        let mut mm: Usd = 0;
        let mut im: Usd = 0;
        // Positions in markets without a mark are excluded from equity/margin
        // and force reduce-only: a zero mark would fabricate full-notional
        // "losses" (longs) or "profits" (shorts) while zeroing margin needs.
        let mut has_unmarked = false;
        for (m, pos) in &self.positions {
            // Isolation: cross equity/risk never sees isolated positions —
            // their losses stop at their own bucket (see `isolated_risk`).
            if pos.isolated {
                continue;
            }
            let mark = match marks.get(m).copied() {
                Some(p) if p != 0 => p,
                _ => {
                    has_unmarked = true;
                    continue;
                }
            };
            let (u, m2, i2) = position_risk(pos, mark, params);
            upnl += u;
            mm += m2;
            im += i2;
        }
        // Realized PnL settles into `collateral` at close time, so equity is
        // collateral + unrealized. realized_pnl is a cumulative stat only.
        let equity = self.collateral + upnl;
        let margin_ratio_bps = if mm == 0 {
            None
        } else if equity < 0 {
            Some(0)
        } else {
            Some((equity.saturating_mul(10_000) / mm) as u64)
        };
        let liquidatable = mm > 0 && equity * 10_000 <= mm * i128::from(LIQ_RATIO_BPS);
        let reduce_only =
            has_unmarked || (mm > 0 && equity * 10_000 <= mm * i128::from(REDUCE_ONLY_RATIO_BPS));
        RiskSnapshot {
            equity,
            mm,
            im,
            margin_ratio_bps,
            liquidatable,
            reduce_only,
        }
    }

    /// Risk of `market`'s position when it is isolated: equity is the
    /// position's own bucket plus its unrealized PnL, so losses stop at the
    /// bucket and never touch cross collateral. No position, or a cross
    /// position: a trivial snapshot that is never liquidatable/reduce-only
    /// (the cross `snapshot` is the authority there). Missing mark: the
    /// bucket alone with reduce-only forced — uPnL is unknowable, so the
    /// position can only shrink.
    pub fn isolated_risk(
        &self,
        market: MarketId,
        marks: &BTreeMap<MarketId, Price>,
        params: &BTreeMap<MarketId, MarketParams>,
    ) -> RiskSnapshot {
        let trivial = |equity: Usd, reduce_only: bool| RiskSnapshot {
            equity,
            mm: 0,
            im: 0,
            margin_ratio_bps: None,
            liquidatable: false,
            reduce_only,
        };
        let pos = match self.positions.get(&market) {
            Some(p) if p.isolated => p,
            _ => return trivial(self.collateral, false),
        };
        let bucket = self.isolated_margin.get(&market).copied().unwrap_or(0);
        let mark = match marks.get(&market).copied() {
            Some(p) if p != 0 => p,
            _ => return trivial(bucket, true),
        };
        let (upnl, mm, im) = position_risk(pos, mark, params);
        let equity = bucket + upnl;
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

    pub fn debit(
        &mut self,
        amount: Usd,
        marks: &BTreeMap<MarketId, Price>,
        params: &BTreeMap<MarketId, MarketParams>,
    ) -> Result<(), AccountError> {
        if amount <= 0 {
            return Err(AccountError::NonPositive);
        }
        if self.collateral < amount {
            return Err(AccountError::Insufficient);
        }
        self.collateral -= amount;
        let snap = self.snapshot(marks, params);
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

/// Per-position (unrealized PnL, mm, im) at `mark`, verbatim from the
/// pooled `snapshot` math: funding-rate markets scale off the listing
/// multiplier, regular markets off notional. Shared by `snapshot` (cross)
/// and `isolated_risk`.
fn position_risk(
    pos: &Position,
    mark: Price,
    params: &BTreeMap<MarketId, MarketParams>,
) -> (Usd, Usd, Usd) {
    let m = &pos.market;
    // Per-market margin rates; a market absent from the map (stale
    // book, e.g. unit tests) falls back to the genesis rates.
    let fp = params.get(m).filter(|p| p.funding_rate);
    if let Some(p) = fp {
        // Funding-rate market: money scales with the listing-time
        // multiplier — book/marks there encode bps, not dollars.
        let notional = funding_notional_usd(pos.qty.unsigned_abs(), p.usd_per_unit);
        let upnl = funding_rate_cash(
            pos.qty,
            funding_rate_bps(mark) - funding_rate_bps(pos.entry_price),
            p.usd_per_unit,
        );
        return (upnl, bps(notional, p.mm_bps), bps(notional, p.im_bps));
    }
    let im_bps = params.get(m).map(|p| p.im_bps).unwrap_or(IM_RATE_BPS);
    let mm_bps = params.get(m).map(|p| p.mm_bps).unwrap_or(MM_RATE_BPS);
    let upnl = signed_notional_usd(pos.qty, mark) - signed_notional_usd(pos.qty, pos.entry_price);
    let abs_n = notional_usd(pos.qty.unsigned_abs(), mark).abs();
    (upnl, bps(abs_n, mm_bps), bps(abs_n, im_bps))
}

fn vwap(old_qty: Qty, old_px: Price, fill_qty: Qty, fill_px: Price) -> Price {
    // Signed i128 math: prices may print negative while quantities stay
    // non-negative; truncation toward zero matches `realize` below.
    let num = i128::from(old_qty) * i128::from(old_px) + i128::from(fill_qty) * i128::from(fill_px);
    let den = i128::from(old_qty) + i128::from(fill_qty);
    (num / den) as Price
}

fn realize(old_qty: i64, entry: Price, exit: Price, reduce_qty: Qty) -> Usd {
    let signed = if old_qty > 0 {
        i128::from(exit) - i128::from(entry)
    } else {
        i128::from(entry) - i128::from(exit)
    };
    // Scale up BEFORE dividing: `x / PRICE_SCALE * USD_SCALE` truncates
    // toward zero on every partial step (fixed by multiplying first).
    signed * i128::from(reduce_qty) * i128::from(USD_SCALE)
        / i128::from(PRICE_SCALE)
        / i128::from(QTY_SCALE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use operp_types::{BTC_USD, PRICE_SCALE, QTY_SCALE, USD_SCALE};

    fn marks(px: Price) -> BTreeMap<MarketId, Price> {
        let mut m = BTreeMap::new();
        m.insert(BTC_USD, px);
        m
    }

    #[test]
    fn long_then_mark_up_increases_equity() {
        let mut a = Account::new(AccountId([1; 32]));
        a.credit(10_000 * USD_SCALE as i128).unwrap();
        a.apply_fill(
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
        let before = a
            .snapshot(&marks(100_000 * PRICE_SCALE as i64), &BTreeMap::new())
            .equity;
        let after = a
            .snapshot(&marks(110_000 * PRICE_SCALE as i64), &BTreeMap::new())
            .equity;
        assert!(after > before);
    }
    #[test]
    fn negative_mark_keeps_margin_positive() {
        let mut a = Account::new(AccountId([1; 32]));
        a.credit(100_000 * USD_SCALE as i128).unwrap();
        a.apply_fill(
            Side::Bid,
            true,
            -100_000 * PRICE_SCALE as i64,
            QTY_SCALE,
            BTC_USD,
            None,
            0,
            false,
        )
        .unwrap();
        // Long 1 @ -100k, mark -90k: upnl = (-90k) - (-100k) = +10k.
        let s = a.snapshot(&marks(-90_000 * PRICE_SCALE as i64), &BTreeMap::new());
        assert_eq!(s.equity, 110_000 * USD_SCALE as i128);
        // Margin is charged on |notional| = 90k: mm = 5% = 4500, im = 9000.
        assert_eq!(s.mm, 4_500 * USD_SCALE as i128);
        assert_eq!(s.im, 9_000 * USD_SCALE as i128);
        // A negative mark is a real mark: no unmarked flag, no liquidation.
        assert!(!s.reduce_only);
        assert!(!s.liquidatable);
    }

    #[test]
    fn close_long_at_profit() {
        let mut a = Account::new(AccountId([1; 32]));
        a.credit(10_000 * USD_SCALE as i128).unwrap();
        a.apply_fill(
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
        a.apply_fill(
            Side::Ask,
            true,
            110_000 * PRICE_SCALE as i64,
            QTY_SCALE,
            BTC_USD,
            None,
            0,
            false,
        )
        .unwrap();
        assert!(a.positions.is_empty());
        // PnL settles into collateral: 10k deposit + 10k profit.
        assert_eq!(a.collateral, 20_000 * USD_SCALE as i128);
    }

    #[test]
    fn profitable_pnl_is_withdrawable() {
        let mut a = Account::new(AccountId([1; 32]));
        a.credit(10_000 * USD_SCALE as i128).unwrap();
        a.apply_fill(
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
        a.apply_fill(
            Side::Ask,
            true,
            110_000 * PRICE_SCALE as i64,
            QTY_SCALE,
            BTC_USD,
            None,
            0,
            false,
        )
        .unwrap();
        let m = marks(110_000 * PRICE_SCALE as i64);
        // Full balance (deposit + settled profit) is withdrawable.
        a.debit(20_000 * USD_SCALE as i128, &m, &BTreeMap::new())
            .unwrap();
        assert_eq!(a.collateral, 0);
    }
    #[test]
    fn margin_ratio_liq_boundary() {
        let mut a = Account::new(AccountId([1; 32]));
        a.apply_fill(
            Side::Bid,
            true,
            2_000 * PRICE_SCALE as i64,
            QTY_SCALE,
            BTC_USD,
            None,
            0,
            false,
        )
        .unwrap();
        let mark = 2_000 * PRICE_SCALE as i64;
        let mm = a.snapshot(&marks(mark), &BTreeMap::new()).mm;
        assert_eq!(mm, 100 * USD_SCALE as i128);
        a.collateral = 105 * USD_SCALE as i128;
        let s = a.snapshot(&marks(mark), &BTreeMap::new());
        assert!(s.liquidatable);
        a.collateral = 104 * USD_SCALE as i128;
        let s = a.snapshot(&marks(mark), &BTreeMap::new());
        assert!(s.liquidatable);
        a.collateral = 106 * USD_SCALE as i128;
        let s = a.snapshot(&marks(mark), &BTreeMap::new());
        assert!(!s.liquidatable);
    }

    #[test]
    fn funding_rate_upnl_uses_multiplier() {
        use operp_types::{encode_funding_price, funding_rate_cash};
        let mut p = operp_types::genesis_params();
        p.funding_rate = true;
        p.usd_per_unit = 10_000;
        p.im_bps = 100;
        p.mm_bps = 50;
        let mut params = BTreeMap::new();
        params.insert(MarketId(2), p);
        let mut marks = BTreeMap::new();
        let entry = encode_funding_price(12);
        let mark = encode_funding_price(20);
        marks.insert(MarketId(2), mark);
        let mut a = Account::new(AccountId([1; 32]));
        a.apply_fill(
            Side::Bid,
            true,
            entry,
            QTY_SCALE,
            MarketId(2),
            Some(10_000),
            0,
            false,
        )
        .unwrap();
        // 1 unit long, rate moved 12 → 20 bps: 8 bp on $10_000/unit = $8.
        // The encoded-price delta would book ~$0.0008 — a 10^4 mismatch.
        let expected = funding_rate_cash(QTY_SCALE as i64, 8, 10_000);
        assert_eq!(expected, 8 * USD_SCALE as i128, "sanity: 8bp on $10k");
        let s = a.snapshot(&marks, &params);
        assert_eq!(
            s.equity, expected,
            "uPnL uses the multiplier, not the encoded price"
        );
        // Margin also scales off the multiplier notional: $10_000 notional.
        assert_eq!(s.mm, 50 * USD_SCALE as i128);
        assert_eq!(s.im, 100 * USD_SCALE as i128);
        // Closed at the same rates: realized cash equals the uPnL.
        let mut b = a.clone();
        b.apply_fill(
            Side::Ask,
            true,
            mark,
            QTY_SCALE,
            MarketId(2),
            Some(10_000),
            0,
            false,
        )
        .unwrap();
        assert_eq!(
            b.collateral, expected,
            "reducing fill realizes the rate cash"
        );
        assert!(b.positions.is_empty());
    }

    #[test]
    fn withdraw_blocked_in_reduce_only() {
        let mut a = Account::new(AccountId([1; 32]));
        a.credit(6 * USD_SCALE as i128).unwrap();
        a.apply_fill(
            Side::Bid,
            true,
            100 * PRICE_SCALE as i64,
            QTY_SCALE,
            BTC_USD,
            None,
            0,
            false,
        )
        .unwrap();
        let m = marks(100 * PRICE_SCALE as i64);
        let s = a.snapshot(&m, &BTreeMap::new());
        assert!(s.reduce_only);
        assert!(a.debit(1, &m, &BTreeMap::new()).is_err());
    }

    #[test]
    fn unmarked_position_forces_reduce_only() {
        let mut a = Account::new(AccountId([1; 32]));
        a.credit(10_000 * USD_SCALE as i128).unwrap();
        a.apply_fill(
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
        // Empty marks map: the position's market has no mark.
        let empty = BTreeMap::new();
        let s = a.snapshot(&empty, &BTreeMap::new());
        // Equity undistorted (no phantom full-notional loss for the long).
        assert_eq!(s.equity, 10_000 * USD_SCALE as i128);
        assert_eq!(s.mm, 0);
        // Risk-increasing ops and withdrawals are blocked.
        assert!(s.reduce_only);
    }

    #[test]
    fn isolated_bucket_release() {
        let usd = |v: i128| v * USD_SCALE as i128;
        let px = |v: i64| v * PRICE_SCALE as i64;
        // Open isolated long 2 BTC @ $100; the $100 post escrows into the
        // bucket (collateral already left at place time, so it starts at 0).
        let mut a = Account::new(AccountId([1; 32]));
        a.apply_fill(
            Side::Bid,
            true,
            px(100),
            2 * QTY_SCALE,
            BTC_USD,
            None,
            usd(100),
            true,
        )
        .unwrap();
        assert_eq!(a.isolated_margin[&BTC_USD], usd(100));
        assert_eq!(a.collateral, 0);

        // Close half at −$30: proportional release 50, then settle −30.
        a.apply_fill(Side::Ask, true, px(70), QTY_SCALE, BTC_USD, None, 0, false)
            .unwrap();
        assert_eq!(a.isolated_margin[&BTC_USD], usd(50));
        assert_eq!(a.collateral, usd(20));

        // Close the rest at −$40: release the whole remaining bucket.
        a.apply_fill(Side::Ask, true, px(60), QTY_SCALE, BTC_USD, None, 0, false)
            .unwrap();
        assert_eq!(a.isolated_margin[&BTC_USD], 0);
        assert_eq!(a.collateral, usd(30));
        assert!(a.positions.is_empty());

        // Blow-through: loss exceeds the bucket. Bucket stops at 0,
        // collateral goes negative — the state-level shortfall loop
        // (operp-exec) clamps it and debits insurance by exactly the hole.
        let mut b = Account::new(AccountId([2; 32]));
        b.apply_fill(
            Side::Bid,
            true,
            px(100),
            QTY_SCALE,
            BTC_USD,
            None,
            usd(100),
            true,
        )
        .unwrap();
        b.apply_fill(Side::Ask, true, px(-50), QTY_SCALE, BTC_USD, None, 0, false)
            .unwrap();
        assert_eq!(b.isolated_margin[&BTC_USD], 0);
        assert_eq!(b.collateral, usd(-50));
        assert!(b.positions.is_empty());
    }
}
