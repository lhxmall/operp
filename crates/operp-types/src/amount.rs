use crate::{Bps, Price, Qty, Usd, PRICE_SCALE, QTY_SCALE, USD_SCALE};

pub fn notional_usd(qty: Qty, price: Price) -> Usd {
    i128::from(qty) * i128::from(price) / i128::from(PRICE_SCALE) * i128::from(USD_SCALE)
        / i128::from(QTY_SCALE)
}

pub fn signed_notional_usd(qty_signed: i64, price: Price) -> Usd {
    i128::from(qty_signed) * i128::from(price) / i128::from(PRICE_SCALE) * i128::from(USD_SCALE)
        / i128::from(QTY_SCALE)
}

/// Notional for a funding-rate market: `qty` units priced at `usd_per_unit`
/// dollars per 1.0 qty. The encoded book price there is a rate in bps, not a
/// dollar price, so `notional_usd` must not see it.
pub fn funding_notional_usd(qty: Qty, usd_per_unit: u64) -> Usd {
    i128::from(qty) * i128::from(usd_per_unit) * i128::from(USD_SCALE) / i128::from(QTY_SCALE)
}

/// Signed cash for `diff_bps` on `qty_signed` (1.0 qty = `QTY_SCALE`).
/// 1 bp on 1.0 qty pays `usd_per_unit / 10_000` dollars.
pub fn funding_rate_cash(qty_signed: i64, diff_bps: i64, usd_per_unit: u64) -> Usd {
    i128::from(qty_signed) * i128::from(diff_bps) * i128::from(usd_per_unit) * i128::from(USD_SCALE)
        / i128::from(QTY_SCALE)
        / 10_000
}

/// Absolute bps of `value`. IM/MM use abs notional.
pub fn bps(value: Usd, bps: Bps) -> Usd {
    value.saturating_abs() * i128::from(bps) / 10_000
}

pub fn i128_to_le16(v: Usd) -> [u8; 16] {
    v.to_le_bytes()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}
