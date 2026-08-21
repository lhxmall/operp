mod amount;
mod ids;
mod order;

pub use amount::{bps, i128_to_le16, notional_usd, sha256, signed_notional_usd};
pub use ids::{account_id_from_pubkey, liq_order_id, order_id, AccountId, OrderId, UnitId};
pub use order::{ExecStatus, OrderType, Side, TimeInForce};

use serde::{Deserialize, Serialize};

pub const PRICE_SCALE: u64 = 100_000_000;
pub const QTY_SCALE: u64 = 100_000_000;
pub const USD_SCALE: u64 = 1_000_000;
pub const CHAIN_ID: &str = "odex-mvp-1";
pub const IM_RATE_BPS: u64 = 1000;
pub const MM_RATE_BPS: u64 = 500;
pub const LIQ_RATIO_BPS: u64 = 10_500;
pub const REDUCE_ONLY_RATIO_BPS: u64 = 12_000;
pub const CHALLENGE_SECS: u64 = 3600;
pub const OBYTE_STABILITY_SECS: u64 = 600;
pub const BATCH_INTERVAL_MS: u64 = 2000;
pub const BATCH_MAX_UNITS: u32 = 512;
pub const MAX_PARENTS: usize = 2;

pub type Price = u64;
pub type Qty = u64;
pub type Usd = i128;
pub type Seq = u64;
pub type Height = u64;
pub type Bps = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MarketId(pub u32);

pub const BTC_USD: MarketId = MarketId(1);

#[derive(Debug, thiserror::Error)]
pub enum TypesError {
    #[error("invalid hex")]
    InvalidHex,
}

pub fn parse_hex32(s: &str) -> Result<[u8; 32], TypesError> {
    let v = hex::decode(s).map_err(|_| TypesError::InvalidHex)?;
    let a: [u8; 32] = v.try_into().map_err(|_| TypesError::InvalidHex)?;
    Ok(a)
}

pub fn parse_hex64(s: &str) -> Result<[u8; 64], TypesError> {
    let v = hex::decode(s).map_err(|_| TypesError::InvalidHex)?;
    let a: [u8; 64] = v.try_into().map_err(|_| TypesError::InvalidHex)?;
    Ok(a)
}
