use crate::amount::sha256;
use crate::MarketId;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AccountId(pub [u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OrderId(pub [u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UnitId(pub [u8; 32]);

impl fmt::Debug for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AccountId({})", hex::encode(self.0))
    }
}
impl fmt::Debug for OrderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OrderId({})", hex::encode(self.0))
    }
}
impl fmt::Debug for UnitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UnitId({})", hex::encode(self.0))
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
impl fmt::Display for OrderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
impl fmt::Display for UnitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

pub fn account_id_from_pubkey(pubkey: &[u8; 32]) -> AccountId {
    AccountId(sha256(pubkey))
}

/// OrderId = SHA-256(account || market_le || client_seq_le)
pub fn order_id(account: AccountId, market: MarketId, client_seq: u64) -> OrderId {
    let mut buf = [0u8; 32 + 4 + 8];
    buf[..32].copy_from_slice(&account.0);
    buf[32..36].copy_from_slice(&market.0.to_le_bytes());
    buf[36..44].copy_from_slice(&client_seq.to_le_bytes());
    OrderId(sha256(&buf))
}

pub fn liq_order_id(unit: UnitId) -> OrderId {
    let mut buf = Vec::with_capacity(3 + 32);
    buf.extend_from_slice(b"liq");
    buf.extend_from_slice(&unit.0);
    OrderId(sha256(&buf))
}
