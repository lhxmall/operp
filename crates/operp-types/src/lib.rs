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
pub const CHAIN_ID: &str = "operp-v2";
pub const ASSERTION_VERSION: u32 = 1;
pub const OBYTE_MERKLE_ROOT_LEN: usize = 44;
pub const INBOX_LAG_SECS: u64 = 600;
pub const WIT_EMPTY_ELEMENT: &str = "empty";
pub const IM_RATE_BPS: u64 = 1000;
pub const MM_RATE_BPS: u64 = 500;
pub const LIQ_RATIO_BPS: u64 = 10_500;
pub const REDUCE_ONLY_RATIO_BPS: u64 = 12_000;
/// Taker fee (bps of notional), routed to the insurance fund so it has
/// income to offset bad-debt absorption and keeper payouts.
pub const TAKER_FEE_BPS: u64 = 5;
/// Per-tick funding cap (bps): longs pay shorts when mark > oracle index,
/// shorts pay longs when mark < oracle. Payment per position =
/// signed_notional(qty, oracle) * clamp(diff_bps, ±FUNDING_CAP_BPS)/10000.
pub const FUNDING_CAP_BPS: i64 = 50;
pub const CHALLENGE_SECS: u64 = 3600;
pub const OBYTE_STABILITY_SECS: u64 = 600;
pub const BATCH_INTERVAL_MS: u64 = 2000;
pub const BATCH_MAX_UNITS: u32 = 512;
pub const MAX_PARENTS: usize = 2;
/// Hard depth cap for the AA-facing hex-domain merkle tree. Mirrors the
/// vault AA's `reduce(..., 18, ...)` and ocore's fatal behavior on arrays
/// longer than the formula's fixed unroll (vendor/ocore/formula/evaluation.js:2374):
/// proofs deeper than this cannot be evaluated on-chain, so proof generation
/// refuses them instead of emitting an unusable path.
pub const MAX_AA_TREE_DEPTH: usize = 16;
// ---------------------------------------------------------------------------
// Mainnet readiness — window & activation gates (Step 0)
// Keep legacy constants unchanged for deterministic replay pre-activation.
// New paths gate on `state.height >= ACTIVATION_HEIGHT`.
pub const REPLAY_WINDOW: u64 = 2048;
pub const REPLAY_WINDOW_LEGACY: u64 = 256;
/// Height at which replay window expands 256→2048. Set high so existing
/// tests (height 0..few hundred) keep legacy behavior; deployment sets to
/// `tip+1000` or `next_finalized+1`.
pub const REPLAY_ACTIVATION_HEIGHT: Height = 1_000_000;
pub const ORDERING_EPOCH_UNITS: u64 = 512;
pub const ORDERING_SALT_DOMAIN: &[u8] = b"operp-order-v1";
pub const ORACLE_SLASH_ACTIVATION_HEIGHT: Height = 0;
pub const FUNDING_TWAP_ACTIVATION_HEIGHT: Height = 0;
pub const STAKE_ORACLE_TAG: u8 = 14;
pub const UNSTAKE_ORACLE_TAG: u8 = 15;
pub const SLASH_ORACLE_TAG: u8 = 16;
pub const ORACLE_UNBOND_HEIGHTS: Height = 256;
pub const ORACLE_TWAP_WINDOW: Height = 256;
pub const ORACLE_TWAP_MAX: Height = 1800;
pub const SLASH_DEVIATION_BPS: u64 = 500;
pub const SLASH_TWAP_STREAK: u64 = 3;
pub const SLASH_REWARD_BPS: u64 = 5000;
pub const FUNDING_TWAP_WINDOW: Height = 256;
pub const FUNDING_TWAP_MIN_SAMPLES: usize = 2;
pub const FUNDING_TWAP_WINDOW_MAX: u64 = 1800;
/// AggregatedExternal freshness: an external feed older than this many
/// heights falls back to the bonded-median TWAP so a liveness failure of
/// external keepers cannot freeze funding (doc 06 §2.6 rule 2).
pub const FUNDING_EXTERNAL_MAX_STALENESS: Height = 32;
// ---------------------------------------------------------------------------
// Commit-reveal ordering v2 (doc 03 §2.3) — additive on top of the salted
// sort (v1). Commits carry no content MEV; reveals must parent their commit
// and re-derive sha256(inner_op_bytes || salt).
pub const COMMIT_REVEAL_ACTIVATION_HEIGHT: Height = 0;
/// Reveal deadline: commits expire COMMIT_TTL_HEIGHTS after creation
/// (~32 s at 2 s/batch), bounding the pending-commit set.
pub const COMMIT_TTL_HEIGHTS: Height = 16;
/// Per-account cap on live (unrevealed, unexpired) commits (doc 03 §2.3.5).
pub const MAX_PENDING_COMMITS_PER_ACCOUNT: usize = 8;
/// canonical_bytes op tags reserved by the v2 additions.
pub const UPDATE_EXTERNAL_PRICE_TAG: u8 = 17;
pub const COMMIT_TAG: u8 = 18;
pub const REVEAL_TAG: u8 = 19;
pub const ESCAPE_STALL_SECS: u64 = 604800;
pub const ESCAPE_STALL_SECS_TESTNET: u64 = 3600;
pub const BOUNCE_FEE_BASE: u64 = 10_000;
pub const SUBMIT_BOND_NET: u64 = 1_000_000_000_000; // 1000 GBYTE
pub const CHALLENGE_BOND_NET: u64 = 1_000_000_000_000;
pub const SUBMIT_BOND_SLASH_HALF: u64 = 500_000_000_000;
pub const RACE_REWARD: u64 = 20_000;
pub const OCCUPANCY_SECS: u64 = 3600; // unlocked candidate replaceable after this
pub const VAULT_AA_ADDRESS: &str = "";
pub const DEPOSIT_EVIDENCE_MAX_BYTES: usize = 1_048_576;
pub const DEPOSIT_VERIFY_ACTIVATION_HEIGHT: Height = 1_000_000;
/// Funding source selector for funding index anchoring.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum FundingSourceKind {
    BondedMedianTwap = 0,
    AggregatedExternal = 1,
}

impl Default for FundingSourceKind {
    fn default() -> Self {
        Self::BondedMedianTwap
    }
}

/// Per-market oracle governance config.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleConfig {
    pub deviation_bps: u64,
    pub twap_window: u64,
    pub slash_reward_bps: u64,
}

impl Default for OracleConfig {
    fn default() -> Self {
        Self {
            deviation_bps: SLASH_DEVIATION_BPS,
            twap_window: ORACLE_TWAP_WINDOW,
            slash_reward_bps: SLASH_REWARD_BPS,
        }
    }
}

pub fn default_oracle_config() -> OracleConfig {
    OracleConfig::default()
}

/// TWAP sample: median observed at a given height/seq. `seq` is the global
/// applied-unit counter at sampling time — the doc-06 time proxy that gives
/// intra-height ordering without wall clocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwapSample {
    pub seq: Seq,
    pub height: Height,
    pub median: Price,
}
/// Per-reporter price history sample for streak detection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSample {
    pub height: Height,
    pub price: Price,
    pub seq: Seq,
}

/// Funding TWAP sample (alias to TwapSample for now).
/// External price sample posted by an allowlisted keeper via
/// `Op::UpdateExternalPrice` (doc 06 §2.3). Empty ring in v1
/// BondedMedianTwap; structure committed in meta_leaf for forward compat.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalSample {
    pub seq: Seq,
    pub height: Height,
    pub price: Price,
    pub source_id: u8,
}
pub type FundingTwapSample = TwapSample;

pub type Price = u64;
pub type Qty = u64;
pub type Usd = i128;
pub type Seq = u64;
pub type Height = u64;
pub type Bps = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MarketId(pub u32);

pub const BTC_USD: MarketId = MarketId(1);
/// Insurance fund vault account (sidechain-internal). Seeded at genesis.
pub const INSURANCE_ACCOUNT: AccountId = AccountId([0u8; 32]);
/// Keeper reward paid from the insurance fund on successful liquidation fill.
pub const KEEPER_REWARD_BPS: u64 = 100;
/// Genesis seed collateral of the insurance fund: 10_000 USD.
pub const INSURANCE_SEED: Usd = 10_000 * USD_SCALE as Usd;

// ---------------------------------------------------------------------------
// PERP governance asset
//
// The real Obyte asset id is unknown until issuance. Everything below keys off
// `PERP_ASSET`; at issuance time the deploy flow writes the actual id into
// this constant and substitutes `PERP_ASSET_PLACEHOLDER` inside the vault AA.
pub type AssetId = [u8; 32];
/// Placeholder until the PERP asset is issued; replaced by the deploy flow.
pub const PERP_ASSET: AssetId = [0u8; 32];
/// Literal marker embedded in `.aa` sources / deploy scripts, swapped for the
/// real asset id string when PERP is issued.
pub const PERP_ASSET_PLACEHOLDER: &str = "PERP_ASSET_ID_HERE";
/// Permissionless market-listing fee, burned from the creator's PERP balance.
pub const CREATE_MARKET_FEE_PERP: u128 = 10_000;
/// Bond staked in PERP by a price reporter; forfeited bonds fund future slashing.
pub const ORACLE_BOND_PERP: u128 = 50_000;
/// Proposal voting window measured in global op-count seqs (deterministic,
/// independent of batch boundaries).
pub const PROPOSAL_DURATION_SEQS: Seq = 20_000;
/// Quorum fraction: yes-votes * DEN >= supply_at_create * NUM.
pub const PROPOSAL_QUORUM_NUM: u128 = 10;
pub const PROPOSAL_QUORUM_DEN: u128 = 100;
/// Minimum PERP balance to open a proposal (threshold check only, not locked).
pub const PROPOSAL_MIN_STAKE_PERP: u128 = 1_000;

/// Which per-market parameter a proposal mutates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ParamKey {
    ImBps,
    MmBps,
    TakerFeeBps,
    KeeperRewardBps,
    Delist,
}

impl ParamKey {
    pub fn as_u8(self) -> u8 {
        match self {
            ParamKey::ImBps => 0,
            ParamKey::MmBps => 1,
            ParamKey::TakerFeeBps => 2,
            ParamKey::KeeperRewardBps => 3,
            ParamKey::Delist => 4,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(ParamKey::ImBps),
            1 => Some(ParamKey::MmBps),
            2 => Some(ParamKey::TakerFeeBps),
            3 => Some(ParamKey::KeeperRewardBps),
            4 => Some(ParamKey::Delist),
            _ => None,
        }
    }
}

/// Per-market risk/fee parameters, mutable via governance proposals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MarketParams {
    /// Right-zero-padded ASCII symbol.
    pub symbol: [u8; 16],
    pub tick_size: Price,
    pub im_bps: Bps,
    pub mm_bps: Bps,
    pub taker_fee_bps: Bps,
    pub keeper_reward_bps: Bps,
    pub delisted: bool,
}

/// Genesis market BTC_USD: same values as the pre-governance globals.
pub fn genesis_params() -> MarketParams {
    let mut symbol = [0u8; 16];
    symbol[..7].copy_from_slice(b"BTC_USD");
    MarketParams {
        symbol,
        tick_size: 1,
        im_bps: IM_RATE_BPS,
        mm_bps: MM_RATE_BPS,
        taker_fee_bps: TAKER_FEE_BPS,
        keeper_reward_bps: KEEPER_REWARD_BPS,
        delisted: false,
    }
}

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

/// Obyte address validity: 32 chars from the base32 alphabet used by
/// `isValidAddress` in vendor/ocore/validation_utils.js (`/^[A-Z2-7]{32}$/`).
/// The trailing chash160 checksum those validators also check is not
/// replicated here — the sidechain only needs the charset/length shape to
/// bind deposit addresses to the AA leaf-key domain.
pub fn valid_obyte_addr(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|c| c.is_ascii_uppercase() || (b'2'..=b'7').contains(&c))
}

pub fn parse_hex64(s: &str) -> Result<[u8; 64], TypesError> {
    let v = hex::decode(s).map_err(|_| TypesError::InvalidHex)?;
    let a: [u8; 64] = v.try_into().map_err(|_| TypesError::InvalidHex)?;
    Ok(a)
}
