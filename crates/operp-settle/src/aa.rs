//! AA behavior specified for later Oscript — not implemented in this MVP pass.
//!
//! ```text
//! states: last_finalized_height, root[height], winner_unit[height], stable_at[height], frozen[height]
//! submit(batch): if height==last_locked+1 && prev matches && batch valid
//!   → record as candidate; do NOT lock root until trigger unit is stable on Obyte
//! on_stable(unit): if unit is a candidate at height H and no winner yet
//!   → winner = first among stable valid candidates by MCI (then obyte_unit)
//!   → lock root[H], stable_at[H]=now (AA timestamp of stability)
//! challenge(height, reason_hash, bond>=10000 bytes):
//!   require winner locked && now < stable_at+3600 → frozen=true
//! withdraw(claim): require height finalized (stable_at+3600 elapsed), !frozen, merkle ok, pay trigger.address
//! ```

use operp_types::{CHALLENGE_SECS, OBYTE_STABILITY_SECS};

pub use operp_types::{CHALLENGE_SECS as AA_CHALLENGE_SECS, OBYTE_STABILITY_SECS as AA_STABILITY_SECS};

pub const BOUNCE_FEES: u64 = 10_000;

#[allow(dead_code)]
const _: () = {
    let _ = CHALLENGE_SECS;
    let _ = OBYTE_STABILITY_SECS;
};

pub struct AaStateNames {
    pub last_finalized_height: &'static str,
    pub root: &'static str,
    pub winner_unit: &'static str,
    pub stable_at: &'static str,
    pub frozen: &'static str,
}

pub const AA_STATE: AaStateNames = AaStateNames {
    last_finalized_height: "last_finalized_height",
    root: "root",
    winner_unit: "winner_unit",
    stable_at: "stable_at",
    frozen: "frozen",
};
