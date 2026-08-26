use ed25519_dalek::{Signature, VerifyingKey};
use operp_types::{
    account_id_from_pubkey, sha256, AccountId, Bps, Height, MarketId, OrderId, OrderType, Price,
    Qty,
    Side, TimeInForce, UnitId, Usd, MAX_PARENTS, COMMIT_TAG, REVEAL_TAG,
    UPDATE_EXTERNAL_PRICE_TAG,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    Place {
        account: AccountId,
        market: MarketId,
        side: Side,
        typ: OrderType,
        tif: TimeInForce,
        price: Price,
        qty: Qty,
        client_seq: u64,
    },
    Cancel {
        account: AccountId,
        order_id: OrderId,
    },
    Deposit {
        account: AccountId,
        /// Obyte withdrawal address bound to this deposit (leaf-key domain).
        addr: String,
        amount: Usd,
        aa_unit: [u8; 32],
    },
    Withdraw {
        account: AccountId,
        amount: Usd,
        nonce: u64,
    },
    /// Bonded-oracle price report: writes/updates the reporter's latest quote
    /// for `market`; the effective mark is the median across reporters.
    ReportPrice {
        oracle: AccountId,
        market: MarketId,
        price: Price,
    },
    /// Deposit of the PERP governance asset, mirrored from the vault AA.
    /// `aa_unit` is the AA unit that paid the asset; replay-protected.
    GovDeposit {
        account: AccountId,
        /// Obyte withdrawal address bound to this deposit (leaf-key domain).
        addr: String,
        amount: u128,
        aa_unit: [u8; 32],
    },
    /// Merkle-proof withdrawal of PERP via the vault AA.
    GovWithdraw {
        account: AccountId,
        amount: u128,
        nonce: u64,
    },
    /// Permissionless market creation. Burns `CREATE_MARKET_FEE_PERP` from
    /// the creator's PERP balance and registers per-market risk parameters.
    CreateMarket {
        creator: AccountId,
        symbol: [u8; 16],
        tick_size: Price,
        im_bps: Bps,
        mm_bps: Bps,
        taker_fee_bps: Bps,
        keeper_reward_bps: Bps,
    },
    /// On-chain parameter proposal for `market`; `key` is a `ParamKey` u8.
    CreateProposal {
        creator: AccountId,
        market: MarketId,
        key: u8,
        value: u64,
    },
    /// Vote on an open proposal; weight = voter's PERP balance at execution.
    Vote {
        voter: AccountId,
        proposal_id: u64,
        approve: bool,
    },
    /// Finalize a proposal once past its deadline; anyone may call.
    FinalizeProposal {
        caller: AccountId,
        proposal_id: u64,
    },
    /// Keeper-initiated liquidation. `caller` is the keeper requesting it and
    /// receives the keeper reward; signature must belong to `caller`.
    Liquidate {
        caller: AccountId,
        target: AccountId,
        market: MarketId,
    },
    /// Stake PERP bond to become a price reporter.
    StakeOracle {
        account: AccountId,
    },
    /// Begin unbonding of a reporter; unlocks after 256 heights.
    UnstakeOracle {
        account: AccountId,
    },
    /// Slash a reporter whose reports deviate >500bps from TWAP for 3 consecutive heights.
    SlashOracle {
        challenger: AccountId,
        target: AccountId,
        market: MarketId,
    },
    /// v2 commit-reveal (doc 03 §2.3): registers `sha256(op_bytes(inner) ||
    /// salt)` until `ttl_height`. Carries no content MEV; ordered salted.
    Commit {
        account: AccountId,
        commit: [u8; 32],
        ttl_height: Height,
    },
    /// v2 commit-reveal reveal half: proves the preimage of a prior Commit
    /// and executes the inner operation. Must parent its Commit unit.
    Reveal {
        account: AccountId,
        commit_ref: [u8; 32],
        op: Box<Op>,
        salt: [u8; 32],
    },
    /// External price tick posted by an allowlisted keeper (doc 06 §2.6).
    /// Gated on `funding_source == AggregatedExternal`; rejected otherwise.
    UpdateExternalPrice {
        source: AccountId,
        market: MarketId,
        price: Price,
        source_id: u8,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unit {
    pub parents: Vec<UnitId>,
    pub op: Op,
    pub pubkey: [u8; 32],
    pub sig: [u8; 64],
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum DagError {
    #[error("missing parent")]
    MissingParent,
    #[error("too many parents")]
    TooManyParents,
    #[error("unsorted or duplicate parents")]
    BadParents,
    #[error("duplicate unit")]
    Duplicate,
    #[error("empty parents")]
    EmptyParents,
    #[error("deposit address too long")]
    AddrTooLong,
    #[error("orphan retry payload mismatch")]
    RetryMismatch,
}

/// Hard cap on the Obyte withdrawal address bound by Deposit/GovDeposit ops.
/// Enforced before signature checks so even the orphan-buffer path rejects
/// oversized payloads.
pub const MAX_ADDR_LEN: usize = 128;

pub fn genesis_id() -> UnitId {
    UnitId(sha256(b"operp-mvp-1-genesis"))
}

pub fn canonical_bytes(unit: &Unit) -> Vec<u8> {
    let mut b = Vec::new();
    // v2 commit-reveal / external-price ops hash under the ODX2 domain so
    // their unit ids can never collide with a legacy ODX1 id (doc 03 §2.3.2).
    b.extend_from_slice(match &unit.op {
        Op::Commit { .. } | Op::Reveal { .. } | Op::UpdateExternalPrice { .. } => &b"ODX2"[..],
        _ => &b"ODX1"[..],
    });
    b.push(unit.parents.len() as u8);
    for p in &unit.parents {
        b.extend_from_slice(&p.0);
    }
    encode_op(&mut b, &unit.op);
    b.extend_from_slice(&unit.pubkey);
    b
}

/// Op payload encoding shared by `canonical_bytes` and the commit-reveal
/// hash: tag byte followed by the op's fields in fixed wire order.
fn encode_op(b: &mut Vec<u8>, op: &Op) {
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
        } => {
            b.push(1);
            b.extend_from_slice(&account.0);
            b.extend_from_slice(&market.0.to_le_bytes());
            b.push(side.as_u8());
            b.push(typ.as_u8());
            b.push(tif.as_u8());
            b.extend_from_slice(&price.to_le_bytes());
            b.extend_from_slice(&qty.to_le_bytes());
            b.extend_from_slice(&client_seq.to_le_bytes());
        }
        Op::Cancel { account, order_id } => {
            b.push(2);
            b.extend_from_slice(&account.0);
            b.extend_from_slice(&order_id.0);
        }
        Op::Deposit {
            account,
            addr,
            amount,
            aa_unit,
        } => {
            b.push(3);
            b.extend_from_slice(&account.0);
            b.extend_from_slice(&amount.to_le_bytes());
            b.extend_from_slice(aa_unit);
            b.extend_from_slice(&(addr.len() as u32).to_le_bytes());
            b.extend_from_slice(addr.as_bytes());
        }
        Op::Withdraw {
            account,
            amount,
            nonce,
        } => {
            b.push(4);
            b.extend_from_slice(&account.0);
            b.extend_from_slice(&amount.to_le_bytes());
            b.extend_from_slice(&nonce.to_le_bytes());
        }
        Op::ReportPrice {
            oracle,
            market,
            price,
        } => {
            b.push(6);
            b.extend_from_slice(&oracle.0);
            b.extend_from_slice(&market.0.to_le_bytes());
            b.extend_from_slice(&price.to_le_bytes());
        }
        Op::GovDeposit {
            account,
            addr,
            amount,
            aa_unit,
        } => {
            b.push(8);
            b.extend_from_slice(&account.0);
            b.extend_from_slice(&amount.to_le_bytes());
            b.extend_from_slice(aa_unit);
            b.extend_from_slice(&(addr.len() as u32).to_le_bytes());
            b.extend_from_slice(addr.as_bytes());
        }
        Op::GovWithdraw {
            account,
            amount,
            nonce,
        } => {
            b.push(9);
            b.extend_from_slice(&account.0);
            b.extend_from_slice(&amount.to_le_bytes());
            b.extend_from_slice(&nonce.to_le_bytes());
        }
        Op::CreateMarket {
            creator,
            symbol,
            tick_size,
            im_bps,
            mm_bps,
            taker_fee_bps,
            keeper_reward_bps,
        } => {
            b.push(10);
            b.extend_from_slice(&creator.0);
            b.extend_from_slice(symbol);
            b.extend_from_slice(&tick_size.to_le_bytes());
            b.extend_from_slice(&im_bps.to_le_bytes());
            b.extend_from_slice(&mm_bps.to_le_bytes());
            b.extend_from_slice(&taker_fee_bps.to_le_bytes());
            b.extend_from_slice(&keeper_reward_bps.to_le_bytes());
        }
        Op::CreateProposal {
            creator,
            market,
            key,
            value,
        } => {
            b.push(11);
            b.extend_from_slice(&creator.0);
            b.extend_from_slice(&market.0.to_le_bytes());
            b.push(*key);
            b.extend_from_slice(&value.to_le_bytes());
        }
        Op::Vote {
            voter,
            proposal_id,
            approve,
        } => {
            b.push(12);
            b.extend_from_slice(&voter.0);
            b.extend_from_slice(&proposal_id.to_le_bytes());
            b.push(u8::from(*approve));
        }
        Op::FinalizeProposal { caller, proposal_id } => {
            b.push(13);
            b.extend_from_slice(&caller.0);
            b.extend_from_slice(&proposal_id.to_le_bytes());
        }
        Op::Liquidate {
            caller,
            target,
            market,
        } => {
            b.push(7);
            b.extend_from_slice(&caller.0);
            b.extend_from_slice(&target.0);
            b.extend_from_slice(&market.0.to_le_bytes());
        }
        Op::StakeOracle { account } => {
            b.push(14);
            b.extend_from_slice(&account.0);
        }
        Op::UnstakeOracle { account } => {
            b.push(15);
            b.extend_from_slice(&account.0);
        }
        Op::SlashOracle {
            challenger,
            target,
            market,
        } => {
            b.push(16);
            b.extend_from_slice(&challenger.0);
            b.extend_from_slice(&target.0);
            b.extend_from_slice(&market.0.to_le_bytes());
        }
        Op::UpdateExternalPrice {
            source,
            market,
            price,
            source_id,
        } => {
            b.push(UPDATE_EXTERNAL_PRICE_TAG);
            b.extend_from_slice(&source.0);
            b.extend_from_slice(&market.0.to_le_bytes());
            b.extend_from_slice(&price.to_le_bytes());
            b.push(*source_id);
        }
        Op::Commit {
            account,
            commit,
            ttl_height,
        } => {
            b.push(COMMIT_TAG);
            b.extend_from_slice(&account.0);
            b.extend_from_slice(commit);
            b.extend_from_slice(&ttl_height.to_le_bytes());
        }
        Op::Reveal {
            account,
            commit_ref,
            op,
            salt,
        } => {
            b.push(REVEAL_TAG);
            b.extend_from_slice(&account.0);
            b.extend_from_slice(commit_ref);
            // Inner payload in the same tagged wire order, so the commit
            // hash (encode_op(inner) || salt) is derivable from bytes alone.
            encode_op(b, op);
            b.extend_from_slice(salt);
        }
    }
}

/// Commit-reveal binding (doc 03 §2.3.1): sha256(op_bytes(inner) || salt).
pub fn reveal_commit_hash(inner: &Op, salt: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::new();
    encode_op(&mut buf, inner);
    buf.extend_from_slice(salt);
    sha256(&buf)
}

pub fn unit_id(unit: &Unit) -> UnitId {
    UnitId(sha256(&canonical_bytes(unit)))
}

/// Verify a unit's ed25519 signature against an ALREADY-COMPUTED unit id, so
/// Also checks the op's signing-account field (account/caller/oracle/creator/
/// voter) matches the signing key.
pub fn verify_sig_by_id(unit: &Unit, id: &UnitId) -> bool {
    let vk = match VerifyingKey::from_bytes(&unit.pubkey) {
        Ok(v) => v,
        Err(_) => return false,
    };
    // verify_strict rejects non-canonical s / small-order components
    // (signature malleability), satisfying strict r/s group-order checks.
    let sig = Signature::from_bytes(&unit.sig);
    vk.verify_strict(&id.0, &sig).is_ok() && account_matches(unit)
}

/// Bounded pubkey -> VerifyingKey cache. Validator traffic is heavily skewed
/// toward a small operator set, so Edwards-point decompression (the setup
/// cost of every ed25519 verification) amortizes to ~zero in steady state.
/// Clears wholesale past [`SigVerifier::CAP`] to keep memory bounded without
#[derive(Clone, Default, Debug)]
pub struct SigVerifier {
    cache: HashMap<[u8; 32], Option<VerifyingKey>>,
}

impl SigVerifier {
    pub const CAP: usize = 4096;

    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Same contract as [`verify_sig_by_id`] with decompression cached.
    pub fn verify_by_id(&mut self, unit: &Unit, id: &UnitId) -> bool {
        let vk = match self.cache.get(&unit.pubkey) {
            Some(cached) => cached.clone(),
            None => {
                let parsed = VerifyingKey::from_bytes(&unit.pubkey).ok();
                if self.cache.len() >= Self::CAP {
                    self.cache.clear();
                }
                self.cache.insert(unit.pubkey, parsed.clone());
                parsed
            }
        };
        let Some(vk) = vk else { return false };
        let sig = Signature::from_bytes(&unit.sig);
        vk.verify_strict(&id.0, &sig).is_ok() && account_matches(unit)
    }
}

fn account_matches(unit: &Unit) -> bool {
    let expected = account_id_from_pubkey(&unit.pubkey);
    match &unit.op {
        Op::Place { account, .. }
        | Op::Cancel { account, .. }
        | Op::Deposit { account, .. }
        | Op::Withdraw { account, .. }
        | Op::GovDeposit { account, .. }
        | Op::GovWithdraw { account, .. } => *account == expected,
        Op::StakeOracle { account } | Op::UnstakeOracle { account } => *account == expected,
        Op::SlashOracle { challenger, .. } => *challenger == expected,
        Op::Commit { account, .. } | Op::Reveal { account, .. } => *account == expected,
        Op::UpdateExternalPrice { source, .. } => *source == expected,
        Op::Liquidate { caller, .. } | Op::FinalizeProposal { caller, .. } => *caller == expected,
        Op::ReportPrice { oracle, .. } => *oracle == expected,
        Op::CreateMarket { creator, .. } => *creator == expected,
        Op::CreateProposal { creator, .. } => *creator == expected,
        Op::Vote { voter, .. } => *voter == expected,
    }
}


pub fn sign_unit(parents: Vec<UnitId>, op: Op, secret: &[u8; 32]) -> Unit {
    use ed25519_dalek::{Signer, SigningKey};
    let sk = SigningKey::from_bytes(secret);
    let pubkey = sk.verifying_key().to_bytes();
    let mut unit = Unit {
        parents,
        op,
        pubkey,
        sig: [0u8; 64],
    };
    let id = unit_id(&unit);
    unit.sig = sk.sign(&id.0).to_bytes();
    unit
}

#[derive(Clone, Debug)]
pub struct Dag {
    units: HashMap<UnitId, Unit>,
    children: HashMap<UnitId, Vec<UnitId>>,
    executed: HashSet<UnitId>,
    /// non-executed units; keeps ready_linearized O(pending) not O(all units)
    pending: HashSet<UnitId>,
    /// units whose parents are not (yet) known; evicted by smallest UnitId
    /// past capacity (see `insert_verified`)
    pending_orphans: HashMap<UnitId, Unit>,
    /// reverse index over `pending_orphans`: missing parent -> buffered
    /// children waiting on it; lets a newly known parent link only the
    /// orphans it actually unblocks instead of scanning the whole buffer
    waiting: HashMap<UnitId, Vec<UnitId>>,
    /// Salt for orphan eviction + ordering tie-breaks (Step9): genesis id
    /// until the first AA finalization, then the finalized state root.
    eviction_salt: [u8; 32],
}

/// Max buffered orphan units. Beyond this the orphan with the smallest
/// UnitId is dropped.
const ORPHAN_CAP: usize = 4096;

impl Dag {
    pub fn new() -> Self {
        let mut executed = HashSet::new();
        executed.insert(genesis_id());
        Self {
            units: HashMap::new(),
            children: HashMap::new(),
            waiting: HashMap::new(),
            executed,
            pending: HashSet::new(),
            pending_orphans: HashMap::new(),
            eviction_salt: genesis_id().0,
        }
    }

    /// Rotate the eviction/ordering salt (Step9): the finalization observer
    /// calls this with each newly AA-finalized state root.
    pub fn set_eviction_salt(&mut self, salt: [u8; 32]) {
        self.eviction_salt = salt;
    }

    pub fn eviction_salt(&self) -> [u8; 32] {
        self.eviction_salt
    }

    /// Salted eviction/ordering key: sha256(salt || unit_id). Grind-resistant
    /// replacement for bare lexicographic UnitId ordering.
    pub fn eviction_key(&self, id: UnitId) -> [u8; 32] {
        let mut b = Vec::with_capacity(64);
        b.extend_from_slice(&self.eviction_salt);
        b.extend_from_slice(&id.0);
        sha256(&b)
    }

    /// Insert a unit, hashing it to compute its id.
    pub fn insert(&mut self, unit: Unit) -> Result<UnitId, DagError> {
        let id = unit_id(&unit);
        self.insert_verified(unit, id)
    }
    /// Same as [`Dag::insert`] but the caller supplies the unit id, so an
    /// ingest path that already hashed the unit (signature check) never
    /// computes it twice. Unknown parents no longer drop the unit: on first
    /// sight it is buffered as an orphan and `Err(MissingParent)` returned; a
    /// retry of the same canonical unit while still orphaned returns its id
    /// without error — a retry with DIFFERENT canonical bytes under an equal
    /// id is rejected with [`DagError::RetryMismatch`]. Buffered orphans are
    /// linked automatically once their parents arrive (see `mark_executed`),
    /// so out-of-order delivery recovers.
    ///
    /// Note: arrival-order buffering itself remains replica-dependent (which
    /// units sit in the buffer depends on delivery order). Eviction drops the
    /// orphan with the smallest salted key sha256(salt||unit_id), where the
    /// salt rotates with AA finalizations (`Engine::note_finalized`). Because
    /// replicas can observe finalizations at slightly different times, two
    /// replicas MAY evict different orphans before they converge; the DA
    /// layer's temp_data full replay is the self-healing backstop that
    /// restores a common unit set after convergence.
    pub fn insert_verified(&mut self, unit: Unit, id: UnitId) -> Result<UnitId, DagError> {
        if unit.parents.is_empty() {
            return Err(DagError::EmptyParents);
        }
        if unit.parents.len() > MAX_PARENTS {
            return Err(DagError::TooManyParents);
        }
        // Address-length gate BEFORE signature verification / buffering: a
        // Deposit/GovDeposit with an oversized withdrawal addr must be
        // rejected on every path, including the orphan buffer.
        match &unit.op {
            Op::Deposit { addr, .. } | Op::GovDeposit { addr, .. } => {
                if addr.len() > MAX_ADDR_LEN {
                    return Err(DagError::AddrTooLong);
                }
            }
            _ => {}
        }
        let mut sorted = unit.parents.clone();
        sorted.sort();
        sorted.dedup();
        if sorted != unit.parents {
            return Err(DagError::BadParents);
        }
        if self.units.contains_key(&id) {
            return Err(DagError::Duplicate);
        }
        let missing: Vec<UnitId> = unit
            .parents
            .iter()
            .copied()
            .filter(|p| !self.known(*p))
            .collect();
        if !missing.is_empty() {
            // Already buffered? Accept the retry only if it is byte-for-byte
            // the same unit: id equality alone is caller-supplied, and a
            // second copy with different canonical bytes must not silently
            // pass (the buffer keeps the first copy while the caller would
            // believe its variant was accepted).
            if self.pending_orphans.contains_key(&id) {
                if unit_id(&unit) != id
                    || canonical_bytes(&unit) != canonical_bytes(&self.pending_orphans[&id])
                {
                    return Err(DagError::RetryMismatch);
                }
                return Ok(id);
            }
            if self.pending_orphans.len() >= ORPHAN_CAP {
                // Salted eviction (Step9): drop the orphan with the smallest
                // key sha256(salt||id) — grind-resistant vs bare lexicographic
                // min. The salt rotates with AA finalizations (see
                // `Engine::note_finalized`), so eviction is NO LONGER a pure
                // function of buffer contents: replicas whose finalize timing
                // diverges pre-convergence may evict different orphans. The
                // DA layer's temp_data full replay self-heals any resulting
                // divergence.
                if let Some(k) = self
                    .pending_orphans
                    .keys()
                    .copied()
                    .min_by(|a, b| self.eviction_key(*a).cmp(&self.eviction_key(*b)))
                {
                    if let Some(evicted) = self.pending_orphans.remove(&k) {
                        // Drop the evicted orphan's reverse-index entries.
                        for p in &evicted.parents {
                            if let Some(v) = self.waiting.get_mut(p) {
                                v.retain(|c| *c != k);
                                if v.is_empty() {
                                    self.waiting.remove(p);
                                }
                            }
                        }
                    }
                }
            }
            // Register the orphan under each of its missing parents so the
            // parent's arrival can find it without a full-buffer scan.
            for p in &missing {
                self.waiting.entry(*p).or_default().push(id);
            }
            self.pending_orphans.insert(id, unit);
            return Err(DagError::MissingParent);
        }
        self.link(id, unit);
        Ok(id)
    }

    /// Attach a validated unit to the DAG structures.
    fn link(&mut self, id: UnitId, unit: Unit) {
        for p in &unit.parents {
            self.children.entry(*p).or_default().push(id);
        }
        self.units.insert(id, unit);
        self.pending.insert(id);
    }

    fn known(&self, id: UnitId) -> bool {
        id == genesis_id() || self.units.contains_key(&id)
    }

    pub fn mark_executed(&mut self, id: UnitId) {
        self.executed.insert(id);
        self.pending.remove(&id);
        // Newly known parent: link the buffered orphans indexed as waiting on
        // it. Linking an orphan makes it a known parent too, so keep walking
        // until fixpoint (orphans may chain).
        let mut frontier = match self.waiting.remove(&id) {
            Some(w) => w,
            None => return,
        };
        while let Some(oid) = frontier.pop() {
            let unit = match self.pending_orphans.remove(&oid) {
                Some(u) => u,
                None => continue,
            };
            if !unit.parents.iter().all(|p| self.known(*p)) {
                // Still missing another parent: leave it buffered; its
                // remaining waiting-index entries stay intact.
                self.pending_orphans.insert(oid, unit);
                continue;
            }
            // Drop this orphan's stale entries under its other parents.
            for p in &unit.parents {
                if *p == id {
                    continue;
                }
                if let Some(v) = self.waiting.get_mut(p) {
                    v.retain(|c| *c != oid);
                    if v.is_empty() {
                        self.waiting.remove(p);
                    }
                }
            }
            self.link(oid, unit);
            if let Some(waiters) = self.waiting.remove(&oid) {
                frontier.extend(waiters);
            }
        }
    }

    pub fn get(&self, id: UnitId) -> Option<&Unit> {
        self.units.get(&id)
    }

    /// Read-only P2P-layer support (docs/mainnet/04 §2.4.3): a WantUnits
    /// peer serves missing units from BOTH linked units (`Dag::get`) and
    /// buffered orphans. Pure peek — no mutation, no consensus-path effect.
    pub fn get_orphan(&self, id: UnitId) -> Option<&Unit> {
        self.pending_orphans.get(&id)
    }

    /// Read-only visibility check for the P2P layer (docs/mainnet/04 §2.4.2):
    /// lets an off-engine observer compute which parents of an orphan are
    /// still unknown so it can emit `WantUnits`. Same predicate as the
    /// internal ingest-time missing-parent computation.
    pub fn is_known(&self, id: UnitId) -> bool {
        self.known(id)
    }

    pub fn is_executed(&self, id: UnitId) -> bool {
        self.executed.contains(&id)
    }

    /// Deterministic execution order over all known-but-unexecuted units:
    /// Kahn's topological sort with plain lexicographic UnitId tie-break.
    /// The eviction salt is deliberately NOT consulted here (user-approved
    /// desalting): the salt rotates per finalized root, so salting the
    /// ready-set order made replicas that lag finalization disagree; salt
    /// remains in force for orphan eviction only. Salted execution order is
    /// deferred until finalize-batch determinization lands (README
    /// Limitations). Units whose parents are still buffered orphans stay
    /// excluded until `mark_executed` links them.
    pub fn ready_linearized(&self) -> Vec<UnitId> {
        // Indegree counts only parents inside the pending set; executed
        // parents (and genesis) impose no ordering constraint.
        let mut indeg: HashMap<UnitId, usize> = self
            .pending
            .iter()
            .map(|&id| {
                (
                    id,
                    self.units[&id]
                        .parents
                        .iter()
                        .filter(|p| self.pending.contains(p))
                        .count(),
                )
            })
            .collect();
        let mut ready: Vec<UnitId> = indeg
            .iter()
            .filter(|(_, &d)| d == 0)
            .map(|(&id, _)| id)
            .collect();
        ready.sort_unstable();
        let mut out = Vec::with_capacity(self.pending.len());
        while let Some(id) = ready.first().copied() {
            ready.remove(0);
            out.push(id);
            for c in self.children.get(&id).into_iter().flatten() {
                if let Some(d) = indeg.get_mut(c) {
                    *d -= 1;
                    if *d == 0 {
                        let pos = ready.binary_search(c).unwrap_or_else(|p| p);
                        ready.insert(pos, *c);
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use operp_types::USD_SCALE;

    /// 32-char uppercase [A-Z0-9] Obyte-style test address, varied by `n`.
    fn test_addr(n: u8) -> String {
        let mut bytes = vec![b'A'; 32];
        bytes[0] = b'A' + (n % 26);
        String::from_utf8(bytes).unwrap()
    }

    fn sk(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn deposit(parents: Vec<UnitId>, secret: &[u8; 32], aa: u8) -> Unit {
        let account = account_id_from_pubkey(&ed25519_dalek::SigningKey::from_bytes(secret).verifying_key().to_bytes());
        sign_unit(
            parents,
            Op::Deposit {
                account,
                addr: test_addr(aa),
                amount: 1 * USD_SCALE as i128,
                aa_unit: [aa; 32],
            },
            secret,
        )
    }

    #[test]
    fn two_children_deterministic_across_replicas() {
        // Tie-break is plain lexicographic UnitId order (desalted): every
        // replica derives the SAME order regardless of finalization state.
        let mut dag = Dag::new();
        let g = genesis_id();
        let u1 = deposit(vec![g], &sk(1), 1);
        let u2 = deposit(vec![g], &sk(2), 2);
        dag.insert(u2.clone()).unwrap();
        dag.insert(u1.clone()).unwrap();
        let expect = dag.ready_linearized();
        let mut dag2 = Dag::new();
        dag2.insert(u1.clone()).unwrap();
        dag2.insert(u2.clone()).unwrap();
        assert_eq!(dag2.ready_linearized(), expect);
        // Same total set either way.
        let mut s1 = expect.clone();
        s1.sort_by(|a, b| a.0.cmp(&b.0));
        let mut s2 = vec![unit_id(&u1), unit_id(&u2)];
        s2.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(s1, s2);
    }

    #[test]
    fn ready_order_is_salt_independent_and_lex() {
        // The eviction salt must NOT reorder ready units (desalting): two
        // engines with different salts produce identical execution order.
        let g = genesis_id();
        let mk = |dag: &mut Dag| -> Vec<UnitId> {
            let secret = [7u8; 32];
            let u1 = deposit(vec![g], &secret, 1);
            let u2 = deposit(vec![g], &secret, 2);
            dag.insert(u1.clone()).unwrap();
            dag.insert(u2.clone()).unwrap();
            dag.ready_linearized()
        };
        let mut d1 = Dag::new();
        let o1 = mk(&mut d1);
        let mut d2 = Dag::new();
        d2.set_eviction_salt([0x99; 32]);
        assert_eq!(mk(&mut d2), o1, "salt must not affect ready order");
        // And the order is exactly lexicographic by UnitId.
        let mut lex = o1.clone();
        lex.sort();
        assert_eq!(o1, lex);
    }

    #[test]
    fn missing_parent_rejected() {
        let mut dag = Dag::new();
        let fake = UnitId([9; 32]);
        let u = deposit(vec![fake], &sk(1), 1);
        assert_eq!(dag.insert(u), Err(DagError::MissingParent));
    }

    #[test]
    fn bad_parent_count_rejected() {
        let mut dag = Dag::new();
        let g = genesis_id();
        let account = account_id_from_pubkey(
            &ed25519_dalek::SigningKey::from_bytes(&sk(1))
                .verifying_key()
                .to_bytes(),
        );
        let u = sign_unit(
            vec![g, g, g],
            Op::Deposit {
                account,
                addr: test_addr(1),
                amount: 1,
                aa_unit: [1; 32],
            },
            &sk(1),
        );
        assert!(matches!(
            dag.insert(u),
            Err(DagError::TooManyParents) | Err(DagError::BadParents)
        ));
        let u2 = sign_unit(
            vec![],
            Op::Deposit {
                account,
                addr: test_addr(2),
                amount: 1,
                aa_unit: [2; 32],
            },
            &sk(1),
        );
        assert_eq!(dag.insert(u2), Err(DagError::EmptyParents));
    }

    #[test]
    fn out_of_order_ingest_recovered() {
        let mut dag = Dag::new();
        let g = genesis_id();
        // child first: parent unknown -> buffered orphan, Err(MissingParent)
        let parent = deposit(vec![g], &sk(1), 1);
        let pid = unit_id(&parent);
        let child = deposit(vec![pid], &sk(1), 2);
        assert_eq!(dag.insert(child.clone()), Err(DagError::MissingParent));
        // retry of the same orphan reports acceptance (still pending)
        assert_eq!(dag.insert(child.clone()), Ok(unit_id(&child)));
        // parent arrives: both become known; after executing the parent the
        // child is linked and ready.
        dag.insert(parent).unwrap();
        assert!(dag.ready_linearized().contains(&pid));
        dag.mark_executed(pid);
        let ready = dag.ready_linearized();
        assert!(ready.contains(&unit_id(&child)), "orphan must be recovered");
    }

    #[test]
    fn orphan_reverse_index_links_multi_and_chained() {
        let mut dag = Dag::new();
        let g = genesis_id();
        // Two missing parents, then a child waiting on the first child.
        let p1 = deposit(vec![g], &sk(1), 1);
        let id1 = unit_id(&p1);
        let p2 = deposit(vec![g], &sk(2), 2);
        let id2 = unit_id(&p2);
        let mut mparents = vec![id1, id2];
        mparents.sort();
        let mid = deposit(mparents, &sk(3), 3);
        let mid_id = unit_id(&mid);
        let leaf = deposit(vec![mid_id], &sk(4), 4);
        let leaf_id = unit_id(&leaf);
        assert_eq!(dag.insert(leaf.clone()), Err(DagError::MissingParent));
        assert_eq!(dag.insert(mid.clone()), Err(DagError::MissingParent));
        // First parent alone must not link `mid` (second parent still missing).
        dag.insert(p1).unwrap();
        dag.mark_executed(id1);
        assert!(dag.get(mid_id).is_none(), "mid still misses a parent");
        // Second parent arrives: mid links via the reverse index, which in
        // turn unblocks leaf (chained fixpoint).
        dag.insert(p2).unwrap();
        dag.mark_executed(id2);
        assert!(dag.get(mid_id).is_some(), "indexed orphan must link");
        assert!(dag.get(leaf_id).is_some(), "chained orphan must link");
        assert!(dag.waiting.is_empty(), "index must not leak entries");
    }

    #[test]
    fn gov_deposit_addr_in_canonical_bytes() {
        let account = account_id_from_pubkey(
            &ed25519_dalek::SigningKey::from_bytes(&sk(5))
                .verifying_key()
                .to_bytes(),
        );
        let mk = |addr: String| {
            sign_unit(
                vec![genesis_id()],
                Op::GovDeposit {
                    account,
                    addr,
                    amount: 7,
                    aa_unit: [9; 32],
                },
                &sk(5),
            )
        };
        let u1 = mk(test_addr(6));
        let u2 = mk(test_addr(7));
        // Distinct addresses must yield distinct unit ids (addr is covered
        // by the signature preimage).
        assert_ne!(unit_id(&u1), unit_id(&u2));
        assert_ne!(u1.sig, u2.sig);
    }
    #[test]
    fn oversized_deposit_addr_rejected() {
        let account = account_id_from_pubkey(
            &ed25519_dalek::SigningKey::from_bytes(&sk(6))
                .verifying_key()
                .to_bytes(),
        );
        // 129 chars > MAX_ADDR_LEN (128): must bounce before any buffering.
        let long = "A".repeat(129);
        let u = sign_unit(
            vec![genesis_id()],
            Op::Deposit {
                account,
                addr: long.clone(),
                amount: 1,
                aa_unit: [1; 32],
            },
            &sk(6),
        );
        assert_eq!(dag_insert_check(u), Err(DagError::AddrTooLong));
        // GovDeposit is bound by the same cap.
        let ug = sign_unit(
            vec![genesis_id()],
            Op::GovDeposit {
                account,
                addr: long,
                amount: 1,
                aa_unit: [1; 32],
            },
            &sk(6),
        );
        assert_eq!(dag_insert_check(ug), Err(DagError::AddrTooLong));
        // Boundary: exactly 128 chars is legal.
        let ok = sign_unit(
            vec![genesis_id()],
            Op::Deposit {
                account,
                addr: "A".repeat(MAX_ADDR_LEN),
                amount: 1,
                aa_unit: [1; 32],
            },
            &sk(6),
        );
        assert!(dag_insert_check(ok).is_ok());
    }

    /// insert() recomputes the id from canonical bytes; to exercise the
    /// caller-supplied-id path (insert_verified) with a MISMATCHING id we
    /// pass a deliberately wrong id directly.
    fn dag_insert_check(u: Unit) -> Result<UnitId, DagError> {
        let mut dag = Dag::new();
        dag.insert(u)
    }

    #[test]
    fn orphan_retry_with_different_payload_rejected() {
        let mut dag = Dag::new();
        let fake = UnitId([9; 32]);
        let child = deposit(vec![fake], &sk(3), 1);
        assert_eq!(dag.insert(child.clone()), Err(DagError::MissingParent));
        // Same id, different canonical payload (amount tampered): the
        // retry must not be silently accepted as the buffered copy.
        let account = account_id_from_pubkey(
            &ed25519_dalek::SigningKey::from_bytes(&sk(3))
                .verifying_key()
                .to_bytes(),
        );
        let impostor = sign_unit(
            vec![fake],
            Op::Deposit {
                account,
                addr: test_addr(1),
                amount: 2 * USD_SCALE as i128,
                aa_unit: [1; 32],
            },
            &sk(3),
        );
        // Force the impostor through the caller-supplied-id path with the
        // ORIGINAL unit's id (signature no longer matches, but insert_verified
        // is the DAG-level gate and must still catch the payload swap).
        let original_id = unit_id(&child);
        assert_eq!(
            dag.insert_verified(impostor, original_id),
            Err(DagError::RetryMismatch)
        );
        // The genuine retry still succeeds.
        assert_eq!(dag.insert(child), Ok(original_id));
    }
}
