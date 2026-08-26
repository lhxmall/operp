//! WantUnits/HaveUnits on-demand orphan sync — the deferred §2.4 of
//! `docs/mainnet/04-salted-orphan-eviction.md`.
//!
//! Pure operator/P2P layer: nothing here enters consensus. Units travel in
//! their existing [`operp_dag::canonical_bytes`] wire format (plus the 64-byte
//! signature canonical bytes deliberately omit); the only new serialization is
//! the small envelope around them. Received units are fed back through the
//! normal `Engine::ingest` path, so signature checks, orphan buffering and the
//! `mark_executed` fixpoint apply unchanged.
//!
//! Protocol constants are exactly those of doc 04 §2.4: fanout 3, per-unit
//! want debounce 500 ms per peer, ≤64 ids per request / ≤64 units per
//! response, at most one response per peer per 100 ms, oversize requests
//! dropped. Reconciliation/anti-entropy (§2.4.4) is explicitly not v1 and is
//! omitted. Transport is operator-supplied (§5 open question 5): this crate
//! produces/consumes typed messages; a real deployment binds them to libp2p
//! gossip topics [`TOPIC_UNITS`] and [`TOPIC_WANT`].

use operp_dag::{canonical_bytes, Dag, Unit};
use operp_types::UnitId;

/// Gossip topic for unit broadcast (`GossipUnit`, already exists operationally).
pub const TOPIC_UNITS: &str = "operp/units/v1";
/// Gossip topic for on-demand want/have exchanges (this module).
pub const TOPIC_WANT: &str = "operp/want/v1";

/// Peers contacted per missing-parent event (doc 04 §2.4.2).
pub const WANT_FANOUT: usize = 3;
/// Per-`UnitId` want rate limit per peer (doc 04 §2.4.2).
pub const WANT_DEBOUNCE_MS: u64 = 500;
/// Max requested ids per WantUnits; larger requests are dropped (doc §2.4.1).
pub const MAX_WANT_IDS: usize = 64;
/// Max units served per HaveUnits response (doc 04 §2.4.3).
pub const MAX_HAVE_UNITS: usize = 64;
/// Min interval between responses to the same peer (doc 04 §2.4.3).
pub const RESPONSE_RATE_LIMIT_MS: u64 = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerId(pub u64);

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum GossipError {
    #[error("malformed message")]
    Malformed,
    #[error("oversize message dropped")]
    Oversize,
}

/// Envelope messages (doc 04 §2.4.1). Unit payloads use the existing
/// canonical-bytes wire format; only the counts/lengths are added framing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GossipMessage {
    /// Request: bounded to [`MAX_WANT_IDS`] ids by the codec and by
    /// [`GossipNode::handle_want`].
    WantUnits { missing: Vec<UnitId> },
    /// Response: bounded to [`MAX_HAVE_UNITS`] units.
    HaveUnits { units: Vec<Unit> },
}

impl GossipMessage {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            GossipMessage::WantUnits { missing } => {
                let mut b = Vec::with_capacity(5 + 32 * missing.len());
                b.push(1);
                b.extend_from_slice(&(missing.len() as u32).to_le_bytes());
                for id in missing {
                    b.extend_from_slice(&id.0);
                }
                b
            }
            GossipMessage::HaveUnits { units } => {
                let mut b = Vec::new();
                b.push(2);
                b.extend_from_slice(&(units.len() as u32).to_le_bytes());
                for u in units {
                    // canonical_bytes + sig: the full unit as verified on
                    // ingest (canonical bytes alone omit the signature).
                    let payload = unit_wire(u);
                    b.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                    b.extend_from_slice(&payload);
                }
                b
            }
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<GossipMessage, GossipError> {
        let mut r = Reader::new(bytes);
        match r.u8()? {
            1 => {
                let n = r.u32()? as usize;
                if n > MAX_WANT_IDS {
                    return Err(GossipError::Oversize);
                }
                let mut missing = Vec::with_capacity(n);
                for _ in 0..n {
                    missing.push(UnitId(r.arr32()?));
                }
                r.finish()?;
                Ok(GossipMessage::WantUnits { missing })
            }
            2 => {
                let n = r.u32()? as usize;
                if n > MAX_HAVE_UNITS {
                    return Err(GossipError::Oversize);
                }
                let mut units = Vec::with_capacity(n);
                for _ in 0..n {
                    let len = r.u32()? as usize;
                    let payload = r.take(len)?;
                    units.push(decode_unit(payload)?);
                }
                r.finish()?;
                Ok(GossipMessage::HaveUnits { units })
            }
            _ => Err(GossipError::Malformed),
        }
    }
}

/// Full wire encoding of one unit: canonical bytes plus the signature that
/// canonical bytes intentionally omit.
fn unit_wire(unit: &Unit) -> Vec<u8> {
    let mut b = canonical_bytes(unit);
    b.extend_from_slice(&unit.sig);
    b
}

/// Inverse of [`unit_wire`]. The canonical section is self-delimiting (every
/// variable field is length-prefixed), so parsing is deterministic.
pub fn decode_unit(bytes: &[u8]) -> Result<Unit, GossipError> {
    let mut r = Reader::new(bytes);
    match r.take(4)? {
        b"ODX1" | b"ODX2" => {}
        _ => return Err(GossipError::Malformed),
    }
    let nparents = r.u8()? as usize;
    let mut parents = Vec::with_capacity(nparents);
    for _ in 0..nparents {
        parents.push(UnitId(r.arr32()?));
    }
    let op = decode_op(&mut r)?;
    let pubkey = r.arr32()?;
    let sig = r.arr::<64>()?;
    r.finish()?;
    Ok(Unit {
        parents,
        op,
        pubkey,
        sig,
    })
}

/// Tagged op decoder mirroring `operp_dag::encode_op`, including the v2
/// commit-reveal / external-price tags (ODX2 domain). Recursive for
/// Reveal's inner payload.
fn decode_op(r: &mut Reader) -> Result<operp_dag::Op, GossipError> {
    use operp_dag::Op;
    use operp_types::{AccountId, MarketId, OrderId, OrderType, Side, TimeInForce};
    Ok(match r.u8()? {
        1 => Op::Place {
            account: AccountId(r.arr32()?),
            market: MarketId(r.u32()?),
            side: Side::from_u8(r.u8()?).ok_or(GossipError::Malformed)?,
            typ: OrderType::from_u8(r.u8()?).ok_or(GossipError::Malformed)?,
            tif: TimeInForce::from_u8(r.u8()?).ok_or(GossipError::Malformed)?,
            price: r.u64()?,
            qty: r.u64()?,
            client_seq: r.u64()?,
        },
        2 => Op::Cancel {
            account: AccountId(r.arr32()?),
            order_id: OrderId(r.arr32()?),
        },
        3 => {
            let account = AccountId(r.arr32()?);
            let amount = r.i128()?;
            let aa_unit = r.arr32()?;
            let addr = r.string(operp_dag::MAX_ADDR_LEN)?;
            Op::Deposit {
                account,
                addr,
                amount,
                aa_unit,
            }
        }
        4 => Op::Withdraw {
            account: AccountId(r.arr32()?),
            amount: r.i128()?,
            nonce: r.u64()?,
        },
        6 => Op::ReportPrice {
            oracle: AccountId(r.arr32()?),
            market: MarketId(r.u32()?),
            price: r.u64()?,
        },
        7 => Op::Liquidate {
            caller: AccountId(r.arr32()?),
            target: AccountId(r.arr32()?),
            market: MarketId(r.u32()?),
        },
        8 => {
            let account = AccountId(r.arr32()?);
            let amount = r.u128()?;
            let aa_unit = r.arr32()?;
            let addr = r.string(operp_dag::MAX_ADDR_LEN)?;
            Op::GovDeposit {
                account,
                addr,
                amount,
                aa_unit,
            }
        }
        9 => Op::GovWithdraw {
            account: AccountId(r.arr32()?),
            amount: r.u128()?,
            nonce: r.u64()?,
        },
        10 => Op::CreateMarket {
            creator: AccountId(r.arr32()?),
            symbol: r.arr::<16>()?,
            tick_size: r.u64()?,
            im_bps: r.u64()?,
            mm_bps: r.u64()?,
            taker_fee_bps: r.u64()?,
            keeper_reward_bps: r.u64()?,
        },
        11 => Op::CreateProposal {
            creator: AccountId(r.arr32()?),
            market: MarketId(r.u32()?),
            key: r.u8()?,
            value: r.u64()?,
        },
        12 => {
            let voter = AccountId(r.arr32()?);
            let proposal_id = r.u64()?;
            let approve = match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(GossipError::Malformed),
            };
            Op::Vote {
                voter,
                proposal_id,
                approve,
            }
        }
        13 => Op::FinalizeProposal {
            caller: AccountId(r.arr32()?),
            proposal_id: r.u64()?,
        },
        14 => Op::StakeOracle {
            account: AccountId(r.arr32()?),
        },
        15 => Op::UnstakeOracle {
            account: AccountId(r.arr32()?),
        },
        16 => Op::SlashOracle {
            challenger: AccountId(r.arr32()?),
            target: AccountId(r.arr32()?),
            market: MarketId(r.u32()?),
        },
        operp_types::UPDATE_EXTERNAL_PRICE_TAG => Op::UpdateExternalPrice {
            source: AccountId(r.arr32()?),
            market: MarketId(r.u32()?),
            price: r.u64()?,
            source_id: r.u8()?,
        },
        operp_types::COMMIT_TAG => Op::Commit {
            account: AccountId(r.arr32()?),
            commit: r.arr32()?,
            ttl_height: r.u64()?,
        },
        operp_types::REVEAL_TAG => {
            let account = AccountId(r.arr32()?);
            let commit_ref = r.arr32()?;
            // Inner payload in the same tagged wire order (encode_op
            // recursion in operp-dag), followed by the 32-byte salt.
            let inner = decode_op(r)?;
            let salt = r.arr::<32>()?;
            Op::Reveal {
                account,
                commit_ref,
                op: Box::new(inner),
                salt,
            }
        }
        _ => return Err(GossipError::Malformed),
    })
}

/// Minimal big-endian-free cursor over fixed-width LE fields.
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], GossipError> {
        if self.b.len() - self.pos < n {
            return Err(GossipError::Malformed);
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn finish(&mut self) -> Result<(), GossipError> {
        if self.pos != self.b.len() {
            Err(GossipError::Malformed)
        } else {
            Ok(())
        }
    }
    fn u8(&mut self) -> Result<u8, GossipError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, GossipError> {
        let mut a = [0u8; 4];
        a.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(a))
    }
    fn u64(&mut self) -> Result<u64, GossipError> {
        let mut a = [0u8; 8];
        a.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(a))
    }
    fn u128(&mut self) -> Result<u128, GossipError> {
        let mut a = [0u8; 16];
        a.copy_from_slice(self.take(16)?);
        Ok(u128::from_le_bytes(a))
    }
    fn i128(&mut self) -> Result<i128, GossipError> {
        let mut a = [0u8; 16];
        a.copy_from_slice(self.take(16)?);
        Ok(i128::from_le_bytes(a))
    }
    fn arr32(&mut self) -> Result<[u8; 32], GossipError> {
        let mut a = [0u8; 32];
        a.copy_from_slice(self.take(32)?);
        Ok(a)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], GossipError> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }
    fn string(&mut self, max: usize) -> Result<String, GossipError> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(GossipError::Oversize);
        }
        String::from_utf8(self.take(len)?.to_vec()).map_err(|_| GossipError::Malformed)
    }
}

/// Doc 04 §2.4.3 serving rule: look a requested id up among linked units AND
/// buffered orphans. Returns an owned clone ready to go on the wire.
pub fn serve_unit(dag: &Dag, id: UnitId) -> Option<Unit> {
    dag.get(id)
        .or_else(|| dag.get_orphan(id))
        .cloned()
}

/// Doc 04 §2.4.2: which of `unit`'s parents does the local DAG still lack?
/// Equivalent to the ingest-time computation inside `insert_verified`; kept
/// off-crate so the P2P layer never mutates or re-derives DAG state.
pub fn missing_parents(unit: &Unit, dag: &Dag) -> Vec<UnitId> {
    unit.parents
        .iter()
        .copied()
        .filter(|p| !dag.is_known(*p))
        .collect()
}

/// Deterministic xorshift64* so want fanout is reproducible in tests; any
/// entropy source works in production via [`GossipNode::reseed`].
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
}

/// Operator-side gossip state machine. Holds no units itself: it decides
/// WHO to ask and WHEN, encodes/decodes envelopes, and enforces both sides'
/// DoS bounds. Delivery is the operator's transport (doc 04 §5 open
/// question 5 defers libp2p/TCP choice).
pub struct GossipNode {
    peers: Vec<PeerId>,
    rng: Rng,
    /// Last ms we sent a want for (peer, unit): debounce map.
    last_want: std::collections::HashMap<(PeerId, UnitId), u64>,
    /// Last ms we answered this peer: response rate limit.
    last_response: std::collections::HashMap<PeerId, u64>,
}

impl GossipNode {
    pub fn new(peers: Vec<PeerId>) -> Self {
        Self::seeded(peers, 0x5EED_0001)
    }

    pub fn seeded(peers: Vec<PeerId>, seed: u64) -> Self {
        Self {
            peers,
            rng: Rng(seed | 1),
            last_want: std::collections::HashMap::new(),
            last_response: std::collections::HashMap::new(),
        }
    }

    pub fn reseed(&mut self, seed: u64) {
        self.rng = Rng(seed | 1);
    }

    /// Doc 04 §2.4.2: call when ingest returns MissingParent with the ids
    /// still unknown ([`missing_parents`]). Emits at most [`WANT_FANOUT`]
    /// WantUnits messages to a random peer subset; each (peer, id) pair is
    /// debounced to one want per [`WANT_DEBOUNCE_MS`].
    pub fn observe_missing(
        &mut self,
        missing: &[UnitId],
        now_ms: u64,
    ) -> Vec<(PeerId, GossipMessage)> {
        if missing.is_empty() || self.peers.is_empty() {
            return Vec::new();
        }
        // Partial Fisher-Yates over a copy of the peer list: distinct random
        // subset without shuffling caller state.
        let mut idx: Vec<usize> = (0..self.peers.len()).collect();
        let fanout = WANT_FANOUT.min(idx.len());
        for i in 0..fanout {
            let j = (self.rng.next() % (idx.len() - i) as u64) as usize + i;
            idx.swap(i, j);
        }
        let mut out = Vec::with_capacity(fanout);
        for &i in &idx[..fanout] {
            let peer = self.peers[i];
            let fresh: Vec<UnitId> = missing
                .iter()
                .copied()
                .filter(|id| {
                    self.last_want
                        .get(&(peer, *id))
                        .map_or(true, |&t| now_ms.saturating_sub(t) >= WANT_DEBOUNCE_MS)
                })
                .collect();
            if fresh.is_empty() {
                continue;
            }
            for id in &fresh {
                self.last_want.insert((peer, *id), now_ms);
            }
            out.push((
                peer,
                GossipMessage::WantUnits {
                    missing: fresh,
                },
            ));
        }
        out
    }

    /// Doc 04 §2.4.3: answer a WantUnits request. Oversize requests (> 64
    /// ids) are dropped; responses to the same peer are rate-limited to one
    /// per [`RESPONSE_RATE_LIMIT_MS`]; at most [`MAX_HAVE_UNITS`] units are
    /// served. Returns `None` when no response may be sent. Serving uses
    /// [`serve_unit`]-equivalent lookups supplied by the operator, keeping
    /// this crate decoupled from any particular engine instance.
    pub fn handle_want(
        &mut self,
        from: PeerId,
        missing: &[UnitId],
        now_ms: u64,
        serve: &dyn Fn(UnitId) -> Option<Unit>,
    ) -> Option<GossipMessage> {
        if missing.len() > MAX_WANT_IDS {
            return None; // drop oversize request
        }
        if self
            .last_response
            .get(&from)
            .map_or(false, |&t| now_ms.saturating_sub(t) < RESPONSE_RATE_LIMIT_MS)
        {
            return None; // rate limited
        }
        let units: Vec<Unit> = missing
            .iter()
            .copied()
            .take(MAX_HAVE_UNITS)
            .filter_map(serve)
            .collect();
        if units.is_empty() {
            return None;
        }
        self.last_response.insert(from, now_ms);
        Some(GossipMessage::HaveUnits { units })
    }

    /// Decode a received HaveUnits into plain units for the normal
    /// `Engine::ingest` path (signature check + orphan fixpoint unchanged).
    pub fn accept_have(&self, msg: &GossipMessage) -> Result<Vec<Unit>, GossipError> {
        match msg {
            GossipMessage::HaveUnits { units } if units.len() <= MAX_HAVE_UNITS => {
                Ok(units.clone())
            }
            GossipMessage::HaveUnits { .. } => Err(GossipError::Oversize),
            GossipMessage::WantUnits { .. } => Err(GossipError::Malformed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use operp_dag::{genesis_id, Op};
    use operp_types::{account_id_from_pubkey, AccountId, MarketId, OrderId};

    fn sk(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    /// Signed unit whose identity field matches its key, as the ingest path
    /// requires (`account_matches`).
    fn signed(parents: Vec<UnitId>, secret: u8) -> Unit {
        let key = sk(secret);
        let account = account_id_from_pubkey(&key.verifying_key().to_bytes());
        let op = Op::Place {
            account,
            market: MarketId(1),
            side: operp_types::Side::Bid,
            typ: operp_types::OrderType::Limit,
            tif: operp_types::TimeInForce::Gtc,
            price: 100,
            qty: 2,
            client_seq: secret as u64,
        };
        operp_dag::sign_unit(parents, op, &[secret; 32])
    }

    fn deposit_unit(parents: Vec<UnitId>, secret: u8, addr: &str) -> Unit {
        let key = sk(secret);
        let account = account_id_from_pubkey(&key.verifying_key().to_bytes());
        let op = Op::Deposit {
            account,
            addr: addr.to_string(),
            amount: 5,
            aa_unit: [7u8; 32],
        };
        operp_dag::sign_unit(parents, op, &[secret; 32])
    }

    #[test]
    fn unit_wire_roundtrip_all_op_variants() {
        let key = sk(9);
        let acct = AccountId(account_id_from_pubkey(&key.verifying_key().to_bytes()).0);
        let g = vec![genesis_id()];
        let ops = vec![
            Op::Place { account: acct, market: MarketId(3), side: operp_types::Side::Ask, typ: operp_types::OrderType::Market, tif: operp_types::TimeInForce::Ioc, price: u64::MAX, qty: 7, client_seq: 42 },
            Op::Cancel { account: acct, order_id: OrderId([1; 32]) },
            Op::Deposit { account: acct, addr: "A".repeat(128), amount: -123456789i128, aa_unit: [2; 32] },
            Op::Withdraw { account: acct, amount: 99i128, nonce: u64::MAX },
            Op::ReportPrice { oracle: acct, market: MarketId(u32::MAX), price: 1 },
            Op::Liquidate { caller: acct, target: AccountId([3; 32]), market: MarketId(2) },
            Op::GovDeposit { account: acct, addr: String::new(), amount: u128::MAX, aa_unit: [4; 32] },
            Op::GovWithdraw { account: acct, amount: u128::MAX, nonce: 5 },
            Op::CreateMarket { creator: acct, symbol: *b"BTC-PERP-0000000", tick_size: 10, im_bps: 100, mm_bps: 50, taker_fee_bps: 5, keeper_reward_bps: 1 },
            Op::CreateProposal { creator: acct, market: MarketId(1), key: 7, value: u64::MAX },
            Op::Vote { voter: acct, proposal_id: 11, approve: true },
            Op::FinalizeProposal { caller: acct, proposal_id: 12 },
            Op::StakeOracle { account: acct },
            Op::UnstakeOracle { account: acct },
            Op::SlashOracle { challenger: acct, target: AccountId([9; 32]), market: MarketId(4) },
            Op::UpdateExternalPrice { source: acct, market: MarketId(1), price: 55, source_id: 2 },
            Op::Commit { account: acct, commit: [0xD; 32], ttl_height: 100 },
            // Nested: Reveal wrapping an inner Place exercises recursion.
            Op::Reveal {
                account: acct,
                commit_ref: [0xE; 32],
                op: Box::new(Op::Place {
                    account: acct,
                    market: MarketId(9),
                    side: operp_types::Side::Bid,
                    typ: operp_types::OrderType::Limit,
                    tif: operp_types::TimeInForce::Gtc,
                    price: 7,
                    qty: 1,
                    client_seq: 3,
                }),
                salt: [0xF; 32],
            },
        ];
        for (i, op) in ops.into_iter().enumerate() {
            let unit = operp_dag::sign_unit(g.clone(), op, &[(i + 1) as u8; 32]);
            assert_eq!(decode_unit(&unit_wire(&unit)).unwrap(), unit, "variant {}", i);
        }
    }

    #[test]
    fn decode_rejects_truncated_and_bad_magic() {
        let unit = signed(vec![genesis_id()], 1);
        let wire = unit_wire(&unit);
        assert_eq!(decode_unit(&wire[..wire.len() - 1]), Err(GossipError::Malformed));
        assert_eq!(decode_unit(&wire[1..]), Err(GossipError::Malformed));
        // Trailing junk after a complete unit is rejected.
        let mut padded = wire.clone();
        padded.push(0);
        assert_eq!(decode_unit(&padded), Err(GossipError::Malformed));
    }

    #[test]
    fn message_roundtrip_and_oversize_bounds() {
        let want = GossipMessage::WantUnits { missing: vec![UnitId([1; 32]), UnitId([2; 32])] };
        assert_eq!(GossipMessage::decode(&want.encode()), Ok(want.clone()));

        let units = vec![signed(vec![genesis_id()], 1), deposit_unit(vec![genesis_id()], 2, "addr-x")];
        let have = GossipMessage::HaveUnits { units };
        assert_eq!(GossipMessage::decode(&have.encode()), Ok(have));

        // > MAX_WANT_IDS ids: dropped at decode.
        let big: Vec<UnitId> = (0..65).map(|i| UnitId([i as u8; 32])).collect();
        let big_msg = GossipMessage::WantUnits { missing: big };
        assert_eq!(GossipMessage::decode(&big_msg.encode()), Err(GossipError::Oversize));
    }

    #[test]
    fn observe_missing_fanout_is_distinct_and_debounced() {
        // Distinctness: 10 peers, fanout caps at 3 distinct contacts.
        let peers: Vec<PeerId> = (0..10).map(PeerId).collect();
        let mut mesh = GossipNode::seeded(peers.clone(), 0xC0FFEE);
        let missing = vec![UnitId([0xAA; 32])];
        let out = mesh.observe_missing(&missing, 1_000);
        assert_eq!(out.len(), WANT_FANOUT.min(peers.len()));
        let asked: std::collections::HashSet<PeerId> = out.iter().map(|(p, _)| *p).collect();
        assert_eq!(asked.len(), WANT_FANOUT);

        // Debounce: with exactly fanout peers every event contacts the same
        // set, so an immediate re-fire must be fully suppressed and a refire
        // past the window allowed.
        let mut node = GossipNode::new(vec![PeerId(1), PeerId(2), PeerId(3)]);
        assert_eq!(node.observe_missing(&missing, 1_000).len(), 3);
        assert!(node.observe_missing(&missing, 1_200).is_empty());
        assert_eq!(
            node.observe_missing(&missing, 1_000 + WANT_DEBOUNCE_MS).len(),
            3
        );

        // Fanout never exceeds the peer count.
        let mut solo = GossipNode::new(vec![PeerId(1)]);
        assert_eq!(solo.observe_missing(&missing, 0).len(), 1);
        assert!(GossipNode::new(vec![]).observe_missing(&missing, 0).is_empty());
    }

    #[test]
    fn handle_want_drops_oversize_and_rate_limits_responses() {
        let mut node = GossipNode::new(vec![PeerId(2)]);
        let big: Vec<UnitId> = (0..=MAX_WANT_IDS).map(|i| UnitId([i as u8; 32])).collect();

        // Rate limit: second response within 100 ms suppressed.
        let u = signed(vec![genesis_id()], 3);
        let one = vec![operp_dag::unit_id(&u)];
        let known = |id: UnitId| -> Option<Unit> { (id == operp_dag::unit_id(&u)).then(|| u.clone()) };
        assert!(node.handle_want(PeerId(1), &one, 1_000, &known).is_some());
        assert!(node.handle_want(PeerId(1), &one, 1_050, &known).is_none());
        assert!(node.handle_want(PeerId(1), &one, 1_000 + RESPONSE_RATE_LIMIT_MS, &known).is_some());

        // A different peer is not throttled by peer 1's budget.
        assert!(node.handle_want(PeerId(5), &one, 1_001, &known).is_some());
    }

    #[test]
    fn serving_covers_linked_units_and_buffered_orphans() {

        let mut dag = Dag::new();
        let parent = deposit_unit(vec![genesis_id()], 4, "p");
        let child = signed(vec![operp_dag::unit_id(&parent)], 5);
        let pid = operp_dag::unit_id(&parent);
        let cid = operp_dag::unit_id(&child);
        dag.insert(child.clone()).unwrap_err(); // buffered orphan
        assert!(dag.get(cid).is_none());
        assert_eq!(serve_unit(&dag, cid), Some(child));
        assert_eq!(serve_unit(&dag, pid), None); // parent unknown here
        dag.insert(parent.clone()).unwrap();
        assert_eq!(serve_unit(&dag, pid), Some(parent));
        // Wire round-trip of the served orphan keeps signature intact.
        let served = serve_unit(&dag, cid).unwrap();
        assert!(operp_dag::verify_sig_by_id(&served, &cid));
        assert_eq!(decode_unit(&unit_wire(&served)).unwrap(), served);
    }

    /// Doc 04 §2.4.5 acceptance shape: replica A receives a child before its
    /// parent, wants the missing parent on demand, and heals through the
    /// normal ingest path — no DAG or consensus change involved.
    #[test]
    fn e2e_out_of_order_child_heals_via_want_have() {


        // Two independent engines (replicas A and B).
        let mut eng_a = operp_exec_like_dag();
        let mut eng_b = operp_exec_like_dag();

        let parent = deposit_unit(vec![genesis_id()], 6, "parent");
        let child = signed(vec![operp_dag::unit_id(&parent)], 7);
        let pid = operp_dag::unit_id(&parent);
        let cid = operp_dag::unit_id(&child);

        // B saw gossip in causal order.
        eng_b.insert(parent.clone()).unwrap();

        // A sees the child first: MissingParent, orphan buffered.
        assert_eq!(
            eng_a.insert_verified(child.clone(), cid),
            Err(operp_dag::DagError::MissingParent)
        );

        // P2P layer on A observes the gap and emits WantUnits to B.
        let missing = missing_parents(&child, &eng_a);
        assert_eq!(missing, vec![pid]);
        let mut gossip_a = GossipNode::new(vec![PeerId(0xB)]);
        let msgs = gossip_a.observe_missing(&missing, 10_000);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].0, PeerId(0xB));

        // Transport hop: encode on A, decode on B, B serves from its DAG
        // (linked units AND buffered orphans) and answers.
        let wire = msgs[0].1.encode();
        let req = GossipMessage::decode(&wire).unwrap();
        let GossipMessage::WantUnits { missing } = req else {
            panic!("want expected");
        };
        let mut gossip_b = GossipNode::new(vec![PeerId(0xA)]);
        let resp = gossip_b
            .handle_want(PeerId(0xA), &missing, 10_000, &|id| serve_unit(&eng_b, id))
            .expect("B must serve the parent");

        // Back to A: HaveUnits decodes and feeds the normal ingest path.
        let units = gossip_a.accept_have(&resp).unwrap();
        assert_eq!(units.len(), 1);
        for u in units {
            eng_a.insert_verified(u.clone(), operp_dag::unit_id(&u)).unwrap();
        }
        // Parent linked; the waiting-index fixpoint pulls the buffered
        // child in when the parent executes.
        assert!(eng_a.get(pid).is_some());
        eng_a.mark_executed(pid);
        // Fixpoint linked the buffered child; it executes on its own turn.
        assert!(eng_a.get(cid).is_some());
        eng_a.mark_executed(cid);
        assert!(eng_a.is_executed(pid));
        assert!(eng_a.is_executed(cid));
    }

    // Minimal stand-in exercising only the Dag surface the P2P layer touches;
    // keeps this crate's tests independent of operp-exec internals.
    fn operp_exec_like_dag() -> Dag {
        Dag::new()
    }
}
