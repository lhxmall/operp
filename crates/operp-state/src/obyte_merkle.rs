//! Obyte-domain merkle tree (matches `vendor/ocore/merkle.js` exactly).
//!
//! Domain: SHA-256 over UTF-8 strings, standard base64 (44 chars).
//! The vault hex tree is a different domain (hex digests); do not mix them.
//! Witness leaves / roots for the rollup dispute predicates live here.

use operp_types::WIT_EMPTY_ELEMENT;
use sha2::{Digest, Sha256};

/// `hash(s)` = base64(sha256(UTF-8 `s`)), same as Node `digest("base64")`.
pub fn hash(s: &str) -> String {
    use base64::Engine as _;
    let digest = Sha256::digest(s.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(digest)
}

/// Merkle root over raw elements. Empty input uses `["empty"]` (ocore
/// `getMerkleRoot` would return undefined; the rollup commits the
/// sentinel root instead).
pub fn root(elements: &[String]) -> String {
    let mut level: Vec<String> = if elements.is_empty() {
        vec![hash(WIT_EMPTY_ELEMENT)]
    } else {
        elements.iter().map(|e| hash(e)).collect()
    };
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let j = if i + 1 < level.len() { i + 1 } else { i };
            next.push(hash(&(level[i].clone() + &level[j])));
            i += 2;
        }
        level = next;
    }
    level.into_iter().next().expect("nonempty")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub root: String,
    pub siblings: Vec<String>,
    pub index: u32,
}

/// Same pairing as ocore `getMerkleProof`.
pub fn proof(elements: &[String], index: usize) -> Proof {
    assert!(index < elements.len(), "invalid index");
    let mut level: Vec<String> = elements.iter().map(|e| hash(e)).collect();
    let mut idx = index;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut over = 0usize;
        let mut i = 0;
        while i < level.len() {
            let j = if i + 1 < level.len() { i + 1 } else { i };
            if i == idx {
                siblings.push(level[j].clone());
                over = i / 2;
            } else if j == idx {
                siblings.push(level[i].clone());
                over = i / 2;
            }
            next.push(hash(&(level[i].clone() + &level[j])));
            i += 2;
        }
        level = next;
        idx = over;
    }
    Proof {
        root: level.into_iter().next().expect("nonempty"),
        siblings,
        index: index as u32,
    }
}

/// Same as ocore `verifyMerkleProof`.
pub fn verify(element: &str, proof: &Proof) -> bool {
    let mut idx = proof.index as usize;
    let mut cur = hash(element);
    for sib in &proof.siblings {
        if idx % 2 == 0 {
            cur = hash(&(cur + sib));
        } else {
            cur = hash(&(sib.clone() + &cur));
        }
        idx /= 2;
    }
    cur == proof.root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_element_fixture_and_roundtrip() {
        // Fixture pinned from node vendor/ocore/merkle.js:
        //   root a b c is IPV+Mb2E/hrd3tKREogAi33zEv//hNefb0HcM22Du/4=
        let els = ["a".to_string(), "b".to_string(), "c".to_string()];
        assert_eq!(root(&els), "IPV+Mb2E/hrd3tKREogAi33zEv//hNefb0HcM22Du/4=");
        for (i, e) in els.iter().enumerate() {
            let p = proof(&els, i);
            assert_eq!(p.root, root(&els));
            assert_eq!(p.index, i as u32);
            assert!(verify(e, &p));
        }
        assert!(!verify("a", &proof(&els, 1)));
        // Empty sentinel.
        assert_eq!(root(&[]), hash(WIT_EMPTY_ELEMENT));
    }
}
