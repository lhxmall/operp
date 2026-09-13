"use strict";
// Local replay of e2e 11a fillHonest2 against fill_math init via ocore evaluation.
const fs = require("fs");
const path = require("path");
const merkle = require("ocore/merkle.js");
const parseOjson = require("ocore/formula/parse_ojson").parse;

const ROLLUP = "RSH52JLCGMTCU4BUHZKG4BIL2XTIYWIP";
const takerH = "b".repeat(64);
const FILL_TAKER_PRE = `acct:${takerH}:0:0:0`;
const META1 = `meta:1:1:1000:500:5:100:0:100`;
const META2 = `meta:2:1:1000:500:5:100:0:100`;
const POS2 = `pos:${takerH}:2:50000000:90000000`;
const DEP_PRE = `acct:${"a".repeat(64)}:1000000:0:0`;
const MAKER_ORD = `ord:${"d".repeat(64)}:1:1:100000000:7:5:${"c".repeat(64)}`;
const BETTER_ORD = `ord:${"e".repeat(63)}f:1:1:90000000:6:9:${"c".repeat(64)}`;
const ZERO_ACCT = "0".repeat(64);
const H3_PRE = [DEP_PRE, FILL_TAKER_PRE, META1, META2, POS2, MAKER_ORD, BETTER_ORD, `acct:${ZERO_ACCT}:0:0:0`].sort();
const H3_PRE_WIT = merkle.getMerkleRoot(H3_PRE);
const IDX = {};
H3_PRE.forEach((l, i) => { IDX[l] = i; });
const fillStr = `f:${"u".repeat(64)}:0:${takerH}:${"c".repeat(64)}:${"d".repeat(64)}:${"e".repeat(64)}:1:100000000:100000000:9:0`;
const pad2 = (arr, tag) => (arr.length >= 2 ? arr : arr.concat([`pad:${tag}:${"z".repeat(16)}`]));
const FILLS1 = pad2([fillStr], "fills1");
const FILLS_ROOT1 = merkle.getMerkleRoot(FILLS1);
const OPS1 = pad2(["x"], "ops1");
const OPS_ROOT1 = merkle.getMerkleRoot(OPS1);
const POST_H = [`acct:${takerH}:-500:0:0`, META1, `pos:${takerH}:1:100000000:100000000`].sort();
const POST_H_WIT = merkle.getMerkleRoot(POST_H);
const TRACE_H = pad2([POST_H_WIT], "traceh");
const TRACE_H_ROOT = merkle.getMerkleRoot(TRACE_H);

console.log("H3_PRE sorted:", JSON.stringify(H3_PRE));
console.log("POST_H sorted:", JSON.stringify(POST_H));
const data = {
  height: 3, pred: "fill_math", k: 0,
  trace_root: TRACE_H_ROOT, fills_root: FILLS_ROOT1, ops_root: OPS_ROOT1,
  fill: fillStr, fill_proof: merkle.getMerkleProof(FILLS1, 0),
  pre_wit: H3_PRE_WIT, post_wit: POST_H_WIT, post_proof: merkle.getMerkleProof(TRACE_H, 0),
  pre_acct: FILL_TAKER_PRE, pre_acct_proof: merkle.getMerkleProof(H3_PRE, IDX[FILL_TAKER_PRE]),
  post_acct: `acct:${takerH}:-500:0:0`,
  post_acct_proof: merkle.getMerkleProof(POST_H, POST_H.indexOf(`acct:${takerH}:-500:0:0`)),
  post_pos: `pos:${takerH}:1:100000000:100000000`,
  post_pos_proof: merkle.getMerkleProof(POST_H, POST_H.indexOf(`pos:${takerH}:1:100000000:100000000`)),
  pre_meta: META1, pre_meta_proof: merkle.getMerkleProof(H3_PRE, IDX[META1]),
  pos_absent: true,
  pleft: BETTER_ORD, pleft_proof: merkle.getMerkleProof(H3_PRE, IDX[BETTER_ORD]),
  pright: POS2, pright_proof: merkle.getMerkleProof(H3_PRE, IDX[POS2]),
  who: "taker",
};
fs.writeFileSync("/tmp/fillhonest2.json", JSON.stringify(data, null, 1));
console.log("wrote /tmp/fillhonest2.json");
console.log("pre_acct_proof root == H3_PRE_WIT:", data.pre_acct_proof.root === H3_PRE_WIT);
console.log("post_acct_proof root == POST_H_WIT:", data.post_acct_proof.root === POST_H_WIT);
console.log("post_proof root == TRACE_H_ROOT:", data.post_proof.root === TRACE_H_ROOT);
console.log("fill_proof root == FILLS_ROOT1:", data.fill_proof.root === FILLS_ROOT1);
console.log("pleft idx:", data.pleft_proof.index, "pright idx:", data.pright_proof.index);
