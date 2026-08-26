"use strict";

// H3 golden vector — canonical batch data hash/length for ONE fixed nested
// object. Must match the Rust side (operp_settle::obyte_hash::get_data_hash
// over get_json_source) on the same input:
//   source      = ocore getJsonSourceString(obj)  (recursively key-sorted minified JSON)
//   data_hash   = hex(sha256(source))
//   data_length = UTF-8 byte length of source
//
// Usage: cd obyte-local && node golden_vector_check.js

const path = require("path");
const crypto = require("crypto");
const aaRoot = path.join(__dirname, "..", "vendor", "aa-testkit");
process.env.NODE_PATH = [path.join(aaRoot, "node_modules"), process.env.NODE_PATH]
  .filter(Boolean)
  .join(path.delimiter);
require("module").Module._initPaths();

const { getJsonSourceString } = require("ocore/string_utils.js");

// Fixed nested object: unsorted keys at two depths, array kept in order,
// every JSON value kind ocore's canonicalizer handles (no empty containers —
// getJsonSourceString rejects those by default).
const obj = {
  zeta: 1,
  alpha: { k2: [1, 2.5, true], k1: "v" },
  mid: false,
  s: "hello",
};

const source = getJsonSourceString(obj);
const dataHash = crypto.createHash("sha256").update(source, "utf8").digest("hex");
const dataLength = Buffer.byteLength(source, "utf8");

console.log("input       :", JSON.stringify(obj));
console.log("source      :", source);
console.log("data_hash   :", dataHash);
console.log("data_length :", dataLength);
