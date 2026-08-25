"use strict";

// AA complexity probe — docs/mainnet/09-complexity-audit.md Step 0.
// Runs ocore's own validateAADefinition (the exact on-chain gate) against
// agents/operp_vault.aa and prints total complexity/count_ops vs
// MAX_COMPLEXITY=100 / MAX_OPS=2000. Exit 2 when complexity > 85
// (CI gate: keep >=15 headroom).

process.env.devnet = "1";
const path = require("path");
const aaRoot = path.join(__dirname, "..", "..", "vendor", "aa-testkit");
process.env.NODE_PATH = [path.join(aaRoot, "node_modules")].join(path.delimiter);
require("module").Module._initPaths();

const fs = require("fs");
const { parse } = require("ocore/formula/parse_ojson");
const { validateAADefinition } = require("ocore/aa_validation.js");

// Substitute the asset placeholder: validateAADefinition checks payment
// assets are valid base64 ids; the raw source carries the deploy marker.
// 44-char base64 of 32 zero bytes.
const DUMMY_ASSET = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const raw = fs.readFileSync(path.join(__dirname, "..", "agents", "operp_vault.aa"), "utf8");
const src = raw.replace(/PERP_ASSET_ID_HERE/g, DUMMY_ASSET);

parse(src, (err, def) => {
  if (err) {
    console.error("PARSE ERR:", err);
    process.exit(1);
  }
  const readGetterProps = (name, cb) => cb(null, null); // no getters used
  const mci = Number.MAX_SAFE_INTEGER; // post-aa3 semantics per audit doc
  validateAADefinition(def, readGetterProps, mci, (error, result) => {
    if (error) {
      console.error("AA INVALID:", error);
      process.exit(1);
    }
    const { complexity, count_ops } = result;
    console.log("cases:", def[1].messages.cases.length);
    console.log("complexity:", complexity, "/ 100  (gate <=85)");
    console.log("count_ops: ", count_ops, "/ 2000");
    if (complexity > 85) {
      console.error(`FAIL: complexity ${complexity} > 85`);
      process.exit(2);
    }
    console.log(`OK: complexity ${complexity} <= 85`);
    process.exit(0);
  });
});
