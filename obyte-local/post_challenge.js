"use strict";

// Watcher challenge poster. Broadcasts {challenge:1, height} with
// CHALLENGE_GROSS = 1e12+10000 against the vault AA.
//
// Usage:
//   OPERP_WATCH_MNEMONIC='...' node obyte-local/post_challenge.js \
//     --vault <aa> --height <n> [--hub <url>]
//
// Default hub: 127.0.0.1:6611. Exit 0 prints the unit id; exit 1 on
// bounce/error. --help prints usage and exits 0 (mnemonic not required).

const path = require("path");

function usage() {
  console.log(
    "usage: node obyte-local/post_challenge.js --vault <aa> --height <n> [--hub <url>]\n" +
      "env: OPERP_WATCH_MNEMONIC required (except --help)"
  );
}

function parseArgs(argv) {
  const out = { vault: null, height: null, hub: "127.0.0.1:6611", help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") out.help = true;
    else if (a === "--vault") out.vault = argv[++i];
    else if (a === "--height") out.height = argv[++i];
    else if (a === "--hub") out.hub = argv[++i];
    else {
      console.error("unknown flag:", a);
      usage();
      process.exit(1);
    }
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
if (args.help) {
  usage();
  process.exit(0);
}
if (!args.vault || args.height == null || args.height === "") {
  usage();
  process.exit(1);
}
const height = Number(args.height);
if (!Number.isFinite(height) || height <= 0) {
  console.error("bad --height:", args.height);
  process.exit(1);
}

const mnemonic = process.env.OPERP_WATCH_MNEMONIC;
if (!mnemonic) {
  console.error("OPERP_WATCH_MNEMONIC required");
  process.exit(1);
}

const aaRoot = path.join(__dirname, "..", "vendor", "aa-testkit");
const nm = path.join(aaRoot, "node_modules");
process.env.NODE_PATH = [nm, process.env.NODE_PATH].filter(Boolean).join(path.delimiter);
require("module").Module._initPaths();

process.env.devnet = process.env.devnet || "1";
process.env.mnemonic = mnemonic;

const conf = require("ocore/conf.js");
conf.hub = args.hub;
conf.bLight = true;

const eventBus = require("ocore/event_bus.js");
const headlessWallet = require("headless-obyte");

const AMOUNT = 1e12 + 10000;

function fail(err) {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
}

eventBus.on("headless_wallet_ready", () => {
  const payload = { challenge: 1, height: height };
  const opts = {
    base_outputs: [{ address: args.vault, amount: AMOUNT }],
    messages: [{ app: "data", payload: payload }],
  };
  const done = (err, unit) => {
    if (err) return fail(err);
    const id = (unit && unit.unit) || unit;
    if (!id) return fail("sendMulti returned no unit");
    console.log(id);
    process.exit(0);
  };
  try {
    const ret = headlessWallet.sendMulti(opts, done);
    if (ret && typeof ret.then === "function") {
      ret.then((unit) => done(null, unit), done);
    }
  } catch (e) {
    fail(e);
  }
});
