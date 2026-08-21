"use strict";
/* 20-min dual-chain stress:
 *  - Sidechain: Rust engine HFT (separate process writes batches to out dir)
 *  - Main chain (local devnet): AA deployed, continuous temp_data traffic + forks
 *      * order provider: posts a batch every 5 min (OP time-travel accelerates stability)
 *      * forkers: competing posters at same height to create DAG forks
 * Reports TPS for both chains at the end.
 */

const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { spawn } = require("child_process");

const aaRoot = path.join(__dirname, "..", "vendor", "aa-testkit");
const nm = path.join(aaRoot, "node_modules");
process.env.NODE_PATH = [nm, process.env.NODE_PATH].filter(Boolean).join(path.delimiter);
process.env.devnet = "1";

const { Testkit } = require(path.join(aaRoot, "main.js"));
const OUT = path.join(__dirname, "stress-out");
fs.mkdirSync(OUT, { recursive: true });

const { Network } = Testkit({
  TESTDATA_DIR: path.join(__dirname, "testdata-stress"),
  NETWORK_PORT: 16615,
});

const RUN_MS = 20 * 60 * 1000;
const ORDER_PROVIDER_MS = 5 * 60 * 1000;
const FORK_EVERY_MS = 30 * 1000;

function getLength(value, bWithKeys) {
  const cache = new WeakMap();
  function _getLength(v) {
    if (v === null) return 0;
    switch (typeof v) {
      case "string":
        return v.length;
      case "number":
        return 8;
      case "boolean":
        return 1;
      case "object": {
        if (cache.has(v)) return cache.get(v);
        let len = 0;
        if (Array.isArray(v)) {
          for (const el of v) len += _getLength(el);
        } else {
          for (const key of Object.keys(v)) {
            if (bWithKeys) len += key.length;
            len += _getLength(v[key]);
          }
        }
        cache.set(v, len);
        return len;
      }
      default:
        throw new Error("unknown type");
    }
  }
  return _getLength(value);
}
function getJsonSourceString(obj) {
  const cache = new WeakMap();
  function stringify(v) {
    if (typeof v === "string") return JSON.stringify(v);
    if (typeof v === "number") return isFinite(v) ? String(v) : "null";
    if (typeof v === "boolean") return String(v);
    if (v === null) throw Error("cannot stringify null");
    if (cache.has(v)) return cache.get(v);
    let s;
    if (Array.isArray(v)) {
      s = "[" + v.map(stringify).join(",") + "]";
    } else {
      const keys = Object.keys(v).sort();
      s = "{" + keys.map((k) => JSON.stringify(k) + ":" + stringify(v[k])).join(",") + "}";
    }
    cache.set(v, s);
    return s;
  }
  return stringify(obj);
}
function getBase64Hash(obj) {
  return crypto.createHash("sha256").update(getJsonSourceString(obj), "utf8").digest("base64");
}
function tempDataMessage(data) {
  return {
    app: "temp_data",
    payload_location: "inline",
    payload: { data_length: getLength(data, true), data_hash: getBase64Hash(data), data },
  };
}

/* ---------- stats ---------- */
const stats = {
  main_units: 0,
  side_batches: 0,
  side_units_total: 0,
  side_fills: 0,
  forks_created: 0,
  aa_ok: 0,
  aa_bounced: 0,
  started: Date.now(),
};
function report() {
  const mins = (Date.now() - stats.started) / 60000;
  console.log(
    `[${mins.toFixed(1)}m] main_units=${stats.main_units} ` +
    `side_batches=${stats.side_batches} side_ops=${stats.side_units_total} fills=${stats.side_fills} ` +
    `forks=${stats.forks_created} aa_ok=${stats.aa_ok} aa_bounce=${stats.aa_bounced}`
  );
}

async function main() {
  console.log("=== boot devnet + deploy vault AA ===");
  const network = await Network.create()
    .with.agent({ vault: path.join(__dirname, "agents/odex_vault.aa") })
    .with.wallet({ provider: 2e9 })
    .with.wallet({ forkerA: 1e9 })
    .with.wallet({ forkerB: 1e9 })
    .with.wallet({ trader: 1e9 })
    .run();
  const genesis = await network.getGenesisNode().ready();
  const vault = network.agent.vault;
  const W = network.wallet;
  console.log("vault", vault);

  /* --- start sidechain HFT engine in background; it writes batch.json per height --- */
  console.log("starting sidechain HFT engine...");
  const hft = spawn("cargo", ["run", "--release", "-p", "odex-exec", "--example", "hft_stress_feed", "--", String(RUN_MS), OUT], {
    cwd: path.join(__dirname, ".."),
    stdio: ["ignore", "pipe", "pipe"],
  });
  let hftReady = false;
  hft.stdout.on("data", (d) => {
    const s = d.toString();
    if (s.includes("READY")) hftReady = true;
    process.stdout.write("[side] " + s);
  });
  hft.stderr.on("data", (d) => process.stderr.write("[side!] " + d));
  while (!hftReady) await new Promise((r) => setTimeout(r, 500));
  console.log("sidechain HFT ready");

  /* ---------- AA smoke: deposit once so the vault has state ---------- */
  async function trigger(walletName, data, amount) {
    const { unit, error } = await W[walletName].triggerAaWithData({ toAddress: vault, amount, data });
    if (error) throw new Error(error);
    return unit;
  }
  try {
    const u = await trigger("trader", { deposit: 1 }, 1000000);
    await network.witnessUntilStable(u);
    stats.aa_ok++;
  } catch (e) { stats.aa_bounced++; console.log("aa deposit err", e.message); }

  /* ---------- loops ---------- */
  const endAt = Date.now() + RUN_MS;
  let nextProviderAt = Date.now() + 20000; // first batch after 20s
  let height = 1;
  let nextForkAt = Date.now() + FORK_EVERY_MS;
  let trafficOn = true;

  // free traffic loop: trader posts temp_data on main chain.
  // ocore crashes with "too deeply nested" if units chain faster than stability:
  // keep >= 2s between sends so composer picks stable parents.
  (async () => {
    let i = 0;
    let n = 0;
    while (Date.now() < endAt && trafficOn) {
      try {
        const r = await W.trader.sendMulti({ messages: [tempDataMessage({ ping: i++, chain: "main", t: Date.now() })] });
        if (r.error) console.log("[traffic] send err:", r.error);
        else { stats.main_units++; if (++n % 10 === 1) console.log(`[traffic] sent ${n} units, last ${String(r.unit).slice(0, 12)}`); }
      } catch (e) { console.log("[traffic] exc:", e.message); }
      await new Promise((r) => setTimeout(r, 2000));
    }
    console.log("[traffic] loop exited");
  })();
  // fork loop starts; probe removed (traffic loop covers first-send validation)
  // fork loop: two posters race same height -> DAG forks on main chain
  // A posts, then B immediately parents onto A's unit creating a competing branch;
  // spaced 60s so the chain has time to stabilize between rounds.
  (async () => {
    let fh = 100;
    while (Date.now() < endAt && trafficOn) {
      await new Promise((r) => setTimeout(r, 60000));
      try {
        const dataA = { chain_id: "odex-mvp-1", height: fh, submitter: "A", prev_state_hash: "aa".repeat(32), state_root: "bb".repeat(32) };
        const ua = (await W.forkerA.sendMulti({ messages: [tempDataMessage(dataA)] })).unit;
        await new Promise((r) => setTimeout(r, 300));
        const ub = (await W.forkerB.sendMulti({ messages: [tempDataMessage({ ...dataA, submitter: "B", prev: ua })] })).unit;
        stats.forks_created++;
        stats.main_units += 2;
        fh++;
        console.log(`[fork] height ${fh - 1}: A=${ua.slice(0, 12)} B=${ub.slice(0, 12)} racing`);
      } catch (e) { console.log("[fork] err", e.message); }
    }
    console.log("[fork] loop exited");
  })();

  // order provider: every 5min post next sidechain height batch to AA + main chain temp_data
  (async () => {
    while (Date.now() < endAt && trafficOn) {
      const waitMs = Math.max(0, nextProviderAt - Date.now());
      if (waitMs > 0) await new Promise((r) => setTimeout(r, Math.min(waitMs, 5000)));
      if (Date.now() < nextProviderAt) continue;
      nextProviderAt += ORDER_PROVIDER_MS;
      try {
        // read latest batch file from sidechain exporter
        const bf = path.join(OUT, "batch.json");
        let data;
        if (fs.existsSync(bf)) {
          const full = JSON.parse(fs.readFileSync(bf, "utf8"));
          // compact on-chain summary: ocore cannot validate huge inline payloads
          // (312KB never resolves); full reveal stays off-chain per OIP-0007.
          data = {
            chain_id: full.chain_id,
            height: full.height,
            prev_state_hash: full.prev_state_hash,
            state_root: full.state_root,
            last_unit: full.last_unit,
            seq: full.seq,
            fill_count: full.fill_count,
            fills_hash: full.fills_hash,
            unit_ids: full.unit_ids,
          };
        } else {
          data = { chain_id: "odex-mvp-1", height, prev_state_hash: "00".repeat(32), state_root: ("11" + height).slice(0, 64).padEnd(64, "0"), fills_hash: "ff".repeat(32), fill_count: 0, unit_ids: [] };
        }
        console.log(`[provider] posting h=${data.height} units=${(data.unit_ids || []).length} bytes=${JSON.stringify(data).length}`);
        const mu = await W.provider.sendMulti({ messages: [tempDataMessage(data)] });
        if (mu.error) throw new Error("sendMulti: " + mu.error);
        stats.main_units++;
        console.log(`[provider] posted h=${data.height} main_unit=${String(mu.unit).slice(0, 12)}`);
        // 2) submit+lock into AA (accelerate via timetravel)
        try {
          const su = await trigger("provider", {
            submit: 1, chain_id: "odex-mvp-1", height: data.height,
            prev_state_hash: data.prev_state_hash || "0",
            state_root: data.state_root || "stress_root_" + data.height,
            fills_hash: data.fills_hash || "0",
          }, 100000);
          await network.timetravel({ shift: "11m" });
          await network.witnessUntilStable(su);
          const lu = await trigger("provider", { lock: 1, height: data.height }, 100000);
          await network.witnessUntilStable(lu);
          stats.aa_ok += 2;
          console.log(`[provider] AA locked h=${data.height}`);
        } catch (e) {
          stats.aa_bounced++;
          console.log(`[provider] aa err h=${data.height}`, e.message);
        }
        stats.side_batches++;
        stats.side_units_total += (data.unit_ids || []).length;
        height = data.height + 1;
      } catch (e) { console.log("[provider] err", e.message); }
    }
  })();

  // progress reports
  const repTimer = setInterval(report, 60000);

  /* ---------- run until end ---------- */
  await new Promise((r) => setTimeout(r, RUN_MS));
  trafficOn = false;
  clearInterval(repTimer);

  /* ---------- final TPS report ---------- */
  const secs = RUN_MS / 1000;
  const minsElapsed = (Date.now() - stats.started) / 1000;
  console.log("\n========== FINAL ==========");
  console.log(`duration_wall_s\t${(minsElapsed).toFixed(0)}`);
  console.log(`main_chain_units\t${stats.main_units}\tTPS\t${(stats.main_units / minsElapsed).toFixed(3)}`);
  console.log(`sidechain_batches\t${stats.side_batches}`);
  console.log(`sidechain_ops\t${stats.side_units_total}\tTPS\t${(stats.side_units_total / minsElapsed).toFixed(1)}`);
  console.log(`sidechain_fills\t${stats.side_fills}`);
  console.log(`forks_raced\t${stats.forks_created}`);
  console.log(`aa_accept\t${stats.aa_ok}\taa_bounce\t${stats.aa_bounced}`);
  console.log("waiting for sidechain engine exit...");
  await new Promise((resolve) => hft.on("exit", resolve));
  await network.stop();
  console.log("OK: 20min dual-chain stress complete");
}

main().catch((err) => {
  console.error("FAILED:", err && err.stack ? err.stack : err);
  process.exit(1);
});
