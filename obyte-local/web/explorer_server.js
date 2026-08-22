"use strict";
/* DAG explorer data source: reads the devnet sqlite directly + sidechain batch registry. */

const http = require("http");
const fs = require("fs");
const path = require("path");
const os = require("os");
const { DatabaseSync } = require("node:sqlite");

const PORT = 8788;
const PUBLIC = path.join(__dirname, "public");

let dbPath = null;
function findDb() {
  const root = path.join(__dirname, "../testdata-stress");
  if (!fs.existsSync(root)) return null;
  const runs = fs.readdirSync(root).filter((d) => d.startsWith("runid-")).sort().reverse();
  for (const run of runs) {
    for (const node of ["genesis-node", "headless-wallet-0001", "obyte-witness-0001"]) {
      const p = path.join(root, run, node);
      if (!fs.existsSync(p)) continue;
      const sub = fs.readdirSync(p)[0];
      if (!sub) continue;
      const db = path.join(p, sub, "byteball.sqlite");
      if (fs.existsSync(db)) return db;
    }
  }
  return null;
}

/* checkpoint the LIVE db's wal into main file, then copy */
function snapshot() {
  if (!dbPath) return null;
  const tmp = path.join(os.tmpdir(), "odex_explorer.sqlite");
  try {
    try {
      const live = new DatabaseSync(dbPath);
      live.exec("PRAGMA wal_checkpoint(TRUNCATE);");
      live.close();
    } catch (_) {}
    fs.copyFileSync(dbPath, tmp);
    if (fs.existsSync(dbPath + "-wal")) {
      try { fs.copyFileSync(dbPath + "-wal", tmp + "-wal"); } catch (_) {}
    }
  } catch (e) {
    return null;
  }
  return tmp;
}

function json(res, code, obj) {
  res.writeHead(code, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  res.end(JSON.stringify(obj));
}

function withDb(fn) {
  const tmp = snapshot();
  if (!tmp) return null;
  try {
    const db = new DatabaseSync(tmp);
    const out = fn(db);
    db.close();
    return out;
  } catch (e) {
    console.error("db error:", e.message);
    return null;
  } finally {
    try { fs.unlinkSync(tmp); } catch (_) {}
  }
}

function unitRows(db) {
  const units = {};
  for (const r of db.prepare(`
    select unit, main_chain_index as mci, level, is_on_main_chain as mc, is_stable as st,
           timestamp, best_parent_unit as bp
    from units`).all()) {
    units[r.unit] = { ...r, parents: [], authors: [], apps: [] };
  }
  for (const r of db.prepare(`select child_unit as c, parent_unit as p from parenthoods`).all()) {
    if (units[r.c]) units[r.c].parents.push(r.p);
  }
  for (const r of db.prepare(`select unit, address from unit_authors`).all()) {
    if (units[r.unit]) units[r.unit].authors.push(r.address);
  }
  for (const r of db.prepare(`select unit, app, payload from messages`).all()) {
    if (!units[r.unit]) continue;
    let summary = r.app;
    if (r.app === "payment") summary = "pay";
    else if ((r.app === "data" || r.app === "temp_data") && r.payload) {
      try {
        const j = JSON.parse(r.payload);
        if (j.deposit) summary = "deposit";
        else if (j.withdraw) summary = "withdraw";
        else if (j.submit) summary = "submit#" + j.height;
        else if (j.lock) summary = "lock#" + j.height;
        else if (j.challenge) summary = "challenge#" + j.height;
        else if (j.ping != null) summary = "ping#" + j.ping;
        else summary = "data";
      } catch (_) { summary = r.app; }
    } else if (r.app === "definition") summary = "def";
    else if (r.app === "data_feed") summary = "feed";
    units[r.unit].apps.push(summary);
  }
  return Object.values(units);
}

const VAULT = "HPR6MWJ62IM4ENCUOP26OZRITMMWFBYH";

function batchRegistry() {
  return withDb((db) => {
    const rows = db.prepare(`
      select r.mci, r.trigger_unit as trigger_unit, substr(r.response,1,400) as resp
      from aa_responses r where r.aa_address = ? order by r.mci desc limit 50`).all(VAULT);
    return rows.map((r) => {
      let status = "ok";
      let err = null;
      try {
        const j = JSON.parse(r.resp);
        if (j.error) { status = "bounced"; err = j.error.message; }
      } catch (_) {}
      return { mci: r.mci, trigger_unit: r.trigger_unit, status, err };
    });
  }) || [];
}

function sidechainBatches() {
  const regPath = path.join(__dirname, "stress-out/batch.json");
  if (fs.existsSync(regPath)) {
    try { return [JSON.parse(fs.readFileSync(regPath, "utf8"))]; } catch (_) {}
  }
  return [];
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  try {
    if (!url.pathname.startsWith("/api/")) {
      const p = path.normalize(path.join(PUBLIC, url.pathname.replace(/^\//, "")));
      if (!p.startsWith(PUBLIC)) return json(res, 403, { error: "path" });
      if (!fs.existsSync(p) || fs.statSync(p).isDirectory()) return json(res, 404, { error: "not found" });
      const ext = path.extname(p);
      const types = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css" };
      res.writeHead(200, { "content-type": (types[ext] || "text/plain") + "; charset=utf-8" });
      return fs.createReadStream(p).pipe(res);
    }

    if (url.pathname === "/api/ex/health") {
      return json(res, 200, { ok: true, db: dbPath ? "found" : "missing" });
    }

    if (url.pathname === "/api/ex/dag") {
      const rows = withDb(unitRows);
      if (!rows) return json(res, 503, { error: "no db yet" });
      return json(res, 200, { units: rows, updated: Date.now() });
    }

    if (url.pathname === "/api/ex/unit") {
      const u = url.searchParams.get("unit");
      const out = withDb((db) => ({
        unit: db.prepare(`select * from units where unit=?`).get(u),
        messages: db.prepare(`select message_index, app, payload_location, payload from messages where unit=? order by message_index`).all(u),
        parents: db.prepare(`select parent_unit from parenthoods where child_unit=?`).all(u).map((x) => x.parent_unit),
        children: db.prepare(`select child_unit from parenthoods where parent_unit=?`).all(u).map((x) => x.child_unit),
        authors: db.prepare(`select address from unit_authors where unit=?`).all(u).map((x) => x.address),
        ball: db.prepare(`select ball from balls where unit=?`).get(u) || null,
      }));
      if (!out || !out.unit) return json(res, 404, { error: "not found" });
      return json(res, 200, out);
    }

    if (url.pathname === "/api/ex/aa") {
      return json(res, 200, { responses: batchRegistry(), vault: VAULT });
    }

    if (url.pathname === "/api/ex/sidechain") {
      return json(res, 200, { batches: sidechainBatches() });
    }

    json(res, 404, { error: "not found" });
  } catch (e) {
    json(res, 500, { error: String(e.message || e) });
  }
});

dbPath = findDb();
setInterval(() => { dbPath = findDb(); }, 5000);

server.listen(PORT, "127.0.0.1", () => {
  console.log(`explorer http://127.0.0.1:${PORT}/explorer.html`);
});
