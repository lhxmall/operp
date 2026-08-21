"use strict";

const { DatabaseSync } = require("node:sqlite");
const fs = require("fs");
const path = require("path");

function normalizeParams(params) {
  if (!params) return [];
  if (!Array.isArray(params)) return [params];
  return params.map((p) => (p === undefined ? null : p));
}

class Database {
  constructor(filename, mode, cb) {
    if (typeof mode === "function") {
      cb = mode;
      mode = undefined;
    }
    this.filename = filename;
    this.changes = 0;
    this.lastID = 0;
    try {
      if (filename && filename !== ":memory:") {
        const dir = path.dirname(filename);
        if (dir && dir !== "." && !fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }
      }
      this._db = new DatabaseSync(filename || ":memory:");
      if (cb) process.nextTick(() => cb(null));
    } catch (err) {
      if (cb) process.nextTick(() => cb(err));
      else throw err;
    }
  }

  all(sql, params, cb) {
    if (typeof params === "function") {
      cb = params;
      params = [];
    }
    try {
      const stmt = this._db.prepare(sql);
      const rows = stmt.all(...normalizeParams(params));
      cb.call(this, null, rows);
    } catch (err) {
      cb.call(this, err);
    }
  }

  run(sql, params, cb) {
    if (typeof params === "function") {
      cb = params;
      params = [];
    }
    try {
      const trimmed = String(sql).trim();
      if (/^(BEGIN|COMMIT|ROLLBACK|PRAGMA|CREATE|DROP|ALTER|VACUUM)\b/i.test(trimmed) && !/\?/.test(trimmed)) {
        this._db.exec(trimmed);
        this.changes = 0;
        this.lastID = 0;
        cb.call(this, null);
        return;
      }
      const stmt = this._db.prepare(sql);
      const info = stmt.run(...normalizeParams(params));
      this.changes = Number(info.changes || 0);
      this.lastID = Number(info.lastInsertRowid || 0);
      cb.call(this, null);
    } catch (err) {
      cb.call(this, err);
    }
  }

  exec(sql, cb) {
    try {
      this._db.exec(sql);
      if (cb) cb.call(this, null);
    } catch (err) {
      if (cb) cb.call(this, err);
      else throw err;
    }
  }

  close(cb) {
    try {
      this._db.close();
      if (cb) cb(null);
    } catch (err) {
      if (cb) cb(err);
    }
  }
}

module.exports = {
  Database,
  OPEN_READONLY: 1,
  OPEN_READWRITE: 2,
  OPEN_CREATE: 4,
  verbose: function () {
    return module.exports;
  },
};
