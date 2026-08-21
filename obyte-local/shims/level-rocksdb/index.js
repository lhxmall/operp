"use strict";

const { EventEmitter } = require("events");

function cmp(a, b) {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

function toStr(k) {
  if (Buffer.isBuffer(k)) return k.toString("utf8");
  return String(k);
}

class MemoryBatch {
  constructor(db) {
    this._db = db;
    this._ops = [];
  }
  put(key, val) {
    this._ops.push({ type: "put", key: toStr(key), value: toStr(val) });
    return this;
  }
  del(key) {
    this._ops.push({ type: "del", key: toStr(key) });
    return this;
  }
  write(opts, cb) {
    if (typeof opts === "function") {
      cb = opts;
      opts = {};
    }
    for (const op of this._ops) {
      if (op.type === "put") this._db._map.set(op.key, op.value);
      else this._db._map.delete(op.key);
    }
    this._ops = [];
    if (cb) process.nextTick(() => cb(null));
    return Promise.resolve();
  }
}

class MemoryDB {
  constructor() {
    this._map = new Map();
    this._open = true;
  }
  isOpen() {
    return this._open;
  }
  isClosed() {
    return !this._open;
  }
  open(cb) {
    this._open = true;
    if (cb) process.nextTick(() => cb(null));
  }
  close(cb) {
    this._open = false;
    if (cb) process.nextTick(() => cb(null));
  }
  get(key, cb) {
    const k = toStr(key);
    if (!this._map.has(k)) {
      const err = new Error("NotFound");
      err.notFound = true;
      return process.nextTick(() => cb(err));
    }
    const val = this._map.get(k);
    process.nextTick(() => cb(null, val));
  }
  put(key, val, cb) {
    this._map.set(toStr(key), toStr(val));
    if (cb) process.nextTick(() => cb(null));
  }
  del(key, cb) {
    this._map.delete(toStr(key));
    if (cb) process.nextTick(() => cb(null));
  }
  batch() {
    return new MemoryBatch(this);
  }
  createReadStream(options) {
    return this._stream(options, true);
  }
  createKeyStream(options) {
    return this._stream(options, false);
  }
  _stream(options, withValue) {
    const opts = options || {};
    const gte = opts.gte !== undefined ? toStr(opts.gte) : undefined;
    const lte = opts.lte !== undefined ? toStr(opts.lte) : undefined;
    const gt = opts.gt !== undefined ? toStr(opts.gt) : undefined;
    const lt = opts.lt !== undefined ? toStr(opts.lt) : undefined;
    const keys = Array.from(this._map.keys()).sort(cmp).filter((k) => {
      if (gte !== undefined && cmp(k, gte) < 0) return false;
      if (gt !== undefined && cmp(k, gt) <= 0) return false;
      if (lte !== undefined && cmp(k, lte) > 0) return false;
      if (lt !== undefined && cmp(k, lt) >= 0) return false;
      return true;
    });
    const ee = new EventEmitter();
    process.nextTick(() => {
      for (const k of keys) {
        if (withValue) ee.emit("data", { key: k, value: this._map.get(k) });
        else ee.emit("data", k);
      }
      ee.emit("end");
      ee.emit("close");
    });
    ee.on = ee.addListener.bind(ee);
    return ee;
  }
}

function rocksdb(location, options, cb) {
  if (typeof options === "function") {
    cb = options;
  }
  const db = new MemoryDB();
  if (cb) process.nextTick(() => cb(null, db));
  return db;
}

module.exports = rocksdb;
