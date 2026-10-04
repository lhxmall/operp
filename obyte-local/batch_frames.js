"use strict";

const zlib = require("zlib");

const DEFAULT_PACKAGE_SOURCE_CAP = 4_000_000;

function packFrames(frames, options = {}) {
  const cap = options.cap ?? DEFAULT_PACKAGE_SOURCE_CAP;
  const getJsonSourceString = options.getJsonSourceString ?? JSON.stringify;
  if (!Array.isArray(frames) || frames.some((frame) => typeof frame !== "string")) {
    throw new TypeError("frames must be an array of strings");
  }
  if (!Number.isSafeInteger(cap) || cap < 0) {
    throw new RangeError("package source cap must be a non-negative safe integer");
  }
  if (typeof getJsonSourceString !== "function") {
    throw new TypeError("getJsonSourceString must be a function");
  }

  const encode = (items) => {
    if (items.length === 0) return "";
    const raw = `${items.join("\n")}\n`;
    return zlib.gzipSync(Buffer.from(raw, "utf8")).toString("base64");
  };
  const sourceLength = (blob) =>
    Buffer.byteLength(getJsonSourceString({ package_blob: blob }), "utf8");

  const packages = [];
  let current = [];
  const flush = () => {
    if (current.length === 0) return;
    packages.push(encode(current));
    current = [];
  };

  for (const frame of frames) {
    const trial = encode([...current, frame]);
    if (current.length > 0 && sourceLength(trial) > cap) flush();
    current.push(frame);
  }
  flush();
  return packages;
}

module.exports = { DEFAULT_PACKAGE_SOURCE_CAP, packFrames };
