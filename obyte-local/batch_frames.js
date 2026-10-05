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

  const encode = (items, packageIndex) => {
    if (items.length === 0) return "";
    const prefix = packageIndex > 0 ? "\n" : "";
    const raw = `${prefix}${items.join("\n")}`;
    return zlib.gzipSync(Buffer.from(raw, "utf8")).toString("base64");
  };
  const sourceLength = (blob) =>
    Buffer.byteLength(getJsonSourceString({ package_blob: blob }), "utf8");

  const packages = [];
  let current = [];
  const flush = () => {
    if (current.length === 0) return;
    packages.push(encode(current, packages.length));
    current = [];
  };

  for (const frame of frames) {
    const trial = encode([...current, frame], packages.length);
    if (current.length > 0 && sourceLength(trial) > cap) flush();
    current.push(frame);
  }
  flush();
  return packages;
}

function assertPackageSourceCap(packages, options = {}) {
  const cap = options.cap ?? DEFAULT_PACKAGE_SOURCE_CAP;
  const getJsonSourceString = options.getJsonSourceString ?? JSON.stringify;
  for (const blob of packages) {
    const sourceLength = Buffer.byteLength(
      getJsonSourceString({ package_blob: blob }),
      "utf8",
    );
    if (sourceLength > cap) {
      throw new RangeError(`package source length ${sourceLength} exceeds cap ${cap}`);
    }
  }
}

module.exports = { DEFAULT_PACKAGE_SOURCE_CAP, assertPackageSourceCap, packFrames };
