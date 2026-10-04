"use strict";

const assert = require("assert");
const crypto = require("crypto");
const zlib = require("zlib");
const { packFrames } = require("./batch_frames");

const frames = [
  JSON.stringify({ u: { id: 1 }, t: "trace-α" }),
  JSON.stringify({ u: { id: 2 }, t: "trace-β" }),
  JSON.stringify({ u: { id: 3 }, t: "trace-γ" }),
];

// A tiny cap forces one frame per package; the watcher concatenates these
// gunzipped package bytes verbatim, so each package must carry its delimiter.
const packages = packFrames(frames, { cap: 1 });
assert.strictEqual(packages.length, frames.length);
const rawPackages = packages.map((blob) => zlib.gunzipSync(Buffer.from(blob, "base64")));
for (const raw of rawPackages) assert.ok(raw.at(-1) === 0x0a, "package lacks terminal newline");

const assembled = Buffer.concat(rawPackages);
const expectedRaw = Buffer.from(frames.map((frame) => `${frame}\n`).join(""), "utf8");
assert.deepStrictEqual(assembled, expectedRaw);
const decoded = assembled.toString("utf8").split("\n");
assert.strictEqual(decoded.pop(), "", "assembled stream should end at a frame boundary");
assert.deepStrictEqual(decoded, frames);
for (const frame of decoded) assert.doesNotThrow(() => JSON.parse(frame));

const expectedRoot = crypto.createHash("sha256").update(expectedRaw).digest("hex");
assert.strictEqual(
  crypto.createHash("sha256").update(assembled).digest("hex"),
  expectedRoot,
  "data_root must cover exactly the bytes the watcher assembles",
);
assert.strictEqual(packFrames(frames).length, 1, "small batch should remain a single package");

console.log("batch frame tests passed: multi-package frames concatenate and decode");
