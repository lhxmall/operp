"use strict";

const assert = require("assert");
const crypto = require("crypto");
const zlib = require("zlib");
const { assertPackageSourceCap, packFrames } = require("./batch_frames");

const frames = [
  JSON.stringify({ u: { id: 1 }, t: "trace-α" }),
  JSON.stringify({ u: { id: 2 }, t: "trace-β" }),
  JSON.stringify({ u: { id: 3 }, t: "trace-γ" }),
];
const getJsonSourceString = (value) => JSON.stringify(value);
const sourceLength = (blob) =>
  Buffer.byteLength(getJsonSourceString({ package_blob: blob }), "utf8");
const rawPackage = (blob) => zlib.gunzipSync(Buffer.from(blob, "base64"));
const encodeRaw = (raw) => zlib.gzipSync(raw).toString("base64");

// Force one frame per package. New packages after the first carry the LF at
// their start, so direct concat has separators but never a trailing empty frame
// for the pre-PR watcher's split("\\n") decoder.
const packages = packFrames(frames, { cap: 1, getJsonSourceString });
assert.strictEqual(packages.length, frames.length);
const rawPackages = packages.map(rawPackage);
assert.deepStrictEqual(rawPackages[0], Buffer.from(frames[0], "utf8"));
for (let i = 1; i < rawPackages.length; i++) {
  assert.strictEqual(rawPackages[i][0], 0x0a, "later package must start with LF");
  assert.deepStrictEqual(rawPackages[i].subarray(1), Buffer.from(frames[i], "utf8"));
}
for (const raw of rawPackages) {
  assert.notStrictEqual(raw.at(-1), 0x0a, "package must not end with LF");
}
const assembled = Buffer.concat(rawPackages);
const expectedRaw = Buffer.from(frames.join("\n"), "utf8");
assert.deepStrictEqual(assembled, expectedRaw);
assert.notStrictEqual(assembled.at(-1), 0x0a);
const legacyWatcherFrames = assembled.toString("utf8").split("\n");
assert.deepStrictEqual(legacyWatcherFrames, frames);
for (const frame of legacyWatcherFrames) assert.doesNotThrow(() => JSON.parse(frame));

const expectedRoot = crypto.createHash("sha256").update(expectedRaw).digest("hex");
assert.strictEqual(
  crypto.createHash("sha256").update(assembled).digest("hex"),
  expectedRoot,
  "data_root must cover the exact concatenated, gunzipped package bytes",
);

// A normal package can contain multiple frames and has no trailing LF.
const onePackage = packFrames(frames);
assert.strictEqual(onePackage.length, 1);
assert.deepStrictEqual(rawPackage(onePackage[0]), expectedRaw);

// Exercise the actual source cap, including the leading LF on later packages.
const entropy = (seed) => {
  let out = "";
  for (let i = 0; out.length < 1024; i++) {
    out += crypto.createHash("sha256").update(`${seed}:${i}`).digest("hex");
  }
  return out.slice(0, 1024);
};
const capFrames = ["A", "B", "C"].map((seed) => JSON.stringify({ u: entropy(seed) }));
const capCandidate = (raw) => sourceLength(encodeRaw(Buffer.from(raw, "utf8")));
const cap = Math.max(
  capCandidate(capFrames[0]),
  capCandidate(`\n${capFrames[1]}`),
  capCandidate(`\n${capFrames[2]}`),
);
assert.ok(capCandidate(`${capFrames[0]}\n${capFrames[1]}`) > cap);
const capped = packFrames(capFrames, { cap, getJsonSourceString });
assert.strictEqual(capped.length, capFrames.length);
for (const blob of capped) assert.ok(sourceLength(blob) <= cap);
assert.doesNotThrow(() => assertPackageSourceCap(capped, { cap, getJsonSourceString }));
assert.deepStrictEqual(
  Buffer.concat(capped.map(rawPackage)),
  Buffer.from(capFrames.join("\n"), "utf8"),
);

// Empty input yields no packages (empty batches are invalid upstream).
assert.deepStrictEqual(packFrames([]), []);

// A single frame is indivisible: the helper emits it intact even when it alone
// exceeds cap; the poster's source-cap guard must reject it before submission.
const tooLarge = JSON.stringify({ u: "x".repeat(512) });
const oversized = packFrames([tooLarge], { cap: 1, getJsonSourceString });
assert.strictEqual(oversized.length, 1);
assert.ok(sourceLength(oversized[0]) > 1);
assert.deepStrictEqual(rawPackage(oversized[0]), Buffer.from(tooLarge, "utf8"));
assert.throws(
  () => assertPackageSourceCap(oversized, { cap: 1, getJsonSourceString }),
  RangeError,
);

console.log("batch frame compatibility, UTF-8, cap, empty, and oversize tests passed");
