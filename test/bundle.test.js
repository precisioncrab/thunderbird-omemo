/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests for the bundled crypto core (scripts/build.mjs), its self-test and
 * the pluggable random source (src/crypto/random.js). The bundle is what
 * Thunderbird loads, so it's built here and imported the way Gecko would:
 * as one self-contained module with no imports.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { buildCore } from "../scripts/build.mjs";
import * as core from "../src/crypto/index.js";
import * as keys from "../src/crypto/keys.js";
import { randomBytes } from "../src/crypto/random.js";
import { hex } from "./helpers.js";
import { readFileSync } from "node:fs";
import { CORE_VERSION as sourceVersion } from "../src/core.js";

const { code, imports } = await buildCore({ write: false });

test("the bundle is one self-contained module with noble's license notices", () => {
  // esbuild's own record of what the output still imports (static, dynamic
  // or require); a text search would trip over JSDoc import() types.
  assert.deepEqual(imports, [], "no imports left");
  for (const lib of ["noble-hashes", "noble-curves", "noble-ciphers"]) {
    // The build appends each library's LICENSE file (noble-hashes 2.x has no comment of its own).
    assert.match(code, new RegExp(`/\\*! ${lib} [0-9.]+ - MIT License\\s+The MIT License \\(MIT\\)\\s+Copyright \\(c\\) [0-9]{4} Paul Miller[^]*?Permission is hereby granted`), lib);
  }
});

test("the bundle loads on its own, exports the core and passes its self-test", async () => {
  const bundle = await import(`data:text/javascript;base64,${Buffer.from(code).toString("base64")}`);
  for (const name of ["xeddsa", "keys", "protobuf", "x3dh", "doubleRatchet", "payload", "envelope", "selfTest", "setRandomSource", "hasWebCrypto", "store", "persist", "xml", "formats", "messages", "pep", "caps", "account", "xmlnode", "bridge", "fingerprint"]) {
    assert.ok(name in bundle, `exports ${name}`);
  }
  assert.match(bundle.selfTest(), /^crypto self-test passed/);
  const manifestVersion = JSON.parse(readFileSync(new URL("../manifest.json", import.meta.url), "utf8")).version;
  assert.equal(bundle.CORE_VERSION, manifestVersion, "stamped with the add-on version");
  assert.equal(sourceVersion, "source", "unbundled source says so");
});

test("the self-test passes from source too, and reports the environment", () => {
  assert.match(core.selfTest(), /crypto\.getRandomValues: function/);
});

test("a plugged-in random source is used by every generator, and can be removed", () => {
  let calls = 0;
  core.setRandomSource((n) => {
    calls++;
    return new Array(n).fill(7);
  });
  try {
    const a = keys.generateIdentityKeyPair();
    const b = keys.generateIdentityKeyPair();
    assert.equal(calls, 2);
    assert.deepEqual(a.privateKey, b.privateKey, "same fixed bytes, same key");
  } finally {
    core.setRandomSource(null);
  }
  // End to end with a custom source that gives different bytes each time.
  const webCrypto = globalThis.crypto;
  core.setRandomSource((n) => webCrypto.getRandomValues(new Uint8Array(n)));
  try {
    assert.match(core.selfTest(), /passed/);
  } finally {
    core.setRandomSource(null);
  }
  assert.notDeepEqual(keys.generateIdentityKeyPair().privateKey, keys.generateIdentityKeyPair().privateKey);
});

test("a random source returning the wrong size is refused, as is a non-function", () => {
  core.setRandomSource((n) => new Uint8Array(n - 1));
  try {
    assert.throws(() => keys.generateIdentityKeyPair(), /returned 31 bytes; 32 were asked for/);
  } finally {
    core.setRandomSource(null);
  }
  assert.throws(() => core.setRandomSource("urandom"), /takes a function or null/);
});

test("without Web Crypto and without a source, randomness fails loudly, and a source fixes it", () => {
  const original = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", { value: undefined, configurable: true });
  try {
    assert.equal(core.hasWebCrypto(), false);
    assert.throws(() => keys.generateIdentityKeyPair(), /No source of randomness/);
    // noble-curves 2.x blinds Ed25519 secret-key multiplication with the Web
    // Crypto it found at load, so with Web Crypto taken away afterwards (which
    // Thunderbird never does) the XEdDSA step fails too. The next test covers
    // the real case: a scope that never had Web Crypto.
    assert.throws(() => core.selfTest(), /self-test failed at "(XEdDSA known answer|oldmemo session)".*crypto\.getRandomValues: undefined/);
    core.setRandomSource((n) => Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 0xff));
    assert.equal(hex(randomBytes(32)), hex(Uint8Array.from({ length: 32 }, (_, i) => (i * 37 + 32) & 0xff)), "the source is used");
  } finally {
    core.setRandomSource(null);
    Object.defineProperty(globalThis, "crypto", original);
  }
  assert.equal(core.hasWebCrypto(), true);
});

test("a bundle loaded where there's no Web Crypto passes its self-test with a plugged-in source", async () => {
  // As the Experiment does it: noble sees no Web Crypto at load (so it doesn't
  // blind), and Thunderbird's own generator is plugged in.
  const original = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", { value: undefined, configurable: true });
  try {
    const fresh = await import(`data:text/javascript;base64,${Buffer.from(`${code}
// fresh copy`).toString("base64")}`);
    assert.equal(fresh.hasWebCrypto(), false);
    const { randomBytes: nodeRandomBytes } = await import("node:crypto");
    fresh.setRandomSource((n) => new Uint8Array(nodeRandomBytes(n)));
    assert.match(fresh.selfTest(), /^crypto self-test passed.*crypto\.getRandomValues: undefined/);
  } finally {
    Object.defineProperty(globalThis, "crypto", original);
  }
});
