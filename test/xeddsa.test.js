/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * XEdDSA tests. Where possible these check against @noble/curves' own
 * Ed25519 and X25519 code rather than only against ourselves: an XEdDSA
 * signature must verify as a standard Ed25519 signature, and the Edwards key
 * must map back to the X25519 public key. Byte-exact known-answer vectors
 * from a reference implementation come later (docs/TASKS.md 2.2).
 */

import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { ed25519, x25519, edwardsToMontgomeryPub } from "@noble/curves/ed25519";
import * as xeddsa from "../src/crypto/xeddsa.js";

const p = ed25519.CURVE.p;
const msg = new TextEncoder().encode("signed prekey bytes stand-in");

function newKey() {
  const k = x25519.utils.randomPrivateKey();
  return { k, u: x25519.getPublicKey(k) };
}

function leBytes(n) {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

test("calculateKeyPair's Edwards key maps to the X25519 public key, for raw unclamped keys", () => {
  for (let i = 0; i < 50; i++) {
    const { k, u } = newKey();
    const { A } = xeddsa.calculateKeyPair(k);
    assert.equal(A[31] & 0x80, 0, "sign bit must be 0");
    assert.deepEqual(edwardsToMontgomeryPub(A), u);
  }
});

test("Montgomery <-> Edwards conversions round-trip and agree with noble", () => {
  for (let i = 0; i < 50; i++) {
    const { k, u } = newKey();
    const A = xeddsa.montgomeryToEdwards(u);
    assert.deepEqual(A, xeddsa.calculateKeyPair(k).A);
    assert.deepEqual(xeddsa.edwardsToMontgomery(A), u);
  }
});

test("edwardsToMontgomery accepts Ed25519 keys with either sign bit", () => {
  let seen = 0;
  while (seen !== 0b11) {
    const A = ed25519.getPublicKey(ed25519.utils.randomPrivateKey());
    seen |= A[31] & 0x80 ? 0b10 : 0b01;
    assert.deepEqual(xeddsa.edwardsToMontgomery(A), edwardsToMontgomeryPub(A));
  }
});

test("sign then verify round-trips, including an empty message", () => {
  for (const m of [msg, new Uint8Array(0), randomBytes(1000)]) {
    const { k, u } = newKey();
    const sig = xeddsa.sign(k, m, randomBytes(64));
    assert.equal(sig.length, 64);
    assert.equal(xeddsa.verify(u, m, sig), true);
  }
});

test("XEdDSA signatures are standard Ed25519 signatures under the Edwards key", () => {
  for (let i = 0; i < 20; i++) {
    const { k } = newKey();
    const { A } = xeddsa.calculateKeyPair(k);
    const sig = xeddsa.sign(k, msg, randomBytes(64));
    assert.equal(ed25519.verify(sig, msg, A), true);
  }
});

test("verifyEdwards accepts genuine Ed25519 signatures from keys with either sign bit", () => {
  let seen = 0;
  while (seen !== 0b11) {
    const seed = ed25519.utils.randomPrivateKey();
    const A = ed25519.getPublicKey(seed);
    seen |= A[31] & 0x80 ? 0b10 : 0b01;
    assert.equal(xeddsa.verifyEdwards(A, msg, ed25519.sign(msg, seed)), true);
  }
});

test("signing is deterministic for fixed randomness, and varies with it", () => {
  const { k, u } = newKey();
  const z1 = randomBytes(64);
  const z2 = randomBytes(64);
  const s1 = xeddsa.sign(k, msg, z1);
  assert.deepEqual(xeddsa.sign(k, msg, z1), s1);
  const s2 = xeddsa.sign(k, msg, z2);
  assert.notDeepEqual(s2, s1);
  assert.equal(xeddsa.verify(u, msg, s2), true);
});

test("private keys must be 32 bytes", () => {
  assert.throws(() => xeddsa.calculateKeyPair(new Uint8Array(31)), /32 bytes/);
  assert.throws(() => xeddsa.sign(new Uint8Array(33), msg, randomBytes(64)), /32 bytes/);
});

test("sign requires exactly 64 bytes of randomness", () => {
  const { k } = newKey();
  assert.throws(() => xeddsa.sign(k, msg, randomBytes(32)), /64 bytes/);
});

test("verify rejects tampering, wrong keys, and malformed input without throwing", () => {
  const { k, u } = newKey();
  const sig = xeddsa.sign(k, msg, randomBytes(64));
  const flip = (bytes, i, mask = 1) => {
    const c = Uint8Array.from(bytes);
    c[i] ^= mask;
    return c;
  };

  assert.equal(xeddsa.verify(u, flip(msg, 0), sig), false, "tampered message");
  assert.equal(xeddsa.verify(u, msg, flip(sig, 0)), false, "tampered R");
  assert.equal(xeddsa.verify(u, msg, flip(sig, 40)), false, "tampered s");
  assert.equal(xeddsa.verify(newKey().u, msg, sig), false, "wrong key");
  assert.equal(xeddsa.verify(u, msg, flip(sig, 63, 0xe0)), false, "s >= 2^253");
  assert.equal(xeddsa.verify(u, msg, new Uint8Array(64)), false, "all-zero signature");
  assert.equal(xeddsa.verify(u, msg, sig.subarray(0, 63)), false, "short signature");
  assert.equal(xeddsa.verify(u.subarray(0, 31), msg, sig), false, "short key");
  assert.equal(xeddsa.verify(leBytes(p), msg, sig), false, "u = p");
  assert.equal(xeddsa.verify(leBytes(p - 1n), msg, sig), false, "u = -1 (no Edwards image)");
  assert.equal(xeddsa.verifyEdwards(new Uint8Array(32).fill(0xff), msg, sig), false, "A off the curve");
});
