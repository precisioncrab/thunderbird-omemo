/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests for src/crypto/keys.js: unit tests, plus known-answer tests that
 * replay the reference implementation's random draws (test/vectors/) and
 * expect the same keys and signatures, byte for byte.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { x25519 } from "@noble/curves/ed25519";
import * as keys from "../src/crypto/keys.js";
import * as xeddsa from "../src/crypto/xeddsa.js";
import { load, h, hex, replay } from "./helpers.js";

const vectors = { oldmemo: load("oldmemo"), twomemo: load("twomemo") };

const isClamped = (k) => (k[0] & 7) === 0 && (k[31] & 0xc0) === 0x40;

// --- known answers from the reference implementation ---

for (const [ns, v] of Object.entries(vectors)) {
  test(`${ns}: replaying the reference's randomness reproduces Alice's keys and signature`, () => {
    const { alice } = v;
    const identityDraws = alice.setup_random.filter((d) => d.source.startsWith("alice_identity"));
    const identity = keys.generateIdentityKeyPair({ random: replay(...identityDraws.slice(-1)) });
    assert.equal(hex(identity.privateKey), alice.identity.priv);
    assert.equal(hex(identity.publicKey.curve25519), alice.identity.curve25519_pub);
    assert.equal(hex(identity.publicKey.ed25519), alice.identity.ed25519_pub);

    const random = replay(...alice.setup_random.filter((d) => d.source === "token_bytes"));
    const spk = alice.signed_pre_key;
    const signedPreKey = keys.generateSignedPreKey(identity.privateKey, spk.id, ns, {
      random,
      now: () => spk.timestamp * 1000,
    });
    assert.equal(hex(signedPreKey.publicKey), spk.pub);
    assert.equal(hex(signedPreKey.signature), spk.signature);
    assert.equal(signedPreKey.createdAt, spk.timestamp * 1000);
    assert.equal(hex(x25519.getPublicKey(signedPreKey.privateKey)), spk.pub);

    const preKeys = keys.generatePreKeys(1, alice.pre_keys.length, { random });
    assert.equal(random.remaining(), 0);
    // The reference numbers pre keys in its own order, so compare as sets.
    assert.deepEqual(preKeys.map((k) => hex(k.publicKey)).sort(), alice.pre_keys.map((k) => k.pub).sort());
  });
}

test("twomemo: a peer's published bundle decodes and its signed prekey verifies (sign bit 1)", () => {
  const { bob } = vectors.twomemo;
  const field = (re) => Buffer.from(re.exec(bob.bundle_xml)[1], "base64");
  const identityKey = keys.decodeIdentityKey("twomemo", field(/<ik>([^<]+)</));
  const signedPreKey = keys.decodePublicKey("twomemo", field(/<spk id="\d+">([^<]+)</));
  const signature = field(/<spks>([^<]+)</);

  assert.equal(identityKey.ed25519[31] >> 7, 1, "vector should exercise sign bit 1");
  assert.equal(hex(identityKey.curve25519), bob.identity.curve25519_pub);
  assert.equal(hex(signedPreKey), bob.signed_pre_key.pub);
  assert.equal(keys.verifySignedPreKey("twomemo", identityKey, signedPreKey, signature), true);
});

test("oldmemo: a peer's signed prekey verifies with the sign bit carried in the signature", () => {
  const { bob } = vectors.oldmemo;
  const edPub = h(bob.identity.ed25519_pub);
  const identityKey = keys.decodeIdentityKey("oldmemo", keys.encodeIdentityKey("oldmemo", {
    curve25519: h(bob.identity.curve25519_pub),
  }));
  assert.equal(identityKey.ed25519, null);

  const signature = h(bob.signed_pre_key.signature);
  const bundleSignature = Uint8Array.from(signature);
  bundleSignature[63] |= edPub[31] & 0x80;
  const spk = h(bob.signed_pre_key.pub);
  assert.equal(keys.verifySignedPreKey("oldmemo", identityKey, spk, bundleSignature), true);
  assert.equal(keys.verifySignedPreKey("oldmemo", identityKey, spk, signature), false);
});

// --- generation ---

test("identity key pairs are clamped, and both public forms agree", () => {
  const seen = new Set();
  for (let i = 0; i < 20; i++) {
    const { privateKey, publicKey } = keys.generateIdentityKeyPair();
    assert.ok(isClamped(privateKey));
    assert.deepEqual(publicKey.curve25519, x25519.getPublicKey(privateKey));
    assert.equal(publicKey.ed25519[31] >> 7, 0, "XEdDSA identity keys have sign bit 0");
    assert.deepEqual(xeddsa.edwardsToMontgomery(publicKey.ed25519), publicKey.curve25519);
    seen.add(hex(privateKey));
  }
  assert.equal(seen.size, 20);
});

test("a signed prekey verifies in its own namespace only", () => {
  const identity = keys.generateIdentityKeyPair();
  for (const ns of keys.NAMESPACES) {
    const other = ns === "oldmemo" ? "twomemo" : "oldmemo";
    const spk = keys.generateSignedPreKey(identity.privateKey, 7, ns, { now: () => 1234 });
    assert.equal(spk.id, 7);
    assert.equal(spk.createdAt, 1234);
    assert.ok(isClamped(spk.privateKey));

    const published = (n) => keys.decodeIdentityKey(n, keys.encodeIdentityKey(n, identity.publicKey));
    assert.equal(keys.verifySignedPreKey(ns, published(ns), spk.publicKey, spk.signature), true);
    assert.equal(keys.verifySignedPreKey(other, published(other), spk.publicKey, spk.signature), false);
  }
});

test("pre keys get consecutive ids that wrap from MAX_KEY_ID to 1", () => {
  const batch = keys.generatePreKeys(keys.MAX_KEY_ID - 1, 4);
  assert.deepEqual(batch.map((k) => k.id), [keys.MAX_KEY_ID - 1, keys.MAX_KEY_ID, 1, 2]);
  assert.equal(new Set(batch.map((k) => hex(k.privateKey))).size, 4);
  for (const k of batch) {
    assert.ok(isClamped(k.privateKey));
    assert.deepEqual(k.publicKey, x25519.getPublicKey(k.privateKey));
  }
  assert.deepEqual(keys.generatePreKeys(5, 0), []);
  assert.equal(keys.nextKeyId(1), 2);
  assert.equal(keys.nextKeyId(keys.MAX_KEY_ID), 1);
});

test("key ids outside 1..MAX_KEY_ID are rejected", () => {
  const identity = keys.generateIdentityKeyPair();
  for (const bad of [0, -1, keys.MAX_KEY_ID + 1, 1.5, "1", NaN]) {
    assert.throws(() => keys.generatePreKeys(bad, 1), /Key id/);
    assert.throws(() => keys.generateSignedPreKey(identity.privateKey, bad, "twomemo"), /Key id/);
    assert.throws(() => keys.nextKeyId(bad), /Key id/);
  }
});

// --- encodings ---

test("public keys encode per namespace and round-trip", () => {
  const u = keys.generatePreKeys(1, 1)[0].publicKey;
  const old = keys.encodePublicKey("oldmemo", u);
  assert.equal(old.length, 33);
  assert.equal(old[0], 0x05);
  assert.deepEqual(keys.decodePublicKey("oldmemo", old), u);
  assert.deepEqual(keys.encodePublicKey("twomemo", u), u);
  assert.deepEqual(keys.decodePublicKey("twomemo", u), u);

  const identity = keys.generateIdentityKeyPair().publicKey;
  assert.deepEqual(keys.encodeIdentityKey("oldmemo", identity), keys.encodePublicKey("oldmemo", identity.curve25519));
  assert.deepEqual(keys.encodeIdentityKey("twomemo", identity), identity.ed25519);
  assert.deepEqual(keys.decodeIdentityKey("twomemo", identity.ed25519), identity);
});

test("malformed keys are rejected when decoding", () => {
  const u = keys.generatePreKeys(1, 1)[0].publicKey;
  const old = keys.encodePublicKey("oldmemo", u);
  assert.throws(() => keys.decodePublicKey("oldmemo", u), /33 bytes/);
  assert.throws(() => keys.decodePublicKey("oldmemo", Uint8Array.of(0x06, ...u)), /0x05/);
  assert.throws(() => keys.decodePublicKey("twomemo", old), /32 bytes/);
  assert.throws(() => keys.decodeIdentityKey("oldmemo", u), /33 bytes/);
  assert.throws(() => keys.decodeIdentityKey("twomemo", new Uint8Array(32).fill(0xff)));
  assert.throws(() => keys.encodePublicKey("omemo:1", u), /Unknown OMEMO namespace/);
  assert.throws(() => keys.encodeIdentityKey("twomemo", { curve25519: u, ed25519: null }), /Ed25519 form/);
});

test("verifySignedPreKey returns false for malformed input instead of throwing", () => {
  const identity = keys.generateIdentityKeyPair();
  const spk = keys.generateSignedPreKey(identity.privateKey, 1, "twomemo");
  assert.equal(keys.verifySignedPreKey("twomemo", { curve25519: identity.publicKey.curve25519, ed25519: null },
    spk.publicKey, spk.signature), false);
  assert.equal(keys.verifySignedPreKey("twomemo", identity.publicKey, spk.publicKey.subarray(1), spk.signature), false);
  assert.equal(keys.verifySignedPreKey("twomemo", identity.publicKey, spk.publicKey, spk.signature.subarray(1)), false);
  assert.equal(keys.verifySignedPreKey("omemo:1", identity.publicKey, spk.publicKey, spk.signature), false);
  assert.equal(keys.verifySignedPreKey("oldmemo", {}, spk.publicKey, spk.signature), false);
});
