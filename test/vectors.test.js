/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Known-answer tests against test/vectors/*.json, which
 * tools/gen-vectors/gen_vectors.py generates from MIT-licensed reference
 * Python implementations (python-xeddsa, python-x3dh, python-doubleratchet,
 * python-twomemo). oldmemo.json covers the key schedule only: it comes from
 * the generic libraries with oldmemo's constants, since no permissively
 * licensed oldmemo implementation exists (see tools/gen-vectors/README.md).
 *
 * XEdDSA is checked through our module here; X3DH through ours in
 * test/x3dh.test.js; the ratchet through ours in test/double-ratchet.test.js,
 * which replays both conversations. The raw-noble KDF check below is kept
 * on purpose (decided in task 2.10): it checks the constants table in
 * docs/TASKS.md without going through our module, so a mistake in the
 * table and the same mistake in the module can't hide each other.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import * as xeddsa from "../src/crypto/xeddsa.js";
import { load, h, hex } from "./helpers.js";

const xv = load("xeddsa");
const conversations = { oldmemo: load("oldmemo"), twomemo: load("twomemo") };

const cat = (...parts) => Uint8Array.from(Buffer.concat(parts.map((p) => Buffer.from(p))));

// --- XEdDSA ---

test("XEdDSA signatures match the reference byte for byte", () => {
  for (const v of xv.signatures) {
    assert.equal(hex(xeddsa.sign(h(v.priv), h(v.message), h(v.nonce))), v.signature);
    assert.equal(hex(xeddsa.calculateKeyPair(h(v.priv)).A), v.ed25519_pub);
    assert.equal(xeddsa.verify(h(v.curve25519_pub), h(v.message), h(v.signature)), true);
  }
});

test("natural-sign-bit signatures verify, directly and in libsignal's transport form", () => {
  const signBits = new Set();
  for (const v of xv.natural_sign_signatures) {
    signBits.add(v.sign_bit);
    assert.equal(xeddsa.verifyEdwards(h(v.ed25519_pub), h(v.message), h(v.signature)), true);
    assert.equal(xeddsa.verify(h(v.curve25519_pub), h(v.message), h(v.signature_with_sign_bit)), true);
  }
  assert.deepEqual([...signBits].sort(), [0, 1]);
});

test("Ed25519 seed signatures verify, for both sign bits", () => {
  for (const v of xv.seed_signatures) {
    assert.equal(xeddsa.verifyEdwards(h(v.ed25519_pub), h(v.message), h(v.signature)), true);
    assert.equal(hex(xeddsa.edwardsToMontgomery(h(v.ed25519_pub))), v.curve25519_pub);
  }
});

test("Curve25519 -> Ed25519 conversion matches the reference", () => {
  for (const v of xv.conversions) {
    assert.equal(hex(xeddsa.montgomeryToEdwards(h(v.curve25519_pub))), v.ed25519_pub_sign_bit_0);
    assert.equal(hex(xeddsa.edwardsToMontgomery(h(v.ed25519_pub_sign_bit_1))), v.curve25519_pub);
  }
});

test("X25519 agrees with the reference", () => {
  for (const v of xv.x25519) {
    assert.equal(hex(x25519.getSharedSecret(h(v.priv), h(v.other_pub))), v.shared_secret);
  }
});

// --- signed prekey signatures as real peers publish them ---

test("oldmemo: a natural-sign-bit peer's signed prekey signature verifies in libsignal's bundle form", () => {
  const { bob } = conversations.oldmemo;
  const edPub = h(bob.identity.ed25519_pub);
  assert.equal(edPub[31] >> 7, 1, "vector should exercise sign bit 1");
  const signedPreKey = cat([0x05], h(bob.signed_pre_key.pub)); // the signature covers all 33 bytes
  const signature = h(bob.signed_pre_key.signature);
  assert.equal(xeddsa.verifyEdwards(edPub, signedPreKey, signature), true);

  // An oldmemo bundle publishes the identity key as 0x05 || u, which has no
  // sign bit, so the bit rides in the top bit of the signature's last byte.
  const bundleSignature = Uint8Array.from(signature);
  bundleSignature[63] |= edPub[31] & 0x80;
  assert.equal(xeddsa.verify(h(bob.identity.curve25519_pub), signedPreKey, bundleSignature), true);
  assert.equal(xeddsa.verify(h(bob.identity.curve25519_pub), signedPreKey, signature), false,
    "without the carried sign bit, the key maps to the other Edwards point");
});

test("twomemo: a peer's signed prekey signature verifies under its Ed25519 identity key", () => {
  const { bob } = conversations.twomemo;
  assert.equal(bob.identity.kind, "seed");
  assert.equal(h(bob.identity.ed25519_pub)[31] >> 7, 1, "vector should exercise sign bit 1");
  const spk = h(bob.signed_pre_key.pub);
  assert.equal(xeddsa.verifyEdwards(h(bob.identity.ed25519_pub), spk, h(bob.signed_pre_key.signature)), true);
  assert.equal(hex(xeddsa.edwardsToMontgomery(h(bob.identity.ed25519_pub))), bob.identity.curve25519_pub);
});

// --- ratchet constants (docs/TASKS.md table), checked independently of our module ---

const ROOT_INFO = { oldmemo: "WhisperRatchet", twomemo: "OMEMO Root Chain" };

for (const [ns, v] of Object.entries(conversations)) {
  test(`${ns}: every root and chain KDF step in the conversation matches`, () => {
    let steps = 0;
    for (const m of v.messages) {
      for (const t of [...m.encrypt.trace, ...m.decrypt.trace]) {
        if (t.step === "root_kdf") {
          const out = hkdf(sha256, h(t.dh_out), h(t.root_key), ROOT_INFO[ns], 64);
          assert.equal(hex(out), t.new_root_key + t.chain_key);
          steps++;
        } else if (t.step === "chain_kdf") {
          const ck = h(t.chain_key);
          assert.equal(hex(hmac(sha256, ck, Uint8Array.of(0x01))), t.message_key);
          assert.equal(hex(hmac(sha256, ck, Uint8Array.of(0x02))), t.next_chain_key);
          steps++;
        }
      }
    }
    assert.ok(steps > 20, `expected a full conversation's worth of KDF steps, got ${steps}`);
  });
}
