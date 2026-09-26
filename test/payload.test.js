/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests for src/crypto/payload.js. twomemo is checked byte for byte against
 * python-twomemo's payloads (test/vectors/twomemo.json; the reference
 * encrypts the raw text, not an envelope). oldmemo has no permissive
 * reference, so its AES-128-GCM is checked against a published GCM test
 * vector, and its layout (key || tag in the key material, tag left out of
 * the payload) gets confirmed against real clients in task 4.12.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "@noble/hashes/utils";
import { gcm } from "@noble/ciphers/aes";
import * as payload from "../src/crypto/payload.js";
import { load, h, hex, b64, text, replay } from "./helpers.js";

const v = load("twomemo");

// --- twomemo, against the reference ---

test("twomemo: every payload matches the reference byte for byte, and decrypts", () => {
  let checked = 0;
  for (const m of v.messages.filter((m) => !m.empty)) {
    // The payload key is the first token_bytes draw of the message's encrypt.
    const key = m.encrypt.random.find((r) => r.source === "token_bytes");
    const random = replay(h(key.value));
    const out = payload.encrypt("twomemo", text(m.plaintext), { random });
    assert.equal(random.remaining(), 0);
    assert.equal(hex(out.keyMaterial), m.payload_key_material, `message ${m.index}: key material`);
    assert.equal(hex(out.ciphertext), m.payload_ciphertext, `message ${m.index}: ciphertext`);
    assert.equal(out.iv, undefined);

    // What a receiver sees: <payload> from the XML, key material from the ratchet.
    const onWire = b64(/<payload>([^<]+)<\/payload>/.exec(m.xml)[1]);
    assert.equal(hex(onWire), m.payload_ciphertext);
    const plain = payload.decrypt("twomemo", { keyMaterial: h(m.payload_key_material), ciphertext: onWire });
    assert.equal(new TextDecoder().decode(plain), m.plaintext);
    checked++;
  }
  assert.equal(checked, 8);
});

test("twomemo: an empty message sends no payload and ratchets 32 zero bytes, as the reference does", () => {
  const empty = v.messages.find((m) => m.empty);
  assert.doesNotMatch(empty.xml, /<payload>/);
  assert.equal(empty.payload_ciphertext, "");
  const ratcheted = empty.encrypt.trace.find((t) => t.step === "aead_encrypt").plaintext;
  assert.equal(empty.payload_key_material, ratcheted);
  assert.equal(hex(payload.emptyKeyMaterial("twomemo")), ratcheted);
});

test("twomemo: a flipped bit in the key material or ciphertext is rejected", () => {
  const out = payload.encrypt("twomemo", text("secret"));
  for (const field of ["keyMaterial", "ciphertext"]) {
    for (let i = 0; i < out[field].length; i++) {
      const bad = { ...out, [field]: Uint8Array.from(out[field]) };
      bad[field][i] ^= 0x80;
      assert.throws(() => payload.decrypt("twomemo", bad), undefined, `${field} byte ${i}`);
    }
  }
  assert.throws(() => payload.decrypt("twomemo", { ...out, keyMaterial: out.keyMaterial.subarray(0, 32) }), /48 bytes/);
});

// --- oldmemo ---

test("oldmemo: AES-128-GCM matches a published test vector, split into key || tag and payload", () => {
  // McGrew & Viega, "The Galois/Counter Mode of Operation", test case 3.
  const key = h("feffe9928665731c6d6a8f9467308308");
  const iv = h("cafebabefacedbaddecaf888");
  const plain = h(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72" +
      "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
  );
  const cipher =
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e" +
    "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985";
  const tag = "4d5c2af327cd64a62cf35abd2ba6fab4";

  const random = replay(key, iv);
  const out = payload.encrypt("oldmemo", plain, { random });
  assert.equal(random.remaining(), 0);
  assert.equal(hex(out.ciphertext), cipher);
  assert.equal(hex(out.keyMaterial), hex(key) + tag);
  assert.equal(hex(out.iv), hex(iv));
  assert.deepEqual(payload.decrypt("oldmemo", out), plain);
});

test("oldmemo: round trip with fresh keys, and tampering is rejected", () => {
  const body = text("Grüße, 👋");
  const out = payload.encrypt("oldmemo", body);
  assert.equal(out.keyMaterial.length, 32);
  assert.equal(out.iv.length, 12);
  assert.equal(out.ciphertext.length, body.length, "GCM adds no padding and the tag travels in the key material");
  assert.deepEqual(payload.decrypt("oldmemo", out), body);
  for (const field of ["keyMaterial", "ciphertext", "iv"]) {
    const bad = { ...out, [field]: Uint8Array.from(out[field]) };
    bad[field][0] ^= 1;
    assert.throws(() => payload.decrypt("oldmemo", bad), undefined, field);
  }
});

test("oldmemo: accepts the legacy forms older clients send (16-byte IV, tag in the payload)", () => {
  const key = randomBytes(16);
  const body = text("from an old Conversations");

  const iv16 = randomBytes(16);
  const sealed16 = gcm(key, iv16).encrypt(body);
  const tag16 = sealed16.subarray(body.length);
  assert.deepEqual(payload.decrypt("oldmemo", {
    keyMaterial: Uint8Array.from([...key, ...tag16]),
    ciphertext: sealed16.subarray(0, body.length),
    iv: iv16,
  }), body);

  const iv12 = randomBytes(12);
  const sealed = gcm(key, iv12).encrypt(body);
  assert.deepEqual(payload.decrypt("oldmemo", { keyMaterial: key, ciphertext: sealed, iv: iv12 }), body);
});

test("oldmemo: wrong-sized key material or IV is rejected", () => {
  const out = payload.encrypt("oldmemo", text("x"));
  assert.throws(() => payload.decrypt("oldmemo", { ...out, keyMaterial: out.keyMaterial.subarray(0, 24) }), /32 \(or legacy 16\)/);
  assert.throws(() => payload.decrypt("oldmemo", { ...out, iv: randomBytes(8) }), /12 or 16/);
  assert.throws(() => payload.decrypt("oldmemo", { ...out, iv: undefined }), /IV must be a Uint8Array/);
});

test("oldmemo: an empty message ratchets 16 random bytes", () => {
  const draw = randomBytes(16);
  assert.deepEqual(payload.emptyKeyMaterial("oldmemo", { random: replay(draw) }), draw);
  assert.equal(payload.emptyKeyMaterial("oldmemo").length, 16);
});

test("the plaintext must be bytes, and random draws the right size", () => {
  assert.throws(() => payload.encrypt("twomemo", "text"), /must be a Uint8Array/);
  assert.throws(() => payload.encrypt("twomemo", text("x"), { random: () => new Uint8Array(16) }), /payload key must be 32 bytes/);
  assert.throws(() => payload.encrypt("oldmemo", text("x"), { random: (n) => new Uint8Array(n + 1) }), /payload key must be 16 bytes/);
  assert.throws(() => payload.emptyKeyMaterial("oldmemo", { random: () => new Uint8Array(0) }), /16 bytes/);
});

test("an unknown namespace is rejected by name", () => {
  assert.throws(() => payload.encrypt("omemo3", text("x")), /Unknown OMEMO namespace "omemo3"/);
  assert.throws(() => payload.decrypt("constructor", {}), /Unknown OMEMO namespace/);
  assert.throws(() => payload.emptyKeyMaterial("omemo3"), /Unknown OMEMO namespace/);
});
