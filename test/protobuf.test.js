/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests for src/crypto/protobuf.js. twomemo layouts are checked against
 * python-twomemo's bytes in test/vectors/twomemo.json. oldmemo has no
 * permissively licensed reference (see tools/gen-vectors/README.md), so its
 * layouts are checked with hand-encoded bytes here and against real clients
 * later (docs/TASKS.md 4.12).
 */

import test from "node:test";
import assert from "node:assert/strict";
import * as pb from "../src/crypto/protobuf.js";
import { load, h, hex, b64 } from "./helpers.js";

const v = load("twomemo");

/** The <key> elements of a message's XML: [{ rid, kex, bytes }]. */
function keyElements(xml) {
  return [...xml.matchAll(/<key rid="(\d+)"( kex="true")?>([^<]+)<\/key>/g)].map((m) => ({
    rid: Number(m[1]),
    kex: Boolean(m[2]),
    bytes: b64(m[3]),
  }));
}

// --- twomemo, against the reference ---

test("twomemo: every ratchet message decodes to its header and re-encodes byte for byte", () => {
  for (const m of v.messages) {
    const bytes = h(m.ratchet_message);
    const authenticated = pb.decode(pb.twomemo.OMEMOAuthenticatedMessage, bytes);
    assert.equal(authenticated.mac.length, 16);
    const message = pb.decode(pb.twomemo.OMEMOMessage, authenticated.message);
    assert.equal(message.n, m.header.n);
    assert.equal(message.pn, m.header.pn);
    assert.equal(hex(message.dhPub), m.header.dh_pub);
    assert.equal(message.ciphertext.length % 16, 0, "AES-CBC output");

    assert.deepEqual(pb.encode(pb.twomemo.OMEMOMessage, message), authenticated.message);
    assert.deepEqual(pb.encode(pb.twomemo.OMEMOAuthenticatedMessage, authenticated), bytes);
  }
});

test("twomemo: the header the MAC covers is OMEMOMessage without its ciphertext", () => {
  let checked = 0;
  for (const m of v.messages) {
    const step = m.encrypt.trace.find((t) => t.step === "aead_encrypt");
    const header = pb.encode(pb.twomemo.OMEMOMessage, { n: m.header.n, pn: m.header.pn, dhPub: h(m.header.dh_pub) });
    // associated data = identity keys (2 x 32 bytes) || encoded header
    assert.equal(step.associated_data.slice(128), hex(header));
    checked++;
  }
  assert.equal(checked, v.messages.length);
});

test("twomemo: key exchanges in the XML decode to the X3DH header and re-encode byte for byte", () => {
  const x3dh = v.messages[0].encrypt.trace.find((t) => t.step === "x3dh_active");
  const usedPreKey = v.bob.pre_keys.find((k) => k.pub === x3dh.pre_key_pub);
  let kexCount = 0;
  for (const m of v.messages) {
    const [key] = keyElements(m.xml);
    assert.equal(key.kex, m.key_exchange);
    if (!key.kex) {
      assert.equal(hex(key.bytes), m.ratchet_message, "a plain <key> holds the OMEMOAuthenticatedMessage");
      continue;
    }
    kexCount++;
    const kex = pb.decode(pb.twomemo.OMEMOKeyExchange, key.bytes);
    assert.equal(kex.preKeyId, usedPreKey.id);
    assert.equal(kex.signedPreKeyId, v.bob.signed_pre_key.id);
    assert.equal(hex(kex.identityKey), v.alice.identity.ed25519_pub);
    assert.equal(hex(kex.ephemeralKey), x3dh.ephemeral_pub);
    assert.equal(hex(pb.encode(pb.twomemo.OMEMOAuthenticatedMessage, kex.message)), m.ratchet_message);
    assert.deepEqual(pb.encode(pb.twomemo.OMEMOKeyExchange, kex), key.bytes);
  }
  assert.equal(kexCount, 2, "the first two messages carry the key exchange");
});

// --- hand-encoded bytes ---

test("encodes known bytes: field order, multi-byte varints, and zero-valued required fields", () => {
  // twomemo OMEMOMessage: n=1, pn=300, dhPub=010203, ciphertext=09
  const two = pb.encode(pb.twomemo.OMEMOMessage, { n: 1, pn: 300, dhPub: h("010203"), ciphertext: h("09") });
  assert.equal(hex(two), "0801" + "10ac02" + "1a03010203" + "220109");

  // oldmemo OMEMOMessage (libsignal SignalMessage): ratchetKey=1, counter=2, previousCounter=3.
  // counter 0 is still written, as proto2 does for set fields.
  const old = pb.encode(pb.oldmemo.OMEMOMessage, { dhPub: h("05aa"), n: 0, pn: 5 });
  assert.equal(hex(old), "0a0205aa" + "1000" + "1805");
  assert.deepEqual(pb.decode(pb.oldmemo.OMEMOMessage, old), { dhPub: h("05aa"), n: 0, pn: 5 });
});

test("oldmemo key exchange: libsignal's field numbers, with and without a registration id", () => {
  const value = { preKeyId: 7, ephemeralKey: h("05bb"), identityKey: h("05cc"), message: h("33dd"), signedPreKeyId: 2 };
  const bytes = pb.encode(pb.oldmemo.OMEMOKeyExchange, value);
  // preKeyId=1, baseKey=2, identityKey=3, message=4, signedPreKeyId=6
  assert.equal(hex(bytes), "0807" + "120205bb" + "1a0205cc" + "220233dd" + "3002");
  assert.deepEqual(pb.decode(pb.oldmemo.OMEMOKeyExchange, bytes), value);

  // What libsignal clients send includes registrationId=5.
  const withRegistration = h("0807" + "120205bb" + "1a0205cc" + "220233dd" + "28b960" + "3002");
  assert.deepEqual(pb.decode(pb.oldmemo.OMEMOKeyExchange, withRegistration), { ...value, registrationId: 12345 });
  assert.deepEqual(pb.encode(pb.oldmemo.OMEMOKeyExchange, { ...value, registrationId: 12345 }), withRegistration);
});

test("uint32 limits round-trip", () => {
  const bytes = pb.encode(pb.twomemo.OMEMOMessage, { n: 0xffffffff, pn: 0, dhPub: new Uint8Array(0) });
  assert.equal(hex(bytes), "08ffffffff0f" + "1000" + "1a00");
  assert.deepEqual(pb.decode(pb.twomemo.OMEMOMessage, bytes), { n: 0xffffffff, pn: 0, dhPub: new Uint8Array(0) });
});

test("decoding accepts fields in any order and skips unknown fields of every wire type", () => {
  const bytes = h(
    "1a03010203" + // dhPub (3)
      "4801" + // unknown 9, varint
      "510102030405060708" + // unknown 10, fixed64
      "5a0100" + // unknown 11, length-delimited
      "6501020304" + // unknown 12, fixed32
      "1005" + // pn (2)
      "0807" // n (1)
  );
  assert.deepEqual(pb.decode(pb.twomemo.OMEMOMessage, bytes), { n: 7, pn: 5, dhPub: h("010203") });
});

test("decoding rejects malformed input", () => {
  const M = pb.twomemo.OMEMOMessage;
  const ok = "0801" + "1002" + "1a0101";
  const cases = {
    "missing required field": ["0801" + "1002", /required but missing/],
    "field sent twice": [ok + "0803", /more than once/],
    "wrong wire type": ["0d01020304" + "1002" + "1a0101", /wire type/],
    "truncated varint": ["08ff", /Truncated protobuf varint/],
    "overlong varint": ["08" + "ff".repeat(10) + "01", /longer than 10 bytes/],
    "10-byte varint over uint32": ["08" + "ff".repeat(9) + "01" + "1002" + "1a0101", /uint32/],
    "uint32 overflow": ["0880808080101002" + "1a0101", /uint32/],
    "length past the end": ["0801" + "1002" + "1a05aa", /Truncated protobuf length-delimited/],
    "truncated fixed64": [ok + "51010203", /Truncated protobuf fixed-width/],
    "group wire type": [ok + "4b", /Unsupported protobuf wire type 3/],
    "field number 0": ["0001" + ok, /field number 0/],
  };
  for (const [what, [bytes, error]] of Object.entries(cases)) {
    assert.throws(() => pb.decode(M, h(bytes)), error, what);
  }
});

test("encoding rejects missing and mistyped values", () => {
  const M = pb.twomemo.OMEMOMessage;
  assert.throws(() => pb.encode(M, { n: 1, dhPub: h("01") }), /pn is required/);
  assert.throws(() => pb.encode(M, { n: -1, pn: 0, dhPub: h("01") }), /uint32/);
  assert.throws(() => pb.encode(M, { n: 2 ** 32, pn: 0, dhPub: h("01") }), /uint32/);
  assert.throws(() => pb.encode(M, { n: 1.5, pn: 0, dhPub: h("01") }), /uint32/);
  assert.throws(() => pb.encode(M, { n: 1, pn: 0, dhPub: [1, 2] }), /Uint8Array/);
  assert.throws(() => pb.encode(pb.twomemo.OMEMOKeyExchange, {
    preKeyId: 1, signedPreKeyId: 1, identityKey: h("01"), ephemeralKey: h("02"), message: { mac: h("03") },
  }), /OMEMOAuthenticatedMessage.message is required/);
});

test("decoded byte fields are copies, not views into the input", () => {
  const input = pb.encode(pb.twomemo.OMEMOMessage, { n: 1, pn: 2, dhPub: h("aabbcc") });
  const decoded = pb.decode(pb.twomemo.OMEMOMessage, input);
  input.fill(0);
  assert.equal(hex(decoded.dhPub), "aabbcc");
});
