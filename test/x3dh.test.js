/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests for src/crypto/x3dh.js: known answers from the reference's first
 * message in each namespace (test/vectors/), for both the initiator and the
 * responder. twomemo starts from the bytes a real peer would see: Bob's
 * published bundle XML and Alice's key exchange in the <encrypted> XML.
 * oldmemo covers the key schedule only (see test/vectors.test.js), so its
 * inputs are built from the vector keys in their wire form.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "@noble/hashes/utils";
import * as keys from "../src/crypto/keys.js";
import * as pb from "../src/crypto/protobuf.js";
import * as x3dh from "../src/crypto/x3dh.js";
import * as xeddsa from "../src/crypto/xeddsa.js";
import { load, h, hex, b64, replay, identityOf } from "./helpers.js";

const vectors = { oldmemo: load("oldmemo"), twomemo: load("twomemo") };

/** Message 0's X3DH traces and the ephemeral key the initiator drew. */
function firstMessage(v) {
  const { encrypt, decrypt } = v.messages[0];
  return {
    active: encrypt.trace.find((t) => t.step === "x3dh_active"),
    passive: decrypt.trace.find((t) => t.step === "x3dh_passive"),
    // The last token_bytes draw in message 0's encrypt (docs/TASKS.md 2.6).
    ephemeralPrivateKey: h(encrypt.random.filter((r) => r.source === "token_bytes").at(-1).value),
  };
}

// --- known answers from the reference ---

test("twomemo: the initiator matches the reference, starting from Bob's bundle XML", () => {
  const v = vectors.twomemo;
  const { active, ephemeralPrivateKey } = firstMessage(v);
  const xml = v.bob.bundle_xml;
  const [, spkId, spk] = /<spk id="(\d+)">([^<]+)</.exec(xml);
  const preKeys = [...xml.matchAll(/<pk id="(\d+)">([^<]+)</g)].map(([, id, pub]) => ({
    id: Number(id),
    publicKey: keys.decodePublicKey("twomemo", b64(pub)),
  }));
  const bundle = {
    identityKey: keys.decodeIdentityKey("twomemo", b64(/<ik>([^<]+)</.exec(xml)[1])),
    signedPreKey: {
      id: Number(spkId),
      publicKey: keys.decodePublicKey("twomemo", b64(spk)),
      signature: b64(/<spks>([^<]+)</.exec(xml)[1]),
    },
    preKey: preKeys.find((k) => hex(k.publicKey) === active.pre_key_pub),
  };
  assert.equal(bundle.identityKey.ed25519[31] >> 7, 1, "vector should exercise sign bit 1");

  const random = replay(ephemeralPrivateKey);
  const alice = { privateKey: h(v.alice.identity.priv), publicKey: keys.identityPublicKey(h(v.alice.identity.priv)) };
  const out = x3dh.initiateHandshake("twomemo", alice, bundle, { random });
  assert.equal(random.remaining(), 0);
  assert.equal(hex(out.sharedSecret), active.shared_secret);
  assert.equal(hex(out.associatedData), active.associated_data);
  assert.equal(hex(out.ephemeralPublicKey), active.ephemeral_pub);
  assert.equal(out.signedPreKeyId, v.bob.signed_pre_key.id);
  assert.equal(out.preKeyId, bundle.preKey.id);
});

test("twomemo: the responder matches the reference, starting from Alice's key exchange on the wire", () => {
  const v = vectors.twomemo;
  const { passive } = firstMessage(v);
  const [, kexBase64] = /<key rid="\d+" kex="true">([^<]+)<\/key>/.exec(v.messages[0].xml);
  const kex = pb.decode(pb.twomemo.OMEMOKeyExchange, b64(kexBase64));
  assert.equal(kex.signedPreKeyId, v.bob.signed_pre_key.id);
  const preKey = v.bob.pre_keys.find((k) => k.id === kex.preKeyId);

  const out = x3dh.respondToHandshake(
    "twomemo",
    {
      identity: identityOf(v.bob),
      signedPreKey: { privateKey: h(v.bob.signed_pre_key.priv) },
      preKey: { privateKey: h(preKey.priv) },
    },
    {
      identityKey: keys.decodeIdentityKey("twomemo", kex.identityKey),
      ephemeralKey: keys.decodePublicKey("twomemo", kex.ephemeralKey),
    }
  );
  assert.equal(hex(out.sharedSecret), passive.shared_secret);
  assert.equal(hex(out.associatedData), passive.associated_data);
});

test("oldmemo: the initiator matches the reference, with the sign bit carried in the bundle signature", () => {
  const v = vectors.oldmemo;
  const { active, ephemeralPrivateKey } = firstMessage(v);
  const { bob } = v;
  // An oldmemo bundle publishes 0x05 || u; the Ed25519 sign bit rides in the
  // signature's top bit (see test/vectors.test.js).
  const signature = h(bob.signed_pre_key.signature);
  signature[63] |= h(bob.identity.ed25519_pub)[31] & 0x80;
  const preKey = bob.pre_keys.find((k) => k.pub === active.pre_key_pub);
  const bundle = {
    identityKey: keys.decodeIdentityKey("oldmemo", keys.encodeIdentityKey("oldmemo", identityOf(bob).publicKey)),
    signedPreKey: { id: bob.signed_pre_key.id, publicKey: h(bob.signed_pre_key.pub), signature },
    preKey: { id: preKey.id, publicKey: h(preKey.pub) },
  };

  const random = replay(ephemeralPrivateKey);
  const out = x3dh.initiateHandshake("oldmemo", identityOf(v.alice), bundle, { random });
  assert.equal(random.remaining(), 0);
  assert.equal(hex(out.sharedSecret), active.shared_secret);
  assert.equal(hex(out.associatedData), active.associated_data);
  assert.equal(hex(out.ephemeralPublicKey), active.ephemeral_pub);
  assert.equal(out.signedPreKeyId, bob.signed_pre_key.id);
  assert.equal(out.preKeyId, preKey.id);
});

test("oldmemo: the responder matches the reference", () => {
  const v = vectors.oldmemo;
  const { active, passive } = firstMessage(v);
  const preKey = v.bob.pre_keys.find((k) => k.pub === active.pre_key_pub);
  const out = x3dh.respondToHandshake(
    "oldmemo",
    {
      identity: identityOf(v.bob),
      signedPreKey: { privateKey: h(v.bob.signed_pre_key.priv) },
      preKey: { privateKey: h(preKey.priv) },
    },
    {
      identityKey: keys.decodeIdentityKey("oldmemo", keys.encodeIdentityKey("oldmemo", identityOf(v.alice).publicKey)),
      ephemeralKey: keys.decodePublicKey("oldmemo", keys.encodePublicKey("oldmemo", h(active.ephemeral_pub))),
    }
  );
  assert.equal(hex(out.sharedSecret), passive.shared_secret);
  assert.equal(hex(out.associatedData), passive.associated_data);
});

// --- round trips with fresh keys ---

function makeParty(namespace) {
  const identity = keys.generateIdentityKeyPair();
  return {
    identity,
    signedPreKey: keys.generateSignedPreKey(identity.privateKey, 1, namespace),
    preKey: keys.generatePreKeys(1, 1)[0],
  };
}

/** A party's bundle as a peer sees it: encoded for the wire, then decoded. */
function bundleOf(namespace, party, { withPreKey = true } = {}) {
  const { identity, signedPreKey, preKey } = party;
  const wire = (key) => keys.decodePublicKey(namespace, keys.encodePublicKey(namespace, key));
  return {
    identityKey: keys.decodeIdentityKey(namespace, keys.encodeIdentityKey(namespace, identity.publicKey)),
    signedPreKey: { id: signedPreKey.id, publicKey: wire(signedPreKey.publicKey), signature: signedPreKey.signature },
    ...(withPreKey ? { preKey: { id: preKey.id, publicKey: wire(preKey.publicKey) } } : {}),
  };
}

/** Bob's side of Alice's handshake, from what her key exchange carries. */
function respond(namespace, bob, alice, initiated, { withPreKey = true } = {}) {
  return x3dh.respondToHandshake(
    namespace,
    { identity: bob.identity, signedPreKey: bob.signedPreKey, ...(withPreKey ? { preKey: bob.preKey } : {}) },
    {
      identityKey: keys.decodeIdentityKey(namespace, keys.encodeIdentityKey(namespace, alice.identity.publicKey)),
      ephemeralKey: keys.decodePublicKey(namespace, keys.encodePublicKey(namespace, initiated.ephemeralPublicKey)),
    }
  );
}

for (const ns of keys.NAMESPACES) {
  test(`${ns}: both sides derive the same secret and associated data, with or without a pre key`, () => {
    const alice = makeParty(ns);
    const bob = makeParty(ns);
    const expectedAd = hex(Buffer.concat([
      keys.encodeIdentityKey(ns, alice.identity.publicKey),
      keys.encodeIdentityKey(ns, bob.identity.publicKey),
    ]));

    const secrets = new Set();
    for (const withPreKey of [true, false]) {
      const initiated = x3dh.initiateHandshake(ns, alice.identity, bundleOf(ns, bob, { withPreKey }));
      const responded = respond(ns, bob, alice, initiated, { withPreKey });
      assert.equal(initiated.sharedSecret.length, 32);
      assert.deepEqual(responded.sharedSecret, initiated.sharedSecret);
      assert.equal(hex(initiated.associatedData), expectedAd);
      assert.equal(hex(responded.associatedData), expectedAd);
      assert.equal(initiated.preKeyId, withPreKey ? bob.preKey.id : null);
      secrets.add(hex(initiated.sharedSecret));
    }
    assert.equal(secrets.size, 2);
  });

  test(`${ns}: a responder that leaves out the pre key the initiator used gets a different secret`, () => {
    const alice = makeParty(ns);
    const bob = makeParty(ns);
    const initiated = x3dh.initiateHandshake(ns, alice.identity, bundleOf(ns, bob));
    const responded = respond(ns, bob, alice, initiated, { withPreKey: false });
    assert.notDeepEqual(responded.sharedSecret, initiated.sharedSecret);
  });

  test(`${ns}: a bundle whose signed prekey doesn't verify is rejected before any randomness is drawn`, () => {
    const alice = makeParty(ns);
    const bob = makeParty(ns);
    const mallory = makeParty(ns);
    const other = ns === "oldmemo" ? "twomemo" : "oldmemo";
    const forged = [
      (b) => { b.signedPreKey.signature[5] ^= 1; },
      // Mallory's key signed by Bob's identity: a swapped signed prekey.
      (b) => { b.signedPreKey.publicKey = mallory.signedPreKey.publicKey; },
      // The right key, signed in the other namespace's encoding.
      (b) => {
        const message = keys.encodePublicKey(other, bob.signedPreKey.publicKey);
        b.signedPreKey.signature = xeddsa.sign(bob.identity.privateKey, message, randomBytes(64));
      },
      (b) => { b.identityKey = bundleOf(ns, mallory).identityKey; },
    ];
    for (const forge of forged) {
      const bundle = bundleOf(ns, bob);
      bundle.signedPreKey.signature = Uint8Array.from(bundle.signedPreKey.signature);
      forge(bundle);
      const random = replay();
      assert.throws(() => x3dh.initiateHandshake(ns, alice.identity, bundle, { random }), /does not verify/);
    }
  });

  test(`${ns}: low-order keys are rejected`, () => {
    const alice = makeParty(ns);
    const bob = makeParty(ns);
    const lowOrder = new Uint8Array(32); // u = 0: every DH with it is all zeros
    const bundle = bundleOf(ns, bob);
    bundle.preKey.publicKey = lowOrder;
    assert.throws(() => x3dh.initiateHandshake(ns, alice.identity, bundle));

    const initiated = x3dh.initiateHandshake(ns, alice.identity, bundleOf(ns, bob));
    assert.throws(() => respond(ns, bob, alice, { ...initiated, ephemeralPublicKey: lowOrder }));
  });
}

test("twomemo: a bundle identity key without its Ed25519 form is rejected", () => {
  const alice = makeParty("twomemo");
  const bundle = bundleOf("twomemo", makeParty("twomemo"));
  bundle.identityKey = { curve25519: bundle.identityKey.curve25519, ed25519: null };
  assert.throws(() => x3dh.initiateHandshake("twomemo", alice.identity, bundle), /does not verify/);
});

test("the two namespaces derive different secrets from the same keys", () => {
  // Same identity keys, signed prekey, pre key and ephemeral key; only the
  // HKDF info and the identity key encoding differ.
  const alice = makeParty("twomemo");
  const bob = makeParty("twomemo");
  const signedPreKeyPrivate = randomBytes(32);
  const ephemeral = randomBytes(32);
  const initiate = (ns) => {
    const signedPreKey = keys.generateSignedPreKey(bob.identity.privateKey, 1, ns, {
      random: replay(signedPreKeyPrivate, randomBytes(64)),
    });
    const bundle = bundleOf(ns, { ...bob, signedPreKey });
    return x3dh.initiateHandshake(ns, alice.identity, bundle, { random: replay(ephemeral) });
  };
  const old = initiate("oldmemo");
  const two = initiate("twomemo");
  assert.deepEqual(old.ephemeralPublicKey, two.ephemeralPublicKey);
  assert.notDeepEqual(old.sharedSecret, two.sharedSecret);
  assert.notDeepEqual(old.associatedData, two.associatedData);
});

test("an unknown namespace is rejected by name", () => {
  const alice = makeParty("twomemo");
  const bob = makeParty("twomemo");
  assert.throws(() => x3dh.initiateHandshake("omemo3", alice.identity, bundleOf("twomemo", bob)), /Unknown OMEMO namespace/);
  assert.throws(
    () => x3dh.respondToHandshake("omemo3", bob, { identityKey: alice.identity.publicKey, ephemeralKey: bob.preKey.publicKey }),
    /Unknown OMEMO namespace/
  );
});
