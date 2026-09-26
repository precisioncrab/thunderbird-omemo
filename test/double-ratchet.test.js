/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests for src/crypto/double-ratchet.js and the key exchange framing in
 * src/crypto/x3dh.js.
 *
 * Known answers: both vector conversations (test/vectors/) are replayed
 * through our modules in the reference's delivery order, feeding in its
 * random draws. twomemo must match python-twomemo's ratchet messages and
 * key exchanges byte for byte. oldmemo's vectors hold no ciphertexts (the
 * reference framing isn't oldmemo's), so for oldmemo the check is that our
 * headers carry the reference's ratchet keys and counters, and that each of
 * our messages opens under the reference's message key and associated data.
 *
 * The rest uses fresh keys: reordering, a late message from a previous
 * chain, replays, tampering, and limits.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { hkdf } from "@noble/hashes/hkdf";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";
import { cbc } from "@noble/ciphers/aes";
import * as dr from "../src/crypto/double-ratchet.js";
import * as keys from "../src/crypto/keys.js";
import * as pb from "../src/crypto/protobuf.js";
import * as x3dh from "../src/crypto/x3dh.js";
import { load, h, hex, b64, text, replay, identityOf } from "./helpers.js";

const vectors = { oldmemo: load("oldmemo"), twomemo: load("twomemo") };

const ratchetDraws = (draws) => draws.filter((r) => r.source === "ratchet_priv").map((r) => h(r.value));

/** Bob's bundle as Alice decodes it from the wire. */
function vectorBundle(ns, bob, preKeyPub) {
  const signature = h(bob.signed_pre_key.signature);
  if (ns === "oldmemo") {
    // oldmemo bundles carry the Ed25519 sign bit in the signature (test/vectors.test.js).
    signature[63] |= h(bob.identity.ed25519_pub)[31] & 0x80;
  }
  const preKey = bob.pre_keys.find((k) => k.pub === preKeyPub);
  return {
    identityKey: keys.decodeIdentityKey(ns, keys.encodeIdentityKey(ns, identityOf(bob).publicKey)),
    signedPreKey: { id: bob.signed_pre_key.id, publicKey: h(bob.signed_pre_key.pub), signature },
    preKey: { id: preKey.id, publicKey: h(preKey.pub) },
  };
}

/** What the ratchet encrypts for message m: the payload key material. */
function ratchetPlaintext(ns, m) {
  return ns === "twomemo" ? h(m.encrypt.trace.find((t) => t.step === "aead_encrypt").plaintext) : h(m.key_material);
}

/** twomemo: the bytes of the <key> element in message m's XML. */
function xmlKey(m) {
  return b64(/<key rid="\d+"(?: kex="true")?>([^<]+)<\/key>/.exec(m.xml)[1]);
}

/**
 * oldmemo: opens one of our framed messages with the reference's message
 * key and associated data, independently of double-ratchet.js.
 */
function openOldmemo(framed, messageKey, associatedData) {
  const km = hkdf(sha256, messageKey, new Uint8Array(32), "WhisperMessageKeys", 80);
  const body = framed.subarray(0, framed.length - 8);
  const mac = hmac(sha256, km.subarray(32, 64), Uint8Array.from([...associatedData, ...body])).subarray(0, 8);
  assert.equal(hex(framed.subarray(framed.length - 8)), hex(mac), "MAC under the reference's key and AD");
  const message = pb.decode(pb.oldmemo.OMEMOMessage, body.subarray(1));
  return cbc(km.subarray(0, 32), km.subarray(64, 80)).decrypt(message.ciphertext);
}

// --- known answers: the reference conversations ---

/** A session saved as JSON text and loaded back, as the key store will. */
const reload = (state) => dr.deserializeState(JSON.parse(JSON.stringify(dr.serializeState(state))));

/**
 * Replays the reference conversation for one namespace. With `persist`,
 * every session is saved and reloaded before each step.
 */
function replayConversation(ns, { persist }) {
  const v = vectors[ns];
  const alice = identityOf(v.alice);
  const bob = identityOf(v.bob);
  const sessions = {};
  const sent = new Map();
  let aliceHasReply = false;
  let kexChecked = 0;

  for (const [action, index] of v.timeline) {
    if (persist) {
      for (const who of ["alice", "bob"]) {
        if (sessions[who]) {
          sessions[who] = reload(sessions[who]);
        }
      }
    }
    const m = v.messages[index];
    assert.equal(m.index, index);
    const sender = m.from;

    if (action === "send") {
      if (!sessions[sender]) {
        assert.equal(sender, "alice");
        const draws = m.encrypt.random;
        const active = m.encrypt.trace.find((t) => t.step === "x3dh_active");
        const ephemeral = h(draws.filter((r) => r.source === "token_bytes").at(-1).value);
        const bundle = vectorBundle(ns, v.bob, active.pre_key_pub);
        const handshake = x3dh.initiateHandshake(ns, alice, bundle, { random: replay(ephemeral) });
        assert.equal(hex(handshake.sharedSecret), active.shared_secret);
        const random = replay(...ratchetDraws(draws));
        sessions.alice = dr.initSender(ns, handshake, bundle.signedPreKey.publicKey, { random });
        assert.equal(random.remaining(), 0);
        sessions.aliceKex = handshake;
      } else {
        assert.deepEqual(ratchetDraws(m.encrypt.random), [], "only the first send draws a ratchet key");
      }

      let framed = dr.encrypt(sessions[sender], ratchetPlaintext(ns, m));
      const header = dr.PROFILES[ns].parse(framed).header;
      assert.equal(hex(header.dhPublicKey), m.header.dh_pub, `message ${index}: ratchet key`);
      assert.equal(header.n, m.header.n, `message ${index}: n`);

      if (ns === "twomemo") {
        assert.equal(header.pn, m.header.pn, `message ${index}: pn`);
        assert.equal(hex(framed), m.ratchet_message, `message ${index}: bytes`);
      } else {
        // libsignal's pn: the previous chain's last index (see PROFILES).
        assert.equal(header.pn, Math.max(m.header.pn - 1, 0), `message ${index}: pn`);
        const chain = m.encrypt.trace.filter((t) => t.step === "chain_kdf").at(-1);
        assert.deepEqual(openOldmemo(framed, h(chain.message_key), h(m.associated_data)), ratchetPlaintext(ns, m));
      }

      // Until Bob replies, Alice wraps every message in the key exchange.
      const wantKex = sender === "alice" && !aliceHasReply;
      assert.equal(m.key_exchange, wantKex, `message ${index}: key exchange`);
      if (wantKex) {
        const hs = sessions.aliceKex;
        framed = x3dh.encodeKeyExchange(ns, {
          preKeyId: hs.preKeyId,
          signedPreKeyId: hs.signedPreKeyId,
          identityKey: alice.publicKey,
          ephemeralKey: hs.ephemeralPublicKey,
          message: framed,
        });
        if (ns === "twomemo") {
          assert.equal(hex(framed), hex(xmlKey(m)), `message ${index}: key exchange bytes`);
          kexChecked++;
        }
      } else if (ns === "twomemo") {
        assert.equal(hex(xmlKey(m)), m.ratchet_message);
      }
      sent.set(index, { framed, kex: wantKex });
      continue;
    }

    // deliver
    const receiver = sender === "alice" ? "bob" : "alice";
    let { framed } = sent.get(index);
    if (sent.get(index).kex) {
      const kex = x3dh.decodeKeyExchange(ns, framed);
      if (!sessions.bob) {
        const preKey = v.bob.pre_keys.find((k) => k.id === kex.preKeyId);
        const handshake = x3dh.respondToHandshake(
          ns,
          { identity: bob, signedPreKey: { privateKey: h(v.bob.signed_pre_key.priv) }, preKey: { privateKey: h(preKey.priv) } },
          { identityKey: kex.identityKey, ephemeralKey: kex.ephemeralKey }
        );
        assert.equal(kex.signedPreKeyId, v.bob.signed_pre_key.id);
        sessions.bob = dr.initReceiver(ns, handshake, {
          privateKey: h(v.bob.signed_pre_key.priv),
          publicKey: h(v.bob.signed_pre_key.pub),
        });
      }
      framed = kex.message;
    }
    const random = replay(...ratchetDraws(m.decrypt.random));
    const plaintext = dr.decrypt(sessions[receiver], framed, { random });
    assert.equal(random.remaining(), 0, `message ${index}: every ratchet draw used`);
    assert.deepEqual(plaintext, ratchetPlaintext(ns, m), `message ${index}: plaintext`);
    if (receiver === "alice") {
      aliceHasReply = true;
    }
  }

  assert.equal(sent.size, v.messages.length);
  if (ns === "twomemo") {
    assert.equal(kexChecked, 2);
  }
  // Message 6 arrived after 7, so its key was skipped and then used up.
  assert.equal(sessions.alice.skippedMessageKeys.size, 0);
  assert.equal(sessions.bob.skippedMessageKeys.size, 0);
}

for (const ns of keys.NAMESPACES) {
  test(`${ns}: the reference conversation replays through our modules`, () => {
    replayConversation(ns, { persist: false });
  });

  test(`${ns}: the reference conversation replays with sessions saved and reloaded before every step`, () => {
    replayConversation(ns, { persist: true });
  });
}

test("oldmemo: the associated data puts the sender first, as in the reference", () => {
  const v = vectors.oldmemo;
  const [aliceIk, bobIk] = [identityOf(v.alice), identityOf(v.bob)].map((p) => hex(keys.encodeIdentityKey("oldmemo", p.publicKey)));
  for (const m of v.messages) {
    assert.equal(m.associated_data, m.from === "alice" ? aliceIk + bobIk : bobIk + aliceIk);
  }
});

// --- fresh keys ---

function makeParty(ns) {
  const identity = keys.generateIdentityKeyPair();
  return {
    identity,
    signedPreKey: keys.generateSignedPreKey(identity.privateKey, 1, ns),
    preKey: keys.generatePreKeys(1, 1)[0],
  };
}

/** A fresh Alice/Bob pair, with Bob's session built from Alice's key exchange. */
function startSession(ns) {
  const alice = makeParty(ns);
  const bob = makeParty(ns);
  const handshake = x3dh.initiateHandshake(ns, alice.identity, {
    identityKey: keys.decodeIdentityKey(ns, keys.encodeIdentityKey(ns, bob.identity.publicKey)),
    signedPreKey: bob.signedPreKey,
    preKey: bob.preKey,
  });
  const aliceState = dr.initSender(ns, handshake, bob.signedPreKey.publicKey);
  const first = x3dh.encodeKeyExchange(ns, {
    preKeyId: handshake.preKeyId,
    signedPreKeyId: handshake.signedPreKeyId,
    identityKey: alice.identity.publicKey,
    ephemeralKey: handshake.ephemeralPublicKey,
    message: dr.encrypt(aliceState, text("hello")),
  });

  const kex = x3dh.decodeKeyExchange(ns, first);
  assert.equal(kex.preKeyId, bob.preKey.id);
  const bobHandshake = x3dh.respondToHandshake(
    ns,
    { identity: bob.identity, signedPreKey: bob.signedPreKey, preKey: bob.preKey },
    { identityKey: kex.identityKey, ephemeralKey: kex.ephemeralKey }
  );
  const bobState = dr.initReceiver(ns, bobHandshake, bob.signedPreKey);
  assert.deepEqual(dr.decrypt(bobState, kex.message), text("hello"));
  return { alice: aliceState, bob: bobState };
}

const snapshot = (state) => JSON.stringify({ ...state, skippedMessageKeys: [...state.skippedMessageKeys] },
  (_, value) => (value instanceof Uint8Array ? hex(value) : value));

for (const ns of keys.NAMESPACES) {
  test(`${ns}: a conversation with ratchet steps both ways`, () => {
    const s = startSession(ns);
    for (let round = 0; round < 4; round++) {
      for (let i = 0; i < 3; i++) {
        assert.deepEqual(dr.decrypt(s.alice, dr.encrypt(s.bob, text(`b${round}.${i}`))), text(`b${round}.${i}`));
      }
      assert.deepEqual(dr.decrypt(s.bob, dr.encrypt(s.alice, text(`a${round}`))), text(`a${round}`));
    }
    assert.equal(s.alice.skippedMessageKeys.size, 0);
  });

  test(`${ns}: out-of-order delivery within a chain (3, 1, 2)`, () => {
    const s = startSession(ns);
    const msgs = [1, 2, 3].map((i) => dr.encrypt(s.alice, text(`m${i}`)));
    for (const i of [2, 0, 1]) {
      assert.deepEqual(dr.decrypt(s.bob, msgs[i]), text(`m${i + 1}`));
    }
    assert.equal(s.bob.skippedMessageKeys.size, 0);
  });

  test(`${ns}: a late message from the sender's previous chain still decrypts`, () => {
    const s = startSession(ns);
    const a1 = dr.encrypt(s.alice, text("a1"));
    const a2 = dr.encrypt(s.alice, text("a2")); // held back
    dr.decrypt(s.bob, a1);
    dr.decrypt(s.alice, dr.encrypt(s.bob, text("reply"))); // Alice ratchets
    const a3 = dr.encrypt(s.alice, text("a3")); // new chain; pn covers a2
    assert.deepEqual(dr.decrypt(s.bob, a3), text("a3"));
    assert.deepEqual(dr.decrypt(s.bob, a2), text("a2"));
  });

  test(`${ns}: a replayed message is rejected`, () => {
    const s = startSession(ns);
    const m = dr.encrypt(s.alice, text("once"));
    dr.decrypt(s.bob, m);
    assert.throws(() => dr.decrypt(s.bob, m), /Duplicate|authentication/);
    // The same for a message that was delivered from the skipped keys.
    const [x, y] = [dr.encrypt(s.alice, text("x")), dr.encrypt(s.alice, text("y"))];
    dr.decrypt(s.bob, y);
    dr.decrypt(s.bob, x);
    assert.throws(() => dr.decrypt(s.bob, x), /Duplicate|authentication/);
  });

  test(`${ns}: any flipped bit is rejected and leaves the session untouched`, () => {
    const s = startSession(ns);
    dr.decrypt(s.alice, dr.encrypt(s.bob, text("so Alice has a receiving chain")));
    const m = dr.encrypt(s.bob, text("genuine"));
    const before = snapshot(s.alice);
    for (let i = 0; i < m.length; i++) {
      const bad = Uint8Array.from(m);
      bad[i] ^= 0x01;
      assert.throws(() => dr.decrypt(s.alice, bad), undefined, `byte ${i}`);
      assert.equal(snapshot(s.alice), before, `byte ${i} changed the state`);
    }
    assert.deepEqual(dr.decrypt(s.alice, m), text("genuine"));
  });

  test(`${ns}: a forged message with a new ratchet key doesn't move the session`, () => {
    const s = startSession(ns);
    const m = dr.encrypt(s.bob, text("genuine"));
    const parsed = dr.PROFILES[ns].parse(m);
    const forged = dr.PROFILES[ns].frame(
      { ...parsed.header, dhPublicKey: keys.generatePreKeys(1, 1)[0].publicKey },
      parsed.ciphertext,
      () => new Uint8Array(dr.PROFILES[ns].macLength)
    );
    const before = snapshot(s.alice);
    assert.throws(() => dr.decrypt(s.alice, forged), /authentication/);
    assert.equal(snapshot(s.alice), before);
    assert.deepEqual(dr.decrypt(s.alice, m), text("genuine"));
  });

  test(`${ns}: the responder can't send before it has received`, () => {
    const alice = makeParty(ns);
    const state = dr.initReceiver(ns, { sharedSecret: new Uint8Array(32), associatedData: new Uint8Array(66) }, alice.signedPreKey);
    assert.throws(() => dr.encrypt(state, text("too early")), /No sending chain/);
  });

  test(`${ns}: skipping more than MAX_SKIP messages is refused`, () => {
    const s = startSession(ns);
    let last;
    for (let i = 0; i <= dr.MAX_SKIP + 1; i++) {
      last = dr.encrypt(s.alice, text("x"));
    }
    const before = snapshot(s.bob);
    assert.throws(() => dr.decrypt(s.bob, last), /Too many skipped/);
    assert.equal(snapshot(s.bob), before);
  });

  test(`${ns}: garbage and truncated input are rejected`, () => {
    const s = startSession(ns);
    const m = dr.encrypt(s.alice, text("x"));
    for (const bad of [new Uint8Array(0), randomBytes(40), m.subarray(0, m.length - 1), m.subarray(1)]) {
      assert.throws(() => dr.decrypt(s.bob, bad));
    }
    assert.deepEqual(dr.decrypt(s.bob, m), text("x"));
  });
}

// --- persistence and the total skipped-key cap ---

for (const ns of keys.NAMESPACES) {
  test(`${ns}: a saved session reloads exactly, skipped keys included, and carries on`, () => {
    const s = startSession(ns);
    const msgs = [1, 2, 3].map((i) => dr.encrypt(s.alice, text(`m${i}`)));
    dr.decrypt(s.bob, msgs[2]);
    assert.equal(s.bob.skippedMessageKeys.size, 2);

    const saved = JSON.stringify(dr.serializeState(s.bob));
    const bob = dr.deserializeState(JSON.parse(saved));
    assert.equal(snapshot(bob), snapshot(s.bob));
    assert.equal(JSON.stringify(dr.serializeState(bob)), saved, "serializing is stable");
    assert.deepEqual(dr.decrypt(bob, msgs[0]), text("m1"));
    assert.deepEqual(dr.decrypt(bob, msgs[1]), text("m2"));
    const alice = reload(s.alice);
    assert.deepEqual(dr.decrypt(alice, dr.encrypt(bob, text("reply"))), text("reply"));

    // A responder that hasn't received yet has no chains; that round-trips too.
    const fresh = dr.initReceiver(ns, { sharedSecret: randomBytes(32), associatedData: randomBytes(ns === "oldmemo" ? 66 : 64) },
      makeParty(ns).signedPreKey);
    assert.equal(snapshot(reload(fresh)), snapshot(fresh));
  });

  test(`${ns}: a malformed or inconsistent stored session is refused`, () => {
    const s = startSession(ns);
    dr.encrypt(s.alice, text("skipped"));
    dr.decrypt(s.bob, dr.encrypt(s.alice, text("delivered")));
    const good = dr.serializeState(s.bob);
    assert.equal(good.skippedMessageKeys.length, 1);
    const other = dr.serializeState(startSession(ns).bob);
    const b64 = (bytes) => Buffer.from(bytes).toString("base64");

    const mutations = {
      "wrong version": (d) => { d.version = 2; },
      "unknown namespace": (d) => { d.namespace = "omemo3"; },
      "unknown role": (d) => { d.role = "observer"; },
      "short associated data": (d) => { d.associatedData = b64(randomBytes(ns === "oldmemo" ? 64 : 66)); },
      "invalid base64": (d) => { d.rootKey = "!".repeat(44); },
      "non-canonical base64": (d) => { d.rootKey = d.rootKey.slice(0, 42) + "B="; },
      "rootKey not a string": (d) => { d.rootKey = [1, 2, 3]; },
      "mismatched ratchet key pair": (d) => { d.dhSelf.publicKey = other.dhSelf.publicKey; },
      "missing dhSelf": (d) => { delete d.dhSelf; },
      "negative counter": (d) => { d.nSend = -1; },
      "fractional counter": (d) => { d.nRecv = 1.5; },
      "string counter": (d) => { d.prevChainLength = "3"; },
      "sending chain without dhRemote": (d) => { d.dhRemote = null; },
      "receiving chain without dhRemote": (d) => { d.dhRemote = null; d.chainKeySend = null; },
      "skipped keys not an array": (d) => { d.skippedMessageKeys = {}; },
      "skipped key entry too short": (d) => { d.skippedMessageKeys[0] = d.skippedMessageKeys[0].slice(0, 2); },
      "duplicate skipped key": (d) => { d.skippedMessageKeys.push(d.skippedMessageKeys[0]); },
      "bad skipped key index": (d) => { d.skippedMessageKeys[0][1] = -4; },
      "too many skipped keys": (d) => { d.skippedMessageKeys = Array(dr.MAX_SKIPPED_TOTAL + 1).fill(d.skippedMessageKeys[0]); },
    };
    for (const [what, mutate] of Object.entries(mutations)) {
      const data = JSON.parse(JSON.stringify(good));
      mutate(data);
      assert.throws(() => dr.deserializeState(data), /Stored session is invalid/, what);
    }
    for (const bad of [null, "text", 42]) {
      assert.throws(() => dr.deserializeState(bad), /Stored session is invalid/);
    }
    // An initiator always knows the peer's ratchet key.
    const initiator = dr.serializeState(s.alice);
    initiator.dhRemote = null;
    initiator.chainKeySend = null;
    initiator.chainKeyRecv = null;
    assert.throws(() => dr.deserializeState(initiator), /initiator/);
  });

  test(`${ns}: skipped keys are capped across chains, dropping the oldest first`, () => {
    const s = startSession(ns);
    const gap = 700; // three gaps: 2100 skipped keys, 100 over the cap
    const firstChain = [];
    for (let round = 0; round < 3; round++) {
      const held = [];
      for (let i = 0; i < gap; i++) {
        held.push(dr.encrypt(s.alice, text(`r${round}.${i}`)));
      }
      dr.decrypt(s.bob, dr.encrypt(s.alice, text("the one that arrives")));
      dr.decrypt(s.alice, dr.encrypt(s.bob, text("reply, so Alice starts a new chain")));
      if (round === 0) {
        firstChain.push(...held);
      }
    }
    assert.equal(s.bob.skippedMessageKeys.size, dr.MAX_SKIPPED_TOTAL);
    assert.throws(() => dr.decrypt(s.bob, firstChain[0]), undefined, "the oldest key was dropped");
    assert.throws(() => dr.decrypt(s.bob, firstChain[99]), undefined, "the 100th oldest too");
    assert.deepEqual(dr.decrypt(s.bob, firstChain[100]), text("r0.100"));
    assert.equal(s.bob.skippedMessageKeys.size, dr.MAX_SKIPPED_TOTAL - 1);
    assert.equal(reload(s.bob).skippedMessageKeys.size, dr.MAX_SKIPPED_TOTAL - 1);
  });
}

test("oldmemo: messages start with version byte 0x33 and carry 0x05-prefixed ratchet keys", () => {
  const s = startSession("oldmemo");
  const m = dr.encrypt(s.alice, text("x"));
  assert.equal(m[0], 0x33);
  const message = pb.decode(pb.oldmemo.OMEMOMessage, m.subarray(1, m.length - 8));
  assert.equal(message.dhPub.length, 33);
  assert.equal(message.dhPub[0], 0x05);
  const wrongVersion = Uint8Array.from(m);
  wrongVersion[0] = 0x22;
  assert.throws(() => dr.decrypt(s.bob, wrongVersion), /version/);
});

test("oldmemo: pn on the wire is the previous chain's last index, as libsignal sends it", () => {
  const s = startSession("oldmemo"); // Alice has sent one message
  dr.encrypt(s.alice, text("a2"));
  dr.encrypt(s.alice, text("a3"));
  dr.decrypt(s.alice, dr.encrypt(s.bob, text("reply")));
  const next = dr.encrypt(s.alice, text("new chain"));
  assert.equal(dr.PROFILES.oldmemo.parse(next).header.pn, 2); // 3 sent, last index 2
});

test("oldmemo key exchanges: version byte, libsignal layout, round trip", () => {
  const party = makeParty("oldmemo");
  const kex = {
    preKeyId: 7,
    signedPreKeyId: 2,
    identityKey: party.identity.publicKey,
    ephemeralKey: party.preKey.publicKey,
    message: Uint8Array.of(0x33, 1, 2, 3),
  };
  const bytes = x3dh.encodeKeyExchange("oldmemo", kex);
  assert.equal(bytes[0], 0x33);
  assert.deepEqual(pb.decode(pb.oldmemo.OMEMOKeyExchange, bytes.subarray(1)), {
    preKeyId: 7,
    signedPreKeyId: 2,
    identityKey: keys.encodeIdentityKey("oldmemo", party.identity.publicKey),
    ephemeralKey: keys.encodePublicKey("oldmemo", party.preKey.publicKey),
    message: kex.message,
  });
  const decoded = x3dh.decodeKeyExchange("oldmemo", bytes);
  assert.deepEqual(decoded.identityKey.curve25519, party.identity.publicKey.curve25519);
  assert.deepEqual(decoded.ephemeralKey, party.preKey.publicKey);
  assert.deepEqual(decoded.message, kex.message);
  assert.throws(() => x3dh.decodeKeyExchange("oldmemo", bytes.subarray(1)), /version byte/);
});

for (const ns of keys.NAMESPACES) {
  test(`${ns}: a message without a ciphertext, or with a short MAC, is refused before any key work`, () => {
    const s = startSession(ns);
    const m = dr.encrypt(s.alice, text("x"));
    const profile = dr.PROFILES[ns];
    const noCiphertext = profile.frame(profile.parse(m).header, undefined, () => new Uint8Array(profile.macLength));
    assert.throws(() => dr.decrypt(s.bob, noCiphertext), /no ciphertext/);
    if (ns === "twomemo") {
      // oldmemo's MAC is the last 8 bytes by construction; twomemo's is a field.
      const authenticated = pb.decode(pb.twomemo.OMEMOAuthenticatedMessage, m);
      const shortMac = pb.encode(pb.twomemo.OMEMOAuthenticatedMessage, { ...authenticated, mac: authenticated.mac.subarray(0, 8) });
      assert.throws(() => dr.decrypt(s.bob, shortMac), /MAC must be 16 bytes/);
    }
    assert.deepEqual(dr.decrypt(s.bob, m), text("x"));
  });
}

for (const ns of keys.NAMESPACES) {
  test(`${ns}: before any reply, a message claiming the responder's signed prekey as ratchet key is refused cleanly`, () => {
    const alice = makeParty(ns);
    const bob = makeParty(ns);
    const hs = x3dh.initiateHandshake(ns, alice.identity, {
      identityKey: keys.decodeIdentityKey(ns, keys.encodeIdentityKey(ns, bob.identity.publicKey)),
      signedPreKey: bob.signedPreKey,
    });
    const state = dr.initSender(ns, hs, bob.signedPreKey.publicKey);
    const profile = dr.PROFILES[ns];
    const forged = profile.frame({ dhPublicKey: bob.signedPreKey.publicKey, n: 0, pn: 0 }, new Uint8Array(16),
      () => new Uint8Array(profile.macLength));
    const before = snapshot(state);
    assert.throws(() => dr.decrypt(state, forged), /no receiving chain/);
    assert.equal(snapshot(state), before);
  });
}

test("a ratchet key draw of the wrong size is refused", () => {
  const hs = { sharedSecret: new Uint8Array(32), associatedData: new Uint8Array(64) };
  const theirs = makeParty("twomemo").signedPreKey.publicKey;
  assert.throws(() => dr.initSender("twomemo", hs, theirs, { random: () => new Uint8Array(31) }), /32 bytes/);
});

test("an unknown namespace is rejected by name", () => {
  const hs = { sharedSecret: new Uint8Array(32), associatedData: new Uint8Array(64) };
  assert.throws(() => dr.initReceiver("omemo3", hs, makeParty("twomemo").signedPreKey), /Unknown OMEMO namespace "omemo3"/);
  assert.throws(() => dr.initSender("toString", hs, new Uint8Array(32)), /Unknown OMEMO namespace/);
});
