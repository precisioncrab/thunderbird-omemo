/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests for src/omemo/store.js: first-connect setup, what we publish,
 * pre key use and refill, sessions and device lists, and the strict JSON
 * form, including a conversation between two stores that are saved and
 * reloaded between messages.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "@noble/hashes/utils";
import * as keys from "../src/crypto/keys.js";
import * as x3dh from "../src/crypto/x3dh.js";
import * as dr from "../src/crypto/double-ratchet.js";
import { createStore, OmemoStore, PRE_KEY_TARGET, MAX_DEVICE_ID, STORE_VERSION, bareJid, SIGNED_PRE_KEY_ROTATE_MS, SIGNED_PRE_KEY_KEEP_MS } from "../src/omemo/store.js";
import { text } from "./helpers.js";

const reload = (store, options) => OmemoStore.fromJSON(JSON.parse(JSON.stringify(store.toJSON())), options);
const json = (store) => JSON.stringify(store.toJSON());

// --- setup ---

test("first-connect setup: a device id in range, avoiding ids already in use", () => {
  const draws = [Uint8Array.of(0, 0, 0, 0), Uint8Array.of(0x80, 0, 0, 5), Uint8Array.of(0, 0, 0, 9)];
  const random = (n) => (draws.length && n === 4 ? draws.shift() : randomBytes(n));
  // 0 is redrawn; 0x80000005 masks to 5, which is taken; 9 is free.
  const store = createStore({ avoidDeviceIds: [5], random });
  assert.equal(store.deviceId, 9);
  for (let i = 0; i < 20; i++) {
    const id = createStore().deviceId;
    assert.ok(Number.isInteger(id) && id >= 1 && id <= MAX_DEVICE_ID);
  }
  assert.throws(() => createStore({ avoidDeviceIds: [7], random: (n) => (n === 4 ? Uint8Array.of(0, 0, 0, 7) : randomBytes(n)) }),
    /unused device id/);
});

test("each namespace publishes a valid bundle: shared identity key, own signed prekey, 100 pre keys", () => {
  const store = createStore();
  const identity = store.identityKeyPair();
  const spks = new Set();
  for (const ns of keys.NAMESPACES) {
    const bundle = store.bundle(ns);
    assert.deepEqual(bundle.identityKey, identity.publicKey);
    assert.equal(bundle.signedPreKey.id, 1);
    assert.equal(keys.verifySignedPreKey(ns, bundle.identityKey, bundle.signedPreKey.publicKey, bundle.signedPreKey.signature), true);
    assert.deepEqual(bundle.preKeys.map((k) => k.id), Array.from({ length: PRE_KEY_TARGET }, (_, i) => i + 1));
    assert.equal(new Set(bundle.preKeys.map((k) => Buffer.from(k.publicKey).toString("hex"))).size, PRE_KEY_TARGET);
    spks.add(Buffer.from(bundle.signedPreKey.publicKey).toString("hex"));
  }
  assert.equal(spks.size, 2, "one signed prekey per namespace");
});

// --- pre keys ---

test("a used pre key is removed, and refilling adds new ids after the last one", () => {
  const store = createStore();
  for (const id of [4, 50, 100]) {
    assert.ok(store.preKey("twomemo", id));
    assert.equal(store.removePreKey("twomemo", id), true);
    assert.equal(store.preKey("twomemo", id), null);
  }
  assert.equal(store.removePreKey("twomemo", 4), false);
  assert.equal(store.bundle("oldmemo").preKeys.length, PRE_KEY_TARGET, "namespaces are separate");

  assert.equal(store.refillPreKeys("twomemo"), 3);
  const ids = store.bundle("twomemo").preKeys.map((k) => k.id);
  assert.equal(ids.length, PRE_KEY_TARGET);
  assert.deepEqual(ids.slice(-3), [101, 102, 103]);
  assert.equal(store.refillPreKeys("twomemo"), 0);
});

test("pre key ids wrap from MAX_KEY_ID to 1", () => {
  const data = createStore().toJSON();
  data.namespaces.oldmemo.preKeys = data.namespaces.oldmemo.preKeys.slice(2);
  data.namespaces.oldmemo.nextPreKeyId = keys.MAX_KEY_ID;
  const store = OmemoStore.fromJSON(data);
  assert.equal(store.refillPreKeys("oldmemo"), 2);
  assert.deepEqual(store.bundle("oldmemo").preKeys.map((k) => k.id).slice(-2), [keys.MAX_KEY_ID, 1]);
});

// --- a conversation between two stores ---

for (const ns of keys.NAMESPACES) {
  test(`${ns}: two stores hold a conversation, reloaded from JSON between messages`, () => {
    let alice = createStore();
    let bob = createStore();

    // Alice starts a session from Bob's published bundle.
    const published = bob.bundle(ns);
    const preKey = published.preKeys[17];
    const hs = x3dh.initiateHandshake(ns, alice.identityKeyPair(), {
      identityKey: keys.decodeIdentityKey(ns, keys.encodeIdentityKey(ns, published.identityKey)),
      signedPreKey: published.signedPreKey,
      preKey,
    });
    alice.setSession(ns, "Bob@Example.org/phone", bob.deviceId, {
      state: dr.initSender(ns, hs, published.signedPreKey.publicKey),
      peerIdentityKey: keys.encodeIdentityKey(ns, published.identityKey),
      pendingKeyExchange: { preKeyId: hs.preKeyId, signedPreKeyId: hs.signedPreKeyId, ephemeralKey: hs.ephemeralPublicKey },
    });
    alice = reload(alice);

    const sessionA = alice.session(ns, "bob@example.org", bob.deviceId);
    const pending = sessionA.pendingKeyExchange;
    const wire = x3dh.encodeKeyExchange(ns, {
      ...pending,
      identityKey: alice.identityKeyPair().publicKey,
      message: dr.encrypt(sessionA.state, text("hello")),
    });
    alice.setSession(ns, "bob@example.org", bob.deviceId, sessionA);
    alice = reload(alice);

    // Bob looks up the keys the key exchange names, answers, uses up the pre key.
    const kex = x3dh.decodeKeyExchange(ns, wire);
    const spk = bob.signedPreKey(ns, kex.signedPreKeyId);
    const pk = bob.preKey(ns, kex.preKeyId);
    assert.ok(spk && pk);
    assert.equal(bob.signedPreKey(ns, kex.signedPreKeyId + 1), null);
    const bobHs = x3dh.respondToHandshake(ns, { identity: bob.identityKeyPair(), signedPreKey: spk, preKey: pk },
      { identityKey: kex.identityKey, ephemeralKey: kex.ephemeralKey });
    const state = dr.initReceiver(ns, bobHs, spk);
    assert.deepEqual(dr.decrypt(state, kex.message), text("hello"));
    bob.removePreKey(ns, kex.preKeyId);
    bob.setSession(ns, "alice@example.org", alice.deviceId, {
      state,
      peerIdentityKey: keys.encodeIdentityKey(ns, alice.identityKeyPair().publicKey),
      pendingKeyExchange: null,
    });
    bob = reload(bob);
    assert.equal(bob.preKey(ns, kex.preKeyId), null);

    // Bob replies; Alice's session is confirmed and drops the key exchange.
    const sessionB = bob.session(ns, "alice@example.org", alice.deviceId);
    const reply = dr.encrypt(sessionB.state, text("hi Alice"));
    bob.setSession(ns, "alice@example.org", alice.deviceId, sessionB);
    const again = alice.session(ns, "bob@example.org", bob.deviceId);
    assert.deepEqual(dr.decrypt(again.state, reply), text("hi Alice"));
    alice.setSession(ns, "bob@example.org", bob.deviceId, { ...again, pendingKeyExchange: null });
    alice = reload(alice);
    bob = reload(bob);

    const final = alice.session(ns, "bob@example.org", bob.deviceId);
    assert.equal(final.pendingKeyExchange, null);
    const last = dr.encrypt(final.state, text("after reloads"));
    assert.deepEqual(dr.decrypt(bob.session(ns, "alice@example.org", alice.deviceId).state, last), text("after reloads"));
    assert.deepEqual(final.peerIdentityKey, keys.encodeIdentityKey(ns, bob.identityKeyPair().publicKey));
  });
}

test("sessions are keyed by namespace, bare JID and device, and can be deleted", () => {
  const store = createStore();
  const record = (ns) => ({
    state: dr.initReceiver(ns, { sharedSecret: randomBytes(32), associatedData: randomBytes(ns === "oldmemo" ? 66 : 64) },
      keys.generateSignedPreKey(keys.generateIdentityKeyPair().privateKey, 1, ns)),
    peerIdentityKey: randomBytes(ns === "oldmemo" ? 33 : 32),
    pendingKeyExchange: null,
  });
  store.setSession("twomemo", "carol@example.org", 1, record("twomemo"));
  assert.ok(store.session("twomemo", "CAROL@example.org/laptop", 1));
  assert.equal(store.session("oldmemo", "carol@example.org", 1), null);
  assert.equal(store.session("twomemo", "carol@example.org", 2), null);
  assert.throws(() => store.setSession("oldmemo", "carol@example.org", 1, record("twomemo")), /different namespace/);
  store.deleteSession("twomemo", "carol@example.org", 1);
  assert.equal(store.session("twomemo", "carol@example.org", 1), null);
  assert.throws(() => store.session("twomemo", "carol@example.org", 0), /Device id/);
});

// --- device lists ---

test("device lists: bare JIDs, duplicates dropped, labels kept, copies handed out", () => {
  let clock = 1000;
  const store = createStore({ now: () => clock });
  store.setDevices("twomemo", "Dave@Example.org/x", [{ id: 3, label: "phone" }, { id: 4 }, { id: 3, label: "dup" }]);
  assert.deepEqual(store.devices("twomemo", "dave@example.org"), [
    { id: 3, label: "phone", lastSeen: 1000, firstSeen: 1000 },
    { id: 4, label: null, lastSeen: 1000, firstSeen: 1000 },
  ]);
  store.devices("twomemo", "dave@example.org")[0].id = 99;
  assert.equal(store.devices("twomemo", "dave@example.org")[0].id, 3, "callers get copies");
  assert.deepEqual(store.devices("oldmemo", "dave@example.org"), []);
  clock = 2000;
  store.setDevices("twomemo", "dave@example.org", [{ id: 4 }]);
  assert.deepEqual(store.devices("twomemo", "dave@example.org"), [{ id: 4, label: null, lastSeen: 2000, firstSeen: 1000 }], "firstSeen is kept");
  assert.throws(() => store.setDevices("twomemo", "dave@example.org", [{ id: 0 }]), /Device id/);
  assert.equal(bareJid("A@B/C/D"), "a@b");
});

// --- change notifications and persistence ---

test("every change notifies, reads don't, and createStore counts as a change", () => {
  let changes = 0;
  const onChange = () => changes++;
  const store = createStore({ onChange });
  assert.equal(changes, 1);
  store.bundle("twomemo");
  store.preKey("twomemo", 1);
  store.devices("twomemo", "a@b");
  store.identityKeyPair();
  assert.equal(changes, 1);
  store.removePreKey("twomemo", 1);
  store.removePreKey("twomemo", 1); // already gone: no change
  store.refillPreKeys("twomemo");
  store.setDevices("twomemo", "a@b", [{ id: 1 }]);
  assert.equal(changes, 4);
  const loaded = reload(store, { onChange });
  assert.equal(changes, 4, "loading isn't a change");
  loaded.removePreKey("oldmemo", 2);
  assert.equal(changes, 5);
});

test("the JSON form round-trips exactly", () => {
  const store = createStore();
  store.removePreKey("oldmemo", 10);
  store.setDevices("oldmemo", "e@example.org", [{ id: 12 }]);
  const saved = json(store);
  const loaded = reload(store);
  assert.equal(json(loaded), saved);
  assert.equal(loaded.deviceId, store.deviceId);
  assert.deepEqual(loaded.bundle("oldmemo"), store.bundle("oldmemo"));
  assert.equal(JSON.parse(saved).version, STORE_VERSION);
});

test("a malformed stored key store is refused", () => {
  const good = createStore().toJSON();
  const s = createStore();
  const hsState = dr.initReceiver("twomemo", { sharedSecret: randomBytes(32), associatedData: randomBytes(64) },
    keys.generateSignedPreKey(s.identityKeyPair().privateKey, 1, "twomemo"));
  s.setSession("twomemo", "f@example.org", 5, { state: hsState, peerIdentityKey: randomBytes(32), pendingKeyExchange: null });
  const withSession = s.toJSON();

  const mutations = {
    "wrong version": [good, (d) => { d.version = 2; }],
    "bad device id": [good, (d) => { d.deviceId = 0; }],
    "device id too large": [good, (d) => { d.deviceId = MAX_DEVICE_ID + 1; }],
    "short identity key": [good, (d) => { d.identityPrivateKey = d.identityPrivateKey.slice(0, 20); }],
    "missing namespace": [good, (d) => { delete d.namespaces.twomemo; }],
    "duplicate pre key": [good, (d) => { d.namespaces.oldmemo.preKeys.push(d.namespaces.oldmemo.preKeys[0]); }],
    "pre key id 0": [good, (d) => { d.namespaces.oldmemo.preKeys[0][0] = 0; }],
    "bad signature length": [good, (d) => { d.namespaces.twomemo.signedPreKey.signature = d.namespaces.twomemo.signedPreKey.privateKey; }],
    "missing createdAt": [good, (d) => { delete d.namespaces.twomemo.signedPreKey.createdAt; }],
    "sessions not an array": [good, (d) => { d.sessions = {}; }],
    "session jid with resource": [withSession, (d) => { d.sessions[0].jid = "f@example.org/x"; }],
    "session jid not lowercase": [withSession, (d) => { d.sessions[0].jid = "F@example.org"; }],
    "session device id": [withSession, (d) => { d.sessions[0].deviceId = -1; }],
    "duplicate session": [withSession, (d) => { d.sessions.push(d.sessions[0]); }],
    "session in another namespace": [withSession, (d) => { d.sessions[0].namespace = "oldmemo"; }],
    "corrupt session state": [withSession, (d) => { d.sessions[0].state.rootKey = "!!!!"; }],
    "bad peer identity key": [withSession, (d) => { d.sessions[0].peerIdentityKey = "AAAA"; }],
    "bad pending key exchange": [withSession, (d) => { d.sessions[0].pendingKeyExchange = { preKeyId: 1 }; }],
    "missing peer base key": [withSession, (d) => { delete d.sessions[0].peerBaseKey; }],
    "short peer base key": [withSession, (d) => { d.sessions[0].peerBaseKey = "AAAA"; }],
    "devices not an array": [good, (d) => { d.devices = null; }],
    "bad device entry": [good, (d) => { d.devices = [{ namespace: "twomemo", jid: "g@h", devices: [{ id: 1, label: 5, lastSeen: 0 }] }]; }],
  };
  for (const [what, [base, mutate]] of Object.entries(mutations)) {
    const data = JSON.parse(JSON.stringify(base));
    mutate(data);
    assert.throws(() => OmemoStore.fromJSON(data), /invalid/i, what);
  }
  assert.throws(() => OmemoStore.fromJSON(null), /invalid/);
});

test("the per-contact encryption choice is remembered, and stores from before it existed still load", () => {
  const store = createStore();
  assert.equal(store.encryptionEnabled("carol@example.org"), false);
  store.setEncryptionEnabled("Carol@Example.org/phone", true);
  assert.equal(store.encryptionEnabled("carol@example.org"), true);
  const loaded = reload(store);
  assert.equal(loaded.encryptionEnabled("carol@example.org"), true);
  loaded.setEncryptionEnabled("carol@example.org", false);
  assert.equal(reload(loaded).encryptionEnabled("carol@example.org"), false);

  const old = store.toJSON();
  delete old.encryption; // as written by 0.0.2-0.0.5
  assert.equal(OmemoStore.fromJSON(old).encryptionEnabled("carol@example.org"), false);
  assert.throws(() => OmemoStore.fromJSON({ ...store.toJSON(), encryption: {} }), /encryption must be an array/);
  // 0.0.6 wrote plain JIDs for "on".
  assert.equal(OmemoStore.fromJSON({ ...store.toJSON(), encryption: ["dave@example.org"] }).encryptionChoice("dave@example.org"), "on");
  assert.throws(() => OmemoStore.fromJSON({ ...store.toJSON(), encryption: [["dave@example.org", "maybe"]] }), /encryption choice/);
  assert.throws(() => OmemoStore.fromJSON({ ...store.toJSON(), encryption: ["Not@Lower"] }), /lowercase bare JID/);
});

test("an explicit off is remembered separately from following the mode", () => {
  const store = createStore();
  store.setEncryptionChoice("sms@cheogram.com", "off");
  store.setEncryptionChoice("friend@example.org", "on");
  const loaded = reload(store);
  assert.equal(loaded.encryptionChoice("sms@cheogram.com"), "off");
  assert.equal(loaded.encryptionChoice("friend@example.org"), "on");
  assert.equal(loaded.encryptionChoice("other@example.org"), null);
  loaded.setEncryptionChoice("sms@cheogram.com", null);
  assert.equal(reload(loaded).encryptionChoice("sms@cheogram.com"), null);
  assert.throws(() => loaded.setEncryptionChoice("x@y", "maybe"), /"on", "off" or null/);
});

test("trust per identity key and the key each device last had are remembered; older stores load", () => {
  const store = createStore();
  const fpA = "11111111 22222222 33333333 44444444 55555555 66666666 77777777 88888888";
  const fpB = "aaaaaaaa bbbbbbbb cccccccc dddddddd eeeeeeee ffffffff 00000000 99999999";
  assert.equal(store.trustOf("bob@example.org", fpA), null);
  store.setTrust("Bob@Example.org/phone", fpA, "blind");
  store.setTrust("bob@example.org", fpB, "verified");
  store.setDeviceKey("bob@example.org", 7, fpA);
  assert.equal(store.hasVerified("bob@example.org"), true);
  assert.equal(store.hasVerified("carol@example.org"), false);
  const loaded = reload(store);
  assert.equal(loaded.trustOf("bob@example.org", fpA), "blind");
  assert.equal(loaded.trustOf("bob@example.org", fpB), "verified");
  assert.equal(loaded.deviceKey("bob@example.org", 7), fpA);
  assert.equal(loaded.deviceKey("bob@example.org", 8), null);
  assert.throws(() => loaded.setTrust("bob@example.org", fpA, "maybe"), /Unknown trust state/);

  const old = store.toJSON();
  delete old.trust;
  delete old.deviceKeys;
  assert.equal(OmemoStore.fromJSON(old).trustOf("bob@example.org", fpA), null);
  assert.throws(() => OmemoStore.fromJSON({ ...store.toJSON(), trust: [["bob@example.org", "nothex", "blind"]] }), /trust entry/);
  assert.throws(() => OmemoStore.fromJSON({ ...store.toJSON(), deviceKeys: [["bob@example.org", 0, fpA]] }), /device id/);
});

test("the time of each device's last message is remembered; older stores load", () => {
  let now = 1000;
  const store = createStore({ now: () => now });
  assert.equal(store.lastMessageFrom("bob@example.org", 7), null);
  store.recordMessageFrom("Bob@Example.org/phone", 7);
  now = 5000;
  store.recordMessageFrom("bob@example.org", 8);
  const loaded = reload(store);
  assert.equal(loaded.lastMessageFrom("bob@example.org", 7), 1000);
  assert.equal(loaded.lastMessageFrom("bob@example.org", 8), 5000);
  assert.equal(loaded.lastMessageFrom("bob@example.org", 9), null);
  assert.throws(() => store.recordMessageFrom("bob@example.org", 0), /Device id/);

  const old = store.toJSON();
  delete old.lastMessages;
  assert.equal(OmemoStore.fromJSON(old).lastMessageFrom("bob@example.org", 7), null);
  assert.throws(() => OmemoStore.fromJSON({ ...store.toJSON(), lastMessages: [["bob@example.org", 7, "soon"]] }), /last-message entry/);
  assert.throws(() => OmemoStore.fromJSON({ ...store.toJSON(), lastMessages: [["bob@example.org", 0, 1]] }), /device id/);
});

test("signed prekeys rotate weekly; replaced ones answer key exchanges for 30 days, then go", () => {
  let clock = Date.parse("2026-09-26T00:00:00Z");
  const store = createStore({ now: () => clock });
  for (const ns of ["oldmemo", "twomemo"]) {
    const first = store.bundle(ns).signedPreKey;
    clock += SIGNED_PRE_KEY_ROTATE_MS - 1;
    assert.equal(store.rotateSignedPreKeyIfDue(ns), false, "not due yet");
    clock += 1;
    assert.equal(store.rotateSignedPreKeyIfDue(ns), true, "due after a week");
    const second = store.bundle(ns).signedPreKey;
    assert.equal(second.id, first.id + 1, "a new id");
    assert.notDeepEqual(second.publicKey, first.publicKey);
    assert.ok(keys.verifySignedPreKey(ns, store.bundle(ns).identityKey, second.publicKey, second.signature), "signed by our identity key");
    assert.deepEqual(store.signedPreKey(ns, first.id).publicKey, first.publicKey, "the replaced one still answers");
    assert.deepEqual(reload(store, { now: () => clock }).signedPreKey(ns, first.id).publicKey, first.publicKey, "and survives a reload");
    assert.equal(store.rotateSignedPreKeyIfDue(ns), false, "the new one isn't due");
    clock += SIGNED_PRE_KEY_KEEP_MS;
    store.rotateSignedPreKeyIfDue(ns);
    assert.equal(store.signedPreKey(ns, first.id), null, "forgotten after 30 days");
    clock -= SIGNED_PRE_KEY_KEEP_MS + SIGNED_PRE_KEY_ROTATE_MS; // back for the other namespace
  }
});

test("stores from before rotation load; devices get a first-seen time", () => {
  let clock = 5000;
  const store = createStore({ now: () => clock });
  store.setDevices("oldmemo", "bob@example.org", [{ id: 7 }]);
  const old = store.toJSON();
  for (const ns of ["oldmemo", "twomemo"]) {
    delete old.namespaces[ns].oldSignedPreKeys;
  }
  delete old.devices[0].devices[0].firstSeen;
  clock = 9000;
  const loaded = OmemoStore.fromJSON(old, { now: () => clock });
  assert.equal(loaded.devices("oldmemo", "bob@example.org")[0].firstSeen, 9000, "counted from the load");
  assert.equal(loaded.rotateSignedPreKeyIfDue("twomemo"), false);
  const bad = store.toJSON();
  bad.namespaces.twomemo.oldSignedPreKeys = [{ id: 1, privateKey: "x", signature: "y", createdAt: 1 }];
  assert.throws(() => OmemoStore.fromJSON(bad), /replaced signed prekey times/);
});
