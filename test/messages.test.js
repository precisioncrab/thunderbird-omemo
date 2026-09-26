/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests for src/omemo/messages.js, end to end: stores for Alice and Bob
 * (and their other devices) exchange messages as serialized XML, the way
 * they'd travel in stanzas, in both namespaces.
 */

import test from "node:test";
import assert from "node:assert/strict";
import * as keys from "../src/crypto/keys.js";
import * as x3dh from "../src/crypto/x3dh.js";
import { createStore, OmemoStore } from "../src/omemo/store.js";
import * as f from "../src/omemo/formats.js";
import { parseXml, serialize } from "../src/omemo/xml.js";
import { encryptMessage, decryptMessage, OmemoError } from "../src/omemo/messages.js";

const ALICE = "alice@example.org";
const BOB = "bob@example.org";

/** A device: its store plus its published bundle as a contact would fetch it. */
function device(jid) {
  const store = createStore();
  return {
    jid,
    store,
    bundle: (ns) => f.parseBundle(ns, parseXml(serialize(f.buildBundle(ns, store.bundle(ns))))),
  };
}

/** Sends from one device to others; returns the stanza's <encrypted> as XML text. */
function send(ns, from, body, to, { withBundles = true } = {}) {
  const { encrypted, skipped } = encryptMessage(from.store, ns, {
    ourJid: `${from.jid}/tb`,
    body,
    recipients: to.map((d) => ({ jid: d.jid, deviceId: d.store.deviceId, bundle: withBundles ? d.bundle(ns) : undefined })),
  });
  return { xml: serialize(f.buildEncrypted(ns, encrypted)), skipped };
}

function receive(to, xmlText, sender) {
  return decryptMessage(to.store, f.parseEncrypted(parseXml(xmlText)), { ourJid: `${to.jid}/tb`, sender: `${sender.jid}/phone` });
}

const reload = (d) => {
  d.store = OmemoStore.fromJSON(JSON.parse(JSON.stringify(d.store.toJSON())));
};

const codeOf = (fn) => {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof OmemoError, `expected an OmemoError, got ${e}`);
    return e.code;
  }
  assert.fail("expected an OmemoError");
};

for (const ns of keys.NAMESPACES) {
  test(`${ns}: a first conversation, with the key exchange repeated until Bob replies`, () => {
    const alice = device(ALICE);
    const bob = device(BOB);

    const m1 = send(ns, alice, "Hi Bob", [bob]);
    assert.match(m1.xml, ns === "oldmemo" ? /prekey="true"/ : /kex="true"/);
    const r1 = receive(bob, m1.xml, alice);
    assert.equal(r1.body, "Hi Bob");
    assert.equal(r1.sessionStarted, true, "Bob should confirm with an empty message");
    assert.ok(r1.preKeyUsed >= 1);
    assert.equal(bob.store.preKey(ns, r1.preKeyUsed), null, "the pre key is used up");
    assert.equal(bob.store.bundle(ns).preKeys.length, 100, "and replaced");
    assert.deepEqual(r1.peerIdentityKey, keys.encodeIdentityKey(ns, alice.store.identityKeyPair().publicKey));

    // Alice hasn't heard back, so her second message repeats the key exchange;
    // Bob reuses the session (the pre key is gone, so a new X3DH would fail).
    const m2 = send(ns, alice, "Are you there?", [bob]);
    assert.match(m2.xml, ns === "oldmemo" ? /prekey="true"/ : /kex="true"/);
    reload(bob);
    const r2 = receive(bob, m2.xml, alice);
    assert.deepEqual([r2.body, r2.sessionStarted, r2.preKeyUsed], ["Are you there?", false, null]);

    // Bob's empty confirmation: no payload, and it clears Alice's key exchange.
    const confirm = send(ns, bob, null, [alice]);
    assert.doesNotMatch(confirm.xml, /<payload>/);
    assert.doesNotMatch(confirm.xml, /prekey=|kex=/);
    reload(alice);
    assert.deepEqual(receive(alice, confirm.xml, bob), {
      body: null,
      peerIdentityKey: keys.encodeIdentityKey(ns, bob.store.identityKeyPair().publicKey),
      sessionStarted: false,
      preKeyUsed: null,
    });
    const m3 = send(ns, alice, "Great, it works 👍", [bob]);
    assert.doesNotMatch(m3.xml, /prekey=|kex=/, "no more key exchange");
    assert.equal(receive(bob, m3.xml, alice).body, "Great, it works 👍");
    assert.equal(receive(alice, send(ns, bob, "It does", [alice]).xml, bob).body, "It does");
  });

  test(`${ns}: one message reaches several devices, including our own other device`, () => {
    const alice = device(ALICE);
    const aliceLaptop = device(ALICE);
    const bobPhone = device(BOB);
    const bobDesktop = device(BOB);
    const m = send(ns, alice, "to everyone", [bobPhone, bobDesktop, aliceLaptop, alice]);
    assert.equal(f.parseEncrypted(parseXml(m.xml)).keys.length, 3, "our own sending device is left out");
    for (const d of [bobPhone, bobDesktop, aliceLaptop]) {
      assert.equal(receive(d, m.xml, alice).body, "to everyone");
    }
    if (ns === "twomemo") {
      assert.match(m.xml, /<keys jid="bob@example.org">.*<\/keys><keys jid="alice@example.org">/);
    }
  });

  test(`${ns}: devices we can't reach are reported, not fatal`, () => {
    const alice = device(ALICE);
    const bob = device(BOB);
    const carol = device("carol@example.org");
    const { encrypted, skipped } = encryptMessage(alice.store, ns, {
      ourJid: ALICE,
      body: "hello",
      recipients: [
        { jid: BOB, deviceId: bob.store.deviceId, bundle: bob.bundle(ns) },
        { jid: "carol@example.org", deviceId: carol.store.deviceId }, // no session, no bundle
        { jid: "dave@example.org", deviceId: 77, bundle: { ...bob.bundle(ns), preKeys: [] } },
      ],
    });
    assert.deepEqual(encrypted.keys.map((k) => k.rid), [bob.store.deviceId]);
    assert.deepEqual(skipped.map((s) => [s.jid, s.reason]), [
      ["carol@example.org", "no session and no bundle"],
      ["dave@example.org", "the bundle has no pre keys"],
    ]);
  });

  test(`${ns}: failures come back as OmemoError codes and leave the store untouched`, () => {
    const alice = device(ALICE);
    const bob = device(BOB);
    const eve = device("eve@example.org");
    const m1 = send(ns, alice, "first", [bob]);

    assert.equal(codeOf(() => receive(eve, m1.xml, alice)), "not-for-this-device");

    const before = JSON.stringify(bob.store.toJSON());
    // A key exchange naming a pre key Bob doesn't have.
    const parsed = f.parseEncrypted(parseXml(m1.xml));
    const kex = x3dh.decodeKeyExchange(ns, parsed.keys[0].data);
    const reencode = (changes) => serialize(f.buildEncrypted(ns, {
      ...parsed,
      keys: [{ ...parsed.keys[0], data: x3dh.encodeKeyExchange(ns, { ...kex, ...changes }) }],
    }));
    assert.equal(codeOf(() => receive(bob, reencode({ preKeyId: 999999 }), alice)), "unknown-pre-key");
    assert.equal(codeOf(() => receive(bob, reencode({ signedPreKeyId: 42 }), alice)), "unknown-signed-prekey");
    // Right ids, wrong ephemeral key: X3DH gives another secret, so the MAC fails.
    assert.equal(codeOf(() => receive(bob, reencode({ ephemeralKey: keys.generatePreKeys(1, 1)[0].publicKey }), alice)), "decryption-failed");
    assert.equal(JSON.stringify(bob.store.toJSON()), before, "nothing changed, pre key still there");

    receive(bob, m1.xml, alice);
    assert.equal(codeOf(() => receive(bob, m1.xml, alice)), "decryption-failed", "a replay");
    const reply = send(ns, bob, "reply", [alice]).xml;
    receive(alice, reply, bob);
    assert.equal(codeOf(() => receive(alice, reply, bob)), "decryption-failed", "a replay without key exchange");
    // A plain message from a device we have no session with.
    const other = device(BOB);
    const fromOther = send(ns, other, "hi", [alice]);
    const plain = f.parseEncrypted(parseXml(fromOther.xml));
    plain.keys[0].kex = false;
    assert.equal(codeOf(() => decryptMessage(alice.store, plain, { ourJid: ALICE, sender: BOB })), "no-session");
  });

  test(`${ns}: a contact who reinstalls (new key exchange from the same device id) gets a new session`, () => {
    const alice = device(ALICE);
    const bob = device(BOB);
    receive(bob, send(ns, alice, "old install", [bob]).xml, alice);
    // Alice reinstalls but keeps her device id: a new identity, a new key exchange.
    const newAlice = { ...device(ALICE) };
    const data = newAlice.store.toJSON();
    data.deviceId = alice.store.deviceId;
    newAlice.store = OmemoStore.fromJSON(data);
    const r = receive(bob, send(ns, newAlice, "new install", [bob]).xml, newAlice);
    assert.equal(r.body, "new install");
    assert.equal(r.sessionStarted, true);
    assert.deepEqual(r.peerIdentityKey, keys.encodeIdentityKey(ns, newAlice.store.identityKeyPair().publicKey),
      "the caller sees the identity key changed (a trust decision, milestone 5)");
  });
}

test("twomemo: an envelope claiming another sender is refused", () => {
  const alice = device(ALICE);
  const bob = device(BOB);
  const m = send("twomemo", alice, "hi", [bob]);
  // Delivered as if from Mallory: the envelope still says alice.
  const code = codeOf(() => decryptMessage(bob.store, f.parseEncrypted(parseXml(m.xml)), { ourJid: BOB, sender: "mallory@example.org/x" }));
  assert.equal(code, "sender-mismatch");
});

test("oldmemo: a corrupted payload is a bad-payload error", () => {
  const alice = device(ALICE);
  const bob = device(BOB);
  const m = f.parseEncrypted(parseXml(send("oldmemo", alice, "hi", [bob]).xml));
  m.payload[0] ^= 1;
  assert.equal(codeOf(() => decryptMessage(bob.store, m, { ourJid: BOB, sender: ALICE })), "bad-payload");
});

test("a key exchange made with a bundle from before our signed prekey rotated still works", () => {
  for (const ns of ["oldmemo", "twomemo"]) {
    let clock = Date.parse("2026-09-26T00:00:00Z");
    const alice = device(ALICE);
    const bob = { jid: BOB, store: createStore({ now: () => clock }) };
    const staleBundle = f.parseBundle(ns, parseXml(serialize(f.buildBundle(ns, bob.store.bundle(ns)))));
    clock += 8 * 24 * 60 * 60 * 1000;
    assert.equal(bob.store.rotateSignedPreKeyIfDue(ns), true);
    const { encrypted } = encryptMessage(alice.store, ns, {
      ourJid: `${ALICE}/tb`, body: "late hello", recipients: [{ jid: BOB, deviceId: bob.store.deviceId, bundle: staleBundle }],
    });
    const got = decryptMessage(bob.store, f.parseEncrypted(parseXml(serialize(f.buildEncrypted(ns, encrypted)))), { ourJid: `${BOB}/tb`, sender: `${ALICE}/phone` });
    assert.equal(got.body, "late hello", ns);
  }
});
