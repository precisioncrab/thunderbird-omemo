/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests for src/omemo/account.js against the fake pubsub server: first
 * connect and reconnect, keeping other devices on our lists, notifications,
 * peer lookups, and an encrypted conversation between two accounts that
 * know each other only through what they published.
 */

import test from "node:test";
import assert from "node:assert/strict";
import * as keys from "../src/crypto/keys.js";
import * as f from "../src/omemo/formats.js";
import * as pep from "../src/omemo/pep.js";
import { createOmemoAccount, DEVICE_LABEL } from "../src/omemo/account.js";
import { encryptMessage, decryptMessage } from "../src/omemo/messages.js";
import { parseXml, serialize } from "../src/omemo/xml.js";
import { createFakePepServer } from "./fake-pep.js";

/** An in-memory file, standing in for <profile>/omemo/<jid>.json. */
function memoryFile() {
  let text = null;
  let writes = 0;
  return {
    read: async () => text,
    write: async (t) => {
      text = t;
      writes++;
    },
    get text() {
      return text;
    },
    get writes() {
      return writes;
    },
  };
}

function account(server, jid, file = memoryFile(), lines = []) {
  const acc = createOmemoAccount({
    jid: `${jid}/Thunderbird`,
    sendIq: server.connect(jid),
    fileAccess: file,
    log: (l) => lines.push(l),
    saverOptions: { setTimer: () => 0, clearTimer: () => {} }, // writes happen on flush
  });
  return Object.assign(acc, { file, lines });
}

const publishedList = (server, jid, ns) => {
  const node = server.accounts.get(jid)?.get(f.deviceListLocation(ns).node);
  return node ? f.parseDeviceList(ns, parseXml(node.items.get("current"))) : null;
};

test("first connect: new keys, our device on both lists, both bundles published and saved", async () => {
  const server = createFakePepServer();
  const alice = account(server, "alice@example.org");
  const result = await alice.start();
  assert.equal(result.created, true);
  assert.deepEqual(result.published, ["oldmemo", "twomemo"]);
  assert.deepEqual(result.failed, []);
  const id = alice.store.deviceId;
  assert.deepEqual(publishedList(server, "alice@example.org", "twomemo"), [{ id, label: DEVICE_LABEL }]);
  assert.deepEqual(publishedList(server, "alice@example.org", "oldmemo"), [{ id, label: null }]);
  for (const ns of keys.NAMESPACES) {
    const { node, itemId } = f.bundleLocation(ns, id);
    const bundle = f.parseBundle(ns, parseXml(server.accounts.get("alice@example.org").get(node).items.get(itemId)));
    assert.deepEqual(bundle.identityKey.curve25519, alice.store.identityKeyPair().publicKey.curve25519);
    assert.equal(bundle.preKeys.length, 100);
    assert.equal(server.accounts.get("alice@example.org").get(node).config["pubsub#access_model"], "open");
  }
  assert.equal(server.accounts.get("alice@example.org").get("urn:xmpp:omemo:2:bundles").config["pubsub#max_items"], "max");
  assert.ok(alice.file.text, "the store was saved");
  assert.match(alice.lines.join("\n"), /created OMEMO keys.*\n.*OMEMO ready for alice@example\.org/);
});

test("reconnect: same keys from the saved store, nothing new created", async () => {
  const server = createFakePepServer();
  const file = memoryFile();
  const first = account(server, "alice@example.org", file);
  await first.start();
  const again = account(server, "alice@example.org", file);
  const result = await again.start();
  assert.equal(result.created, false);
  assert.equal(again.store.deviceId, first.store.deviceId);
  assert.deepEqual(again.store.identityKeyPair().publicKey, first.store.identityKeyPair().publicKey);
  assert.deepEqual(publishedList(server, "alice@example.org", "twomemo").map((d) => d.id), [first.store.deviceId]);
});

test("our other devices stay on our device lists, and their ids aren't reused", async () => {
  const server = createFakePepServer();
  server.put("alice@example.org", "urn:xmpp:omemo:2:devices", "current",
    f.buildDeviceList("twomemo", [{ id: 111, label: "Conversations" }, { id: 222, label: null }]));
  server.put("alice@example.org", "eu.siacs.conversations.axolotl.devicelist", "current",
    f.buildDeviceList("oldmemo", [{ id: 111 }]));
  const alice = account(server, "alice@example.org");
  await alice.start();
  const id = alice.store.deviceId;
  assert.ok(![111, 222].includes(id));
  assert.deepEqual(publishedList(server, "alice@example.org", "twomemo"),
    [{ id: 111, label: "Conversations" }, { id: 222, label: null }, { id, label: DEVICE_LABEL }]);
  assert.deepEqual(publishedList(server, "alice@example.org", "oldmemo").map((d) => d.id), [111, id]);
});

test("a namespace whose PEP fails is skipped and logged; the other still publishes", async () => {
  const server = createFakePepServer();
  const inner = server.connect("alice@example.org");
  const sendIq = async (iq) => {
    const text = serialize(iq);
    if (text.includes("eu.siacs.conversations.axolotl.bundles")) {
      return parseXml("<iq type='error'><error type='cancel'><not-allowed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>");
    }
    return inner(iq);
  };
  const lines = [];
  const alice = createOmemoAccount({ jid: "alice@example.org", sendIq, fileAccess: memoryFile(), log: (l) => lines.push(l) });
  const result = await alice.start();
  assert.deepEqual(result.published, ["twomemo"]);
  assert.deepEqual(result.failed, ["oldmemo"]);
  assert.match(lines.join("\n"), /ERROR: oldmemo: publishing failed: PEP request failed: not-allowed/);
});

test("if our device list can't be read, we don't publish over it", async () => {
  const server = createFakePepServer();
  const inner = server.connect("alice@example.org");
  const sendIq = async (iq) => (serialize(iq).includes('type="get"') && serialize(iq).includes("omemo:2:devices")
    ? parseXml("<iq type='error'><error type='wait'><internal-server-error xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")
    : inner(iq));
  const alice = createOmemoAccount({ jid: "alice@example.org", sendIq, fileAccess: memoryFile() });
  const result = await alice.start();
  assert.deepEqual(result.failed, ["twomemo"]);
  assert.equal(server.accounts.get("alice@example.org").has("urn:xmpp:omemo:2:devices"), false);
});

test("notifications: a contact's list updates the store; ours without our device gets republished", async () => {
  const server = createFakePepServer();
  const alice = account(server, "alice@example.org");
  await alice.start();
  const id = alice.store.deviceId;

  const contactEvent = pep.parseEvent(parseXml(`<message from='bob@example.org'><event xmlns='http://jabber.org/protocol/pubsub#event'>
      <items node='urn:xmpp:omemo:2:devices'><item id='current'><devices xmlns='urn:xmpp:omemo:2'><device id='5' label='phone'/></devices></item></items>
    </event></message>`));
  assert.equal(await alice.handleEvent(contactEvent), true);
  assert.deepEqual(alice.store.devices("twomemo", "bob@example.org").map((d) => [d.id, d.label]), [[5, "phone"]]);

  // Another of Alice's clients publishes a list without this device.
  const ownEvent = pep.parseEvent(parseXml(`<message from='alice@example.org'><event xmlns='http://jabber.org/protocol/pubsub#event'>
      <items node='eu.siacs.conversations.axolotl.devicelist'><item id='current'><list xmlns='eu.siacs.conversations.axolotl'><device id='9'/></list></item></items>
    </event></message>`));
  assert.equal(await alice.handleEvent(ownEvent), true);
  assert.deepEqual(publishedList(server, "alice@example.org", "oldmemo").map((d) => d.id), [9, id]);
  assert.match(alice.lines.join("\n"), /oldmemo: our device was dropped/);

  const other = pep.parseEvent(parseXml("<message from='bob@example.org'><event xmlns='http://jabber.org/protocol/pubsub#event'><items node='urn:xmpp:avatar:metadata'/></event></message>"));
  assert.equal(await alice.handleEvent(other), false, "not ours to handle");
});

test("two accounts find each other's devices and bundles, and talk encrypted", async () => {
  const server = createFakePepServer();
  const alice = account(server, "alice@example.org");
  const bob = account(server, "bob@example.org");
  await alice.start();
  await bob.start();

  for (const ns of keys.NAMESPACES) {
    const devices = await alice.getDevices(ns, "Bob@Example.org");
    assert.deepEqual(devices.map((d) => d.id), [bob.store.deviceId]);
    const bundle = await alice.getBundle(ns, "bob@example.org", bob.store.deviceId);
    assert.equal(bundle.preKeys.length, 100);
    assert.equal(await alice.getBundle(ns, "bob@example.org", 12345), null, "a device without a bundle");

    const { encrypted, skipped } = encryptMessage(alice.store, ns, {
      ourJid: "alice@example.org",
      body: `hello over ${ns}`,
      recipients: devices.map((d) => ({ jid: "bob@example.org", deviceId: d.id, bundle })),
    });
    assert.deepEqual(skipped, []);
    const wire = serialize(f.buildEncrypted(ns, encrypted));
    const got = decryptMessage(bob.store, f.parseEncrypted(parseXml(wire)), { ourJid: "bob@example.org", sender: "alice@example.org/tb" });
    assert.equal(got.body, `hello over ${ns}`);
    assert.ok(got.preKeyUsed);
    // Bob republishes his bundle without the used pre key.
    await bob.republishBundle(ns);
    const fresh = await alice.getBundle(ns, "bob@example.org", bob.store.deviceId);
    assert.equal(fresh.preKeys.some((k) => k.id === got.preKeyUsed), false);
    assert.equal(fresh.preKeys.length, 100, "refilled");
  }
  await bob.stop();
  assert.ok(bob.file.writes >= 2, "changes after start were saved on stop");
});

test("getDevices uses the store unless asked to refresh", async () => {
  const server = createFakePepServer();
  const alice = account(server, "alice@example.org");
  const bob = account(server, "bob@example.org");
  await alice.start();
  await bob.start();
  const first = await alice.getDevices("twomemo", "bob@example.org");
  server.put("bob@example.org", "urn:xmpp:omemo:2:devices", "current",
    f.buildDeviceList("twomemo", [...first, { id: 777, label: null }]));
  assert.deepEqual(await alice.getDevices("twomemo", "bob@example.org"), first, "cached");
  assert.deepEqual((await alice.getDevices("twomemo", "bob@example.org", { refresh: true })).map((d) => d.id), [bob.store.deviceId, 777]);
});

test("a bundle whose signature doesn't verify is refused", async () => {
  const server = createFakePepServer();
  const alice = account(server, "alice@example.org");
  const bob = account(server, "bob@example.org");
  await alice.start();
  await bob.start();
  const { node, itemId } = f.bundleLocation("twomemo", bob.store.deviceId);
  const stored = server.accounts.get("bob@example.org").get(node);
  const forged = f.buildBundle("twomemo", { ...bob.store.bundle("twomemo"), identityKey: alice.store.identityKeyPair().publicKey });
  stored.items.set(itemId, serialize(forged));
  await assert.rejects(alice.getBundle("twomemo", "bob@example.org", bob.store.deviceId), /signature does not verify/);
});

// --- milestone 6 ---

const publishedBundle = (server, jid, ns, deviceId) => {
  const { node, itemId } = f.bundleLocation(ns, deviceId);
  return f.parseBundle(ns, parseXml(server.accounts.get(jid).get(node).items.get(itemId)));
};

test("maintain() replaces a week-old signed prekey and republishes; start() does it on connect too", async () => {
  const server = createFakePepServer();
  let clock = Date.parse("2026-09-26T00:00:00Z");
  const file = memoryFile();
  const make = () => createOmemoAccount({
    jid: "alice@example.org/Thunderbird", sendIq: server.connect("alice@example.org"), fileAccess: file,
    log: () => {}, now: () => clock, saverOptions: { setTimer: () => 0, clearTimer: () => {} },
  });
  const alice = make();
  await alice.start();
  const id = alice.store.deviceId;
  const before = { oldmemo: publishedBundle(server, "alice@example.org", "oldmemo", id).signedPreKey.id,
    twomemo: publishedBundle(server, "alice@example.org", "twomemo", id).signedPreKey.id };
  assert.deepEqual(await alice.maintain(), [], "nothing due yet");
  clock += 7 * 24 * 60 * 60 * 1000;
  assert.deepEqual(await alice.maintain(), ["oldmemo", "twomemo"]);
  for (const ns of ["oldmemo", "twomemo"]) {
    assert.equal(publishedBundle(server, "alice@example.org", ns, id).signedPreKey.id, before[ns] + 1, `${ns} republished`);
  }
  await alice.stop();

  // A week later, offline: the next connect rotates before publishing.
  clock += 7 * 24 * 60 * 60 * 1000;
  const again = make();
  await again.start();
  assert.equal(publishedBundle(server, "alice@example.org", "twomemo", id).signedPreKey.id, before.twomemo + 2);
});

test("removeOwnDevice() takes an old install off both of our lists, never this Thunderbird", async () => {
  const server = createFakePepServer();
  const alice = account(server, "alice@example.org");
  await alice.start();
  const me = alice.store.deviceId;
  // An old phone install on both lists (as another client would publish it).
  for (const ns of ["oldmemo", "twomemo"]) {
    const { node, itemId } = f.deviceListLocation(ns);
    server.put("alice@example.org", node, itemId, f.buildDeviceList(ns, [{ id: me }, { id: 4242 }]));
  }
  assert.deepEqual(await alice.removeOwnDevice(4242), ["oldmemo", "twomemo"]);
  for (const ns of ["oldmemo", "twomemo"]) {
    assert.deepEqual(publishedList(server, "alice@example.org", ns).map((d) => d.id), [me]);
    assert.deepEqual(alice.store.devices(ns, "alice@example.org").map((d) => d.id), [me]);
  }
  assert.deepEqual(await alice.removeOwnDevice(4242), [], "already gone");
  await assert.rejects(alice.removeOwnDevice(me), /this Thunderbird/);
});
