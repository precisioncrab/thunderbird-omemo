/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Milestone 4 through the bridge: encrypted 1:1 messages between two
 * accounts on the encryption allowlist, over the fake Thunderbird (which
 * delivers message stanzas between its accounts) and the fake pubsub
 * server. Also: everything outside the allowlist is left alone.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { installBridge, FALLBACK_BODY } from "../src/omemo/bridge.js";
import { parseXml, serialize } from "../src/omemo/xml.js";
import { createFakePepServer } from "./fake-pep.js";
import { createFakeThunderbird, parseToXmlNode } from "./fake-thunderbird.js";
import { createStore } from "../src/omemo/store.js";
import * as f from "../src/omemo/formats.js";
import { encryptMessage, decryptMessage } from "../src/omemo/messages.js";

const T1 = "test1@example.org";
const T2 = "test2@example.org";
const CAROL = "carol@example.org";

function memoryFile() {
  let text = null;
  return { read: async () => text, write: async (t) => { text = t; } };
}

const tick = (ms = 5) => new Promise((r) => setTimeout(r, ms));

async function until(check, what) {
  for (let i = 0; i < 400; i++) {
    if (check()) {
      return;
    }
    await tick();
  }
  assert.fail(`timed out waiting for ${what}`);
}

/** Two (or more) connected accounts with OMEMO ready. */
const STATES = { NOT_SUPPORTED: 0, AVAILABLE: 1, ENABLED: 2, TRUSTED: 3 };

async function setup(jids = [T1, T2], { allowlist = [T1, T2], optIn = false, mode, now, setTimer = setTimeout } = {}) {
  const server = createFakePepServer();
  const tb = createFakeThunderbird(server);
  const lines = [];
  // One file per account, kept across reconnects.
  const files = new Map();
  const bridge = installBridge({
    ...tb,
    now,
    setTimer,
    clearTimer: clearTimeout,
    appName: "Thunderbird",
    fileAccessFor: (jid) => {
      if (!files.has(jid)) {
        files.set(jid, memoryFile());
      }
      return files.get(jid);
    },
    log: (l) => lines.push(l),
    encryptionAllowlist: allowlist,
    optIn,
    mode,
    encryptionStates: STATES,
  });
  const accounts = {};
  for (const jid of jids) {
    accounts[jid] = tb.makeAccount(jid);
    accounts[jid].onConnection();
  }
  await until(() => jids.every((j) => lines.some((l) => l.startsWith(`OMEMO ready for ${j}`))), "OMEMO to start");
  return { server, tb, lines, bridge, accounts, files };
}

const bodies = (account) => account.received.map((r) => r.body);

test("test1 and test2 exchange encrypted messages; the session is confirmed and the key exchange stops", async () => {
  const { tb, accounts, bridge, lines } = await setup();
  const conv1 = tb.makeConversation(accounts[T1], T2);
  conv1.dispatchMessage("Hello from test1");
  await until(() => accounts[T2].received.length === 1, "test2 to receive");

  // On the wire: a fallback body, twomemo <encrypted>, hints; no plaintext.
  const sent = accounts[T1].sent.find((x) => x.startsWith("<message"));
  assert.match(sent, /<body>This message is OMEMO encrypted/);
  assert.match(sent, /<encrypted xmlns="urn:xmpp:omemo:2">.*kex="true"/);
  assert.match(sent, /<store xmlns="urn:xmpp:hints"\/>/);
  assert.match(sent, /<encryption xmlns="urn:xmpp:eme:0" namespace="urn:xmpp:omemo:2" name="OMEMO"\/>/);
  assert.doesNotMatch(sent, /Hello from test1/);
  assert.equal(tb.calls.filter((c) => c[0] === "dispatchMessage").length, 0, "Thunderbird's plaintext send never ran");

  // test2's Thunderbird shows the plaintext; test1 sees its own local echo.
  assert.deepEqual(bodies(accounts[T2]), ["Hello from test1"]);
  assert.deepEqual(conv1.shown.map((m) => [m.text, m.flags.outgoing, m.flags.isEncrypted]), [["Hello from test1", true, true]]);
  assert.equal(conv1.shown[0].who, `${T1}/Thunderbird`);

  // test2 confirmed the new session with an empty message; test1 swallowed it.
  await until(() => lines.some((l) => /decrypted a twomemo empty message from test2/.test(l)), "the confirmation");
  assert.equal(accounts[T1].received.length, 0, "the empty message never reached a conversation");
  const session = bridge.accounts.get(accounts[T1]).store.session("twomemo", T2, bridge.accounts.get(accounts[T2]).store.deviceId);
  assert.equal(session.pendingKeyExchange, null, "confirmed");

  // Next message: no key exchange. And a reply the other way.
  conv1.dispatchMessage("Second");
  await until(() => accounts[T2].received.length === 2, "the second message");
  assert.doesNotMatch(accounts[T1].sent.filter((x) => x.startsWith("<message")).at(-1), /kex=/);
  const conv2 = tb.makeConversation(accounts[T2], `${T1}/Thunderbird`);
  conv2.dispatchMessage("Hi test1!");
  await until(() => accounts[T1].received.length === 1, "the reply");
  assert.deepEqual(bodies(accounts[T1]), ["Hi test1!"]);
  assert.deepEqual(bodies(accounts[T2]), ["Hello from test1", "Second"]);
});

test("rapid messages arrive in the order they were sent", async () => {
  const { tb, accounts } = await setup();
  const conv = tb.makeConversation(accounts[T1], T2);
  for (let i = 1; i <= 5; i++) {
    conv.dispatchMessage(`message ${i}`);
  }
  await until(() => accounts[T2].received.length === 5, "five messages");
  assert.deepEqual(bodies(accounts[T2]), ["message 1", "message 2", "message 3", "message 4", "message 5"]);
});

test("/me actions go through encrypted, marked as Thunderbird marks them", async () => {
  const { tb, accounts } = await setup();
  tb.makeConversation(accounts[T1], T2).dispatchMessage(" waves", true);
  await until(() => accounts[T2].received.length === 1, "the action");
  assert.deepEqual(bodies(accounts[T2]), ["/me waves"]);
});

test("a contact that publishes only oldmemo gets oldmemo", async () => {
  const { server, tb, accounts } = await setup();
  server.accounts.get(T2).delete("urn:xmpp:omemo:2:devices");
  tb.makeConversation(accounts[T1], T2).dispatchMessage("old school");
  await until(() => accounts[T2].received.length === 1, "the oldmemo message");
  assert.match(accounts[T1].sent.find((x) => x.startsWith("<message")), /<encrypted xmlns="eu\.siacs\.conversations\.axolotl">.*prekey="true".*<iv>/);
  assert.deepEqual(bodies(accounts[T2]), ["old school"]);
});

test("conversations outside the allowlist are untouched in both directions", async () => {
  const { tb, accounts, lines } = await setup([T1, T2, CAROL]);
  // Sending to Carol: Thunderbird's own plaintext send.
  tb.makeConversation(accounts[T1], CAROL).dispatchMessage("plain hello");
  assert.deepEqual(tb.calls.filter((c) => c[0] === "dispatchMessage").map((c) => c[2]), ["plain hello"]);

  // An OMEMO message from Carol to test1: left as it came, fallback and all,
  // and no automatic reply.
  const fromCarol = parseToXmlNode(`<message xmlns="jabber:client" from="${CAROL}/phone" to="${T1}" type="chat">` +
    `<body>${FALLBACK_BODY}</body><encrypted xmlns="urn:xmpp:omemo:2"><header sid="5"><keys jid="${T1}">` +
    `<key rid="12345">AAAA</key></keys></header><payload>AAAA</payload></encrypted></message>`);
  const sentBefore = accounts[T1].sent.length;
  accounts[T1].onMessageStanza(fromCarol);
  assert.deepEqual(bodies(accounts[T1]), [FALLBACK_BODY]);
  await tick(20);
  assert.equal(accounts[T1].sent.length, sentBefore, "nothing sent back to Carol");
  assert.equal(lines.some((l) => /decrypt/.test(l)), false);
});

test("with an empty allowlist nothing is ever encrypted", async () => {
  const { tb, accounts } = await setup([T1, T2], { allowlist: [] });
  tb.makeConversation(accounts[T1], T2).dispatchMessage("hi");
  assert.equal(tb.calls.filter((c) => c[0] === "dispatchMessage").length, 1);
});

test("a message that can't be encrypted is not sent, and the conversation says so", async () => {
  const { tb, accounts, server } = await setup();
  // test2 without any OMEMO devices.
  server.accounts.get(T2).delete("urn:xmpp:omemo:2:devices");
  server.accounts.get(T2).delete("eu.siacs.conversations.axolotl.devicelist");
  const conv = tb.makeConversation(accounts[T1], T2);
  const sentBefore = accounts[T1].sent.filter((x) => x.startsWith("<message")).length;
  conv.dispatchMessage("secret");
  await until(() => conv.shown.length === 1, "the error notice");
  assert.equal(conv.shown[0].flags.error, true);
  assert.match(conv.shown[0].text, /not sent, because it couldn't be encrypted: test2@example\.org has no OMEMO devices/);
  assert.equal(accounts[T1].sent.filter((x) => x.startsWith("<message")).length, sentBefore, "nothing went out");
  assert.equal(tb.calls.filter((c) => c[0] === "dispatchMessage").length, 0, "and never in plaintext");
});

test("carbons go through decryption too: a replayed message arriving as a carbon gets a notice", async () => {
  const { tb, accounts } = await setup();
  tb.makeConversation(accounts[T1], T2).dispatchMessage("via carbon");
  await until(() => accounts[T2].received.length === 1, "delivery");
  // Replay the same encrypted stanza to test2 as a <received> carbon: it's a
  // duplicate now, so the ratchet refuses it, and the notice says so.
  const original = parseXml(accounts[T2].received[0].xml);
  const encryptedXml = serialize(original.children.find((c) => c.name === "encrypted"));
  const carbon = parseToXmlNode(`<message xmlns="jabber:client" from="${T2}" to="${T2}/Thunderbird">` +
    `<received xmlns="urn:xmpp:carbons:2"><forwarded xmlns="urn:xmpp:forward:0"><message xmlns="jabber:client" from="${T1}/Thunderbird" to="${T2}" type="chat">` +
    `<body>${FALLBACK_BODY}</body>${encryptedXml}</message></forwarded></received></message>`);
  accounts[T2].onMessageStanza(carbon);
  const xml = accounts[T2].received.at(-1).xml;
  assert.match(xml, /<forwarded[^>]*><message[^>]*>.*\[OMEMO\] This message couldn't be decrypted \(damaged, repeated or out of sync\)/);
  assert.doesNotMatch(xml, /This message is OMEMO encrypted/, "the fallback body is gone");
});

test("a message not encrypted for this device shows a notice instead of the fallback", async () => {
  const { accounts } = await setup();
  accounts[T2].onMessageStanza(parseToXmlNode(`<message xmlns="jabber:client" from="${T1}/phone" to="${T2}" type="chat">` +
    `<body>${FALLBACK_BODY}</body><encrypted xmlns="urn:xmpp:omemo:2"><header sid="77"><keys jid="${T2}"><key rid="1">AAAA</key></keys></header>` +
    `<payload>AAAA</payload></encrypted></message>`));
  assert.deepEqual(bodies(accounts[T2]), ["[OMEMO] This message wasn't encrypted for this device."]);
});

// --- a Conversations-style phone (oldmemo only) next to Thunderbird ---

/** Puts an oldmemo-only "phone" device on `jid`'s account, as Cheogram would publish it. */
function addPhone(server, bridge, account, jid) {
  const phone = createStore();
  const ownId = bridge.accounts.get(account).store.deviceId;
  server.put(jid, f.bundleLocation("oldmemo", phone.deviceId).node, "current", f.buildBundle("oldmemo", phone.bundle("oldmemo")));
  server.put(jid, "eu.siacs.conversations.axolotl.devicelist", "current",
    f.buildDeviceList("oldmemo", [{ id: ownId }, { id: phone.deviceId }]));
  return phone;
}

test("a contact with Thunderbird (both namespaces) and an oldmemo-only phone gets both in one message", async () => {
  const { server, tb, accounts, bridge, lines } = await setup();
  const phone = addPhone(server, bridge, accounts[T2], T2);
  tb.makeConversation(accounts[T1], T2).dispatchMessage("to desktop and phone");
  await until(() => accounts[T2].received.length === 1, "delivery");
  assert.deepEqual(bodies(accounts[T2]), ["to desktop and phone"], "Thunderbird read the twomemo part");
  assert.match(lines.find((l) => l.startsWith("sent an encrypted message to test2")), /twomemo: 1 device keys, oldmemo: 1 device keys/);

  // The phone reads the oldmemo part of the same stanza.
  const stanza = parseXml(accounts[T1].sent.find((x) => x.startsWith("<message")));
  const encrypted = stanza.children.filter((c) => c.name === "encrypted");
  assert.deepEqual(encrypted.map((e) => e.ns), ["urn:xmpp:omemo:2", "eu.siacs.conversations.axolotl"]);
  assert.equal(stanza.children.filter((c) => c.name === "encryption").length, 2);
  const forPhone = f.parseEncrypted(encrypted[1]);
  const got = decryptMessage(phone, forPhone, { ourJid: T2, sender: `${T1}/Thunderbird` });
  assert.equal(got.body, "to desktop and phone");
});

test("a message from the phone is read, and the confirmation meant for the phone doesn't bother test2's Thunderbird", async () => {
  const { server, tb, accounts, bridge, lines } = await setup();
  const phone = addPhone(server, bridge, accounts[T2], T2);
  const t1 = bridge.accounts.get(accounts[T1]);
  const t1Bundle = f.parseBundle("oldmemo", parseXml(serialize(f.buildBundle("oldmemo", t1.store.bundle("oldmemo")))));
  const { encrypted } = encryptMessage(phone, "oldmemo", {
    ourJid: T2,
    body: "sent from my phone",
    recipients: [{ jid: T1, deviceId: t1.store.deviceId, bundle: t1Bundle }],
  });
  const fromPhone = `<message xmlns="jabber:client" from="${T2}/Cheogram" to="${T1}" type="chat"><body>${FALLBACK_BODY}</body>` +
    `${serialize(f.buildEncrypted("oldmemo", encrypted))}</message>`;
  accounts[T1].onMessageStanza(parseToXmlNode(fromPhone));
  assert.deepEqual(bodies(accounts[T1]), ["sent from my phone"]);

  // test1 confirms the phone's new session with an empty message to test2,
  // which the server also delivers to test2's Thunderbird: ignored quietly.
  await until(() => lines.some((l) => /ignored an empty message from test1@example\.org meant for another device/.test(l)), "the ignore");
  assert.equal(accounts[T2].received.length, 0, "no notice in test2's conversation");
  // The phone can read it.
  const confirmation = parseXml(accounts[T1].sent.filter((x) => x.startsWith("<message")).at(-1));
  const parsed = f.parseEncrypted(confirmation.children.find((c) => c.name === "encrypted"));
  assert.equal(parsed.namespace, "oldmemo");
  assert.equal(decryptMessage(phone, parsed, { ourJid: T2, sender: `${T1}/Thunderbird` }).body, null);
});

test("a message our own phone sent arrives as a sent carbon: decrypted, shown as ours, with a padlock", async () => {
  const { server, tb, accounts, bridge, lines } = await setup();
  const myPhone = addPhone(server, bridge, accounts[T2], T2);
  const t2 = bridge.accounts.get(accounts[T2]).store;
  const t2Bundle = f.parseBundle("oldmemo", parseXml(serialize(f.buildBundle("oldmemo", t2.bundle("oldmemo")))));
  // The phone encrypts for its own account's Thunderbird too (as Cheogram does).
  const { encrypted } = encryptMessage(myPhone, "oldmemo", {
    ourJid: T2,
    body: "Ooo",
    recipients: [{ jid: T2, deviceId: t2.deviceId, bundle: t2Bundle }],
  });
  const conv = tb.makeConversation(accounts[T2], T1);
  accounts[T2].onMessageStanza(parseToXmlNode(`<message xmlns="jabber:client" from="${T2}" to="${T2}/Thunderbird">` +
    `<sent xmlns="urn:xmpp:carbons:2"><forwarded xmlns="urn:xmpp:forward:0"><message xmlns="jabber:client" from="${T2}/Cheogram" to="${T1}" type="chat">` +
    `<body>${FALLBACK_BODY}</body>${serialize(f.buildEncrypted("oldmemo", encrypted))}</message></forwarded></sent></message>`));
  const shown = conv.shown.filter((m) => !m.flags.system);
  assert.deepEqual(shown.map((m) => [m.text, m.flags.outgoing, m.flags.isEncrypted]), [["Ooo", true, true]]);
  assert.notEqual(t2.lastMessageFrom(T2, myPhone.deviceId), null, "the phone's last message is recorded");
});

test("our own oldmemo-only phone gets a copy of what we send", async () => {
  const { server, tb, accounts, bridge } = await setup();
  const myPhone = addPhone(server, bridge, accounts[T1], T1);
  // test1's store learns its own lists on the next connect, or from a push;
  // here, set them as a push would.
  bridge.accounts.get(accounts[T1]).store.setDevices("oldmemo", T1,
    [{ id: bridge.accounts.get(accounts[T1]).store.deviceId }, { id: myPhone.deviceId }]);
  tb.makeConversation(accounts[T1], T2).dispatchMessage("copy for my phone");
  await until(() => accounts[T2].received.length === 1, "delivery");
  const stanza = parseXml(accounts[T1].sent.find((x) => x.startsWith("<message")));
  const old = f.parseEncrypted(stanza.children.find((c) => c.name === "encrypted" && c.ns === "eu.siacs.conversations.axolotl"));
  assert.equal(decryptMessage(myPhone, old, { ourJid: T1, sender: `${T1}/Thunderbird` }).body, "copy for my phone");
});

// --- Thunderbird's encryption UI: padlocks and the conversation lock ---

test("decrypted messages get a padlock like our own sent ones; failure notices don't", async () => {
  const { tb, accounts } = await setup();
  const conv2 = tb.makeConversation(accounts[T2], T1);
  tb.makeConversation(accounts[T1], T2).dispatchMessage("padlock please");
  await until(() => conv2.shown.length === 1, "the message in test2's conversation");
  assert.deepEqual([conv2.shown[0].text, conv2.shown[0].flags.isEncrypted], ["padlock please", true]);

  accounts[T2].onMessageStanza(parseToXmlNode(`<message xmlns="jabber:client" from="${T1}/phone" to="${T2}" type="chat">` +
    `<body>${FALLBACK_BODY}</body><encrypted xmlns="urn:xmpp:omemo:2"><header sid="77"><keys jid="${T2}"><key rid="1">AAAA</key></keys></header>` +
    `<payload>AAAA</payload></encrypted></message>`));
  assert.equal(conv2.shown.at(-1).text, "[OMEMO] This message wasn't encrypted for this device.");
  assert.notEqual(conv2.shown.at(-1).flags.isEncrypted, true);

  // Messages that weren't OMEMO at all stay unflagged.
  accounts[T2].onMessageStanza(parseToXmlNode(`<message xmlns="jabber:client" from="${T1}/phone" to="${T2}" type="chat"><body>plain</body></message>`));
  assert.notEqual(conv2.shown.at(-1).flags.isEncrypted, true);
});

test("the lock: test1-test2 chats show encrypted, others nothing, and the switch is off in allowlist mode", async () => {
  const { tb, accounts, lines } = await setup([T1, T2, CAROL]);
  const withT2 = tb.makeConversation(accounts[T1], `${T2}/Thunderbird`);
  const withCarol = tb.makeConversation(accounts[T1], CAROL);
  assert.equal(withT2.encryptionState, STATES.ENABLED);
  assert.equal(withCarol.encryptionState, STATES.NOT_SUPPORTED);
  withCarol.initializeEncryption();
  assert.match(lines.at(-1), /can't be switched on for carol@example\.org in this build/);
  assert.equal(withCarol.encryptionState, STATES.NOT_SUPPORTED);
  withCarol.dispatchMessage("still plaintext");
  assert.deepEqual(tb.calls.filter((c) => c[0] === "dispatchMessage").map((c) => c[2]), ["still plaintext"]);
});

test("conversations opened before OMEMO was ready are told to redraw their lock once it is", async () => {
  const server = createFakePepServer();
  const tb = createFakeThunderbird(server);
  const lines = [];
  installBridge({
    ...tb, setTimer: setTimeout, clearTimer: clearTimeout, appName: "Thunderbird", fileAccessFor: memoryFile,
    log: (l) => lines.push(l), encryptionAllowlist: [T1, T2], encryptionStates: STATES,
  });
  const account = tb.makeAccount(T1);
  const conversation = tb.makeConversation(account, T2);
  assert.equal(conversation.encryptionState, STATES.NOT_SUPPORTED, "not ready yet");
  account.onConnection();
  await until(() => conversation.notifications.includes("update-conv-encryption"), "the redraw");
  assert.equal(conversation.encryptionState, STATES.ENABLED);
});

test("opt-in mode: the lock offers encryption for a contact with OMEMO, and switching it on sticks", async () => {
  const { tb, accounts, bridge, lines } = await setup([T1, CAROL], { allowlist: [], optIn: true });
  const conv = tb.makeConversation(accounts[T1], CAROL);
  // Carol's devices aren't known yet: looked up in the background, then a redraw.
  assert.equal(conv.encryptionState, STATES.NOT_SUPPORTED);
  await until(() => conv.notifications.includes("update-conv-encryption"), "the lookup");
  assert.equal(conv.encryptionState, STATES.AVAILABLE);

  conv.dispatchMessage("before switching on");
  assert.deepEqual(tb.calls.filter((c) => c[0] === "dispatchMessage").map((c) => c[2]), ["before switching on"]);

  conv.initializeEncryption();
  assert.equal(conv.encryptionState, STATES.ENABLED);
  assert.match(lines.join("\n"), /encryption switched on for carol@example\.org/);
  assert.equal(bridge.accounts.get(accounts[T1]).store.encryptionEnabled(CAROL), true, "remembered in the store");

  conv.dispatchMessage("after switching on");
  await until(() => accounts[CAROL].received.length === 1, "Carol's copy");
  assert.deepEqual(bodies(accounts[CAROL]), ["after switching on"], "Carol decrypts it (opt-in mode reads whatever arrives)");
  assert.equal(tb.calls.filter((c) => c[0] === "dispatchMessage").length, 1, "not sent in plaintext");
});

test("opt-in mode: a contact without OMEMO devices never gets the switch", async () => {
  const { tb, accounts } = await setup([T1], { allowlist: [], optIn: true });
  const conv = tb.makeConversation(accounts[T1], "nobody@example.org");
  assert.equal(conv.encryptionState, STATES.NOT_SUPPORTED);
  await tick(50);
  assert.equal(conv.encryptionState, STATES.NOT_SUPPORTED);
  assert.deepEqual(conv.notifications, []);
});

test("uninstall removes the encryption members and the padlock wrapper", async () => {
  const { tb, bridge } = await setup();
  const proto = tb.xmppBase.XMPPConversationPrototype;
  assert.ok(Object.getOwnPropertyDescriptor(proto, "encryptionState"));
  await bridge.uninstall();
  for (const name of ["encryptionState", "initializeEncryption", "writeMessage"]) {
    assert.equal(Object.getOwnPropertyDescriptor(proto, name), undefined, name);
  }
});

// --- the modes and the /omemo command ---

const plainSends = (tb) => tb.calls.filter((c) => c[0] === "dispatchMessage").map((c) => c[2]);
const lastSaid = (conv) => conv.shown.filter((m) => m.flags.system).at(-1)?.text ?? "";

test("mode 'available': contacts with OMEMO are encrypted without a click; others stay plaintext and aren't re-queried", async () => {
  const { tb, accounts, server } = await setup([T1, CAROL], { allowlist: [], mode: "available" });
  const withCarol = tb.makeConversation(accounts[T1], CAROL);
  withCarol.dispatchMessage("automatic");
  await until(() => accounts[CAROL].received.length === 1, "Carol's copy");
  assert.deepEqual(bodies(accounts[CAROL]), ["automatic"]);
  assert.deepEqual(plainSends(tb), []);
  assert.equal(withCarol.encryptionState, STATES.ENABLED);

  const sms = tb.makeConversation(accounts[T1], "+15551234567@cheogram.com");
  const queries = () => server.log.filter((l) => l.iq.includes("cheogram.com")).length;
  sms.dispatchMessage("hello by SMS");
  await until(() => plainSends(tb).length === 1, "the plaintext send");
  const afterFirst = queries();
  assert.ok(afterFirst > 0, "looked the contact up once");
  sms.dispatchMessage("second SMS");
  await until(() => plainSends(tb).length === 2, "the second send");
  assert.equal(queries(), afterFirst, "not looked up again");
  assert.deepEqual(plainSends(tb), ["hello by SMS", "second SMS"]);
  assert.equal(sms.encryptionState, STATES.NOT_SUPPORTED);
});

test("mode 'always': a contact without OMEMO isn't messaged until /omemo off; the notice says how", async () => {
  const { tb, bridge, accounts } = await setup([T1], { allowlist: [], mode: "always" });
  const sms = tb.makeConversation(accounts[T1], "+15551234567@cheogram.com");
  sms.dispatchMessage("blocked");
  await until(() => sms.shown.some((m) => m.flags.error), "the error");
  assert.match(sms.shown.find((m) => m.flags.error).text, /has no OMEMO devices \(type \/omemo off to allow unencrypted messages with them\)/);
  assert.deepEqual(plainSends(tb), []);

  assert.equal(bridge.runCommand(sms, "off"), true);
  assert.match(lastSaid(sms), /Encryption is off for this chat: messages go out unencrypted/);
  sms.dispatchMessage("now allowed");
  await until(() => plainSends(tb).length === 1, "the plaintext send");
  assert.deepEqual(plainSends(tb), ["now allowed"]);
});

/**
 * Makes the fake server answer requests to `jid`'s nodes whose name
 * matches `nodePattern` with a timeout error. Returns a function that stops it.
 */
function failLookups(server, jid, nodePattern) {
  const connect = server.connect;
  server.connect = (from) => {
    const send = connect(from);
    return (iq) => {
      const text = serialize(iq);
      if (text.includes(`to="${jid}"`) && nodePattern.test(text)) {
        return Promise.resolve(parseXml(`<iq xmlns="jabber:client" type="error"><error type="wait">` +
          `<remote-server-timeout xmlns="urn:ietf:params:xml:ns:xmpp-stanzas"/></error></iq>`));
      }
      return send(iq);
    };
  };
  return () => {
    server.connect = connect;
  };
}

const errors = (conv) => conv.shown.filter((m) => m.flags.error).map((m) => m.text);

test("mode 'available': a failed device lookup blocks the message instead of sending plaintext, and isn't remembered", async () => {
  const { tb, accounts, server, bridge } = await setup([T1, CAROL], { allowlist: [], mode: "available" });
  const conv = tb.makeConversation(accounts[T1], CAROL);

  // Both namespaces time out.
  let stop = failLookups(server, CAROL, /devicelist|omemo:2:devices/);
  conv.dispatchMessage("first");
  await until(() => errors(conv).length === 1, "the first error");
  assert.match(errors(conv)[0], /not sent.*couldn't check whether carol@example\.org uses OMEMO \(PEP request failed: remote-server-timeout\)\. Try again in a moment\./);
  bridge.runCommand(conv, "status");
  await until(() => /couldn't be looked up just now/.test(lastSaid(conv)), "the status");
  stop();

  // Only oldmemo fails, while twomemo would have answered: still not plaintext.
  stop = failLookups(server, CAROL, /devicelist/);
  conv.dispatchMessage("second");
  await until(() => errors(conv).length === 2, "the second error");
  stop();

  // The lookup works again: not remembered as "no OMEMO", so it's encrypted.
  conv.dispatchMessage("third");
  await until(() => accounts[CAROL].received.length === 1, "Carol's copy");
  assert.deepEqual(bodies(accounts[CAROL]), ["third"]);
  assert.deepEqual(plainSends(tb), [], "nothing ever went out in plaintext");
});

test("a message sent while OMEMO starts waits for it: an encrypted chat stays encrypted", async () => {
  const { tb, accounts, bridge } = await setup([T1, CAROL], { allowlist: [], mode: "manual" });
  const conv = tb.makeConversation(accounts[T1], CAROL);
  bridge.runCommand(conv, "on");
  await bridge.saveAll();
  // Reconnect, and send before the key store (which has the "on") is loaded.
  accounts[T1]._disconnect();
  accounts[T1].onConnection();
  assert.equal(bridge.accounts.get(accounts[T1]).store, null, "not loaded yet");
  conv.dispatchMessage("right away");
  await until(() => accounts[CAROL].received.length === 1, "Carol's copy");
  assert.deepEqual(bodies(accounts[CAROL]), ["right away"]);
  assert.deepEqual(plainSends(tb), []);
});

test("mode 'available': a message sent while OMEMO starts is encrypted for a contact with OMEMO", async () => {
  const { tb, accounts, bridge } = await setup([T1, CAROL], { allowlist: [], mode: "available" });
  const conv = tb.makeConversation(accounts[T1], CAROL);
  accounts[T1]._disconnect();
  accounts[T1].onConnection();
  assert.equal(bridge.accounts.get(accounts[T1]).store, null, "not loaded yet");
  conv.dispatchMessage("early");
  await until(() => accounts[CAROL].received.length === 1, "Carol's copy");
  assert.deepEqual(bodies(accounts[CAROL]), ["early"]);
  assert.deepEqual(plainSends(tb), []);
});

test("if OMEMO fails to start, messages aren't sent in plaintext; the chat says why", async () => {
  const { tb, accounts, files } = await setup([T1, CAROL], { allowlist: [], mode: "manual" });
  const conv = tb.makeConversation(accounts[T1], CAROL);
  accounts[T1]._disconnect();
  files.set(T1, { read: async () => { throw new Error("unreadable"); }, write: async () => {} });
  accounts[T1].onConnection();
  conv.dispatchMessage("hello");
  await until(() => errors(conv).length === 1, "the error");
  assert.match(errors(conv)[0], /OMEMO isn't ready for this account yet, so it can't tell whether this chat is encrypted\. Try again in a moment\./);
  assert.deepEqual(plainSends(tb), []);
});

test("a device the contact removed while we were offline gets no key in the next message", async () => {
  const { tb, accounts, bridge, server } = await setup([T1, CAROL], { allowlist: [], mode: "always" });
  const conv = tb.makeConversation(accounts[T1], CAROL);
  const carolDevice = bridge.accounts.get(accounts[CAROL]).store.deviceId;
  const lostPhone = createStore();
  const devicesNode = f.deviceListLocation("twomemo").node;
  server.put(CAROL, devicesNode, "current", f.buildDeviceList("twomemo", [{ id: carolDevice }, { id: lostPhone.deviceId }]));
  server.put(CAROL, f.bundleLocation("twomemo", lostPhone.deviceId).node, String(lostPhone.deviceId),
    f.buildBundle("twomemo", lostPhone.bundle("twomemo")));
  conv.dispatchMessage("before");
  await until(() => accounts[CAROL].received.length === 1, "the first message");
  const keysTo = (xml) => [...xml.matchAll(/<key rid="(\d+)"/g)].map((m) => Number(m[1]));
  assert.ok(keysTo(accounts[T1].sent.filter((x) => x.startsWith("<message")).at(-1)).includes(lostPhone.deviceId));

  // Offline: Carol removes the lost phone; no push reaches test1.
  accounts[T1]._disconnect();
  server.put(CAROL, devicesNode, "current", f.buildDeviceList("twomemo", [{ id: carolDevice }]));
  accounts[T1].onConnection();
  await until(() => bridge.accounts.get(accounts[T1])?.store, "OMEMO to start again");
  conv.dispatchMessage("after");
  await until(() => accounts[CAROL].received.length === 2, "the second message");
  assert.equal(keysTo(accounts[T1].sent.filter((x) => x.startsWith("<message")).at(-1)).includes(lostPhone.deviceId), false);
});

test("mode 'manual' with /omemo on, off and default", async () => {
  const { tb, bridge, accounts } = await setup([T1, CAROL], { allowlist: [], mode: "manual" });
  const conv = tb.makeConversation(accounts[T1], CAROL);
  conv.dispatchMessage("plain first");
  assert.deepEqual(plainSends(tb), ["plain first"]);

  bridge.runCommand(conv, " ON ");
  assert.equal(conv.encryptionState, STATES.ENABLED);
  assert.ok(conv.notifications.includes("update-conv-encryption"));
  conv.dispatchMessage("encrypted now");
  await until(() => accounts[CAROL].received.length === 1, "Carol's copy");
  assert.deepEqual(bodies(accounts[CAROL]), ["encrypted now"]);

  bridge.runCommand(conv, "default");
  assert.match(lastSaid(conv), /follows your setting again \(off unless switched on per chat\)/);
  conv.dispatchMessage("plain again");
  await until(() => plainSends(tb).length === 2, "the plaintext send");
  bridge.runCommand(conv, "nonsense");
  assert.match(lastSaid(conv), /Usage: \/omemo \[on \| off \| default \| status \| help \| qr \| verify <device> \[fingerprint\] \| trust <device> \| distrust <device> \| remove <device>\]/);
});

test("/omemo status shows the setting, this device's fingerprint and the contact's devices, labeled", async () => {
  const { tb, bridge, accounts, lines } = await setup();
  const conv = tb.makeConversation(accounts[T1], T2);
  conv.dispatchMessage("so a session exists");
  await until(() => accounts[T2].received.length === 1, "delivery");
  // test2's confirmation is its last message; an old phone install never wrote.
  await until(() => lines.some((l) => /decrypted a twomemo empty message from test2/.test(l)), "the confirmation");
  const t1store = bridge.accounts.get(accounts[T1]).store;
  t1store.setDevices("oldmemo", T2, [...t1store.devices("oldmemo", T2), { id: 4242 }]);
  const before = conv.shown.length;
  bridge.runCommand(conv, "");
  await until(() => conv.shown.length > before, "the status");
  const status = lastSaid(conv);
  const t1 = bridge.accounts.get(accounts[T1]).store;
  const t2 = bridge.accounts.get(accounts[T2]).store;
  assert.match(status, /Setting: test build \(fixed list\)/);
  assert.match(status, /Messages to test2@example\.org are encrypted/);
  assert.ok(status.includes(`This Thunderbird: device ${t1.deviceId}, fingerprint `));
  const fp = (store) => Array.from(store.identityKeyPair().publicKey.curve25519, (b) => b.toString(16).padStart(2, "0")).join("").match(/.{8}/g).join(" ");
  assert.ok(status.includes(fp(t1)), "our fingerprint");
  const statusLines = status.split("\n");
  const contact = statusLines.slice(statusLines.indexOf("test2@example.org's devices:") + 1);
  assert.equal(contact[0], `- device ${t2.deviceId}, "Thunderbird": last message just now; ${fp(t2)} (trusted automatically, not verified)`,
    "the contact's Thunderbird, by its label, heard from most recently");
  assert.equal(contact[1], "- device 4242, older OMEMO: no messages from it yet; fingerprint not known yet");
  assert.match(status, /old installs stay listed/);
  assert.equal(conv.shown.at(-1).flags.noLog, true, "status lines aren't logged");
});

test("the options page's setting takes effect at once and redraws the locks", async () => {
  const { tb, bridge, accounts } = await setup([T1, CAROL], { allowlist: [], mode: "manual" });
  const conv = tb.makeConversation(accounts[T1], CAROL);
  await until(() => conv.encryptionState === STATES.AVAILABLE, "the device lookup");
  const redraws = conv.notifications.length;
  bridge.updateSettings({ mode: "available" });
  assert.ok(conv.notifications.length > redraws);
  assert.equal(conv.encryptionState, STATES.ENABLED);
  assert.throws(() => bridge.updateSettings({ mode: "sometimes" }), /Unknown encryption mode/);
  bridge.updateSettings({ mode: null });
  assert.equal(conv.encryptionState, STATES.NOT_SUPPORTED);
});

test("the /omemo command ignores group chats and other conversations", async () => {
  const { bridge } = await setup();
  assert.equal(bridge.runCommand({ name: "room@muc" }, "on"), false);
});

// --- trust (milestone 5): blind trust before verification ---

/** A fingerprint as fingerprint.js formats it, from a store's identity key. */
const fpOf = (store) => Array.from(store.identityKeyPair().publicKey.curve25519, (b) => b.toString(16).padStart(2, "0")).join("").match(/.{8}/g).join(" ");

test("verifying a device makes the lock say verified; the fingerprint must match if given", async () => {
  const { tb, bridge, accounts } = await setup();
  const conv = tb.makeConversation(accounts[T1], T2);
  conv.dispatchMessage("first");
  await until(() => accounts[T2].received.length === 1, "delivery");
  const t2 = bridge.accounts.get(accounts[T2]).store;
  assert.equal(conv.encryptionState, STATES.ENABLED, "blindly trusted: encrypted, not verified");

  bridge.runCommand(conv, `verify ${t2.deviceId} 00000000`);
  await until(() => /doesn't match/.test(lastSaid(conv)), "the mismatch");
  assert.equal(conv.encryptionState, STATES.ENABLED);

  bridge.runCommand(conv, `verify ${t2.deviceId} ${fpOf(t2)}`);
  await until(() => /is now verified/.test(lastSaid(conv)), "the verification");
  assert.equal(conv.encryptionState, STATES.TRUSTED);

  const before = conv.shown.length;
  bridge.runCommand(conv, "");
  await until(() => conv.shown.length > before, "the status");
  assert.ok(lastSaid(conv).split("\n").some((l) => l.startsWith(`- device ${t2.deviceId}, "Thunderbird": `) && l.endsWith(`; ${fpOf(t2)} (verified)`)));
});

test("after verifying, a contact's new device is held back until trusted, and the chat says so", async () => {
  const { server, tb, bridge, accounts, lines } = await setup();
  const conv = tb.makeConversation(accounts[T1], T2);
  conv.dispatchMessage("first");
  await until(() => accounts[T2].received.length === 1, "delivery");
  const t2 = bridge.accounts.get(accounts[T2]).store;
  bridge.runCommand(conv, `verify ${t2.deviceId}`);
  await until(() => /is now verified/.test(lastSaid(conv)), "the verification");

  // test2 gets a Cheogram phone; test1 learns of it (as from a push).
  const phone = addPhone(server, bridge, accounts[T2], T2);
  bridge.accounts.get(accounts[T1]).store.setDevices("oldmemo", T2, [{ id: t2.deviceId }, { id: phone.deviceId }]);
  conv.dispatchMessage("second");
  await until(() => conv.shown.some((m) => /has a new device/.test(m.text)), "the new-device notice");
  assert.ok(conv.shown.find((m) => /has a new device/.test(m.text)).text
    .includes(`has a new device (${phone.deviceId}, ${fpOf(phone)}). Messages aren't encrypted to it`));
  await until(() => accounts[T2].received.length === 2, "delivery to test2's Thunderbird");
  const sent = parseXml(accounts[T1].sent.filter((x) => x.startsWith("<message")).at(-1));
  assert.equal(sent.children.filter((c) => c.name === "encrypted").length, 1, "no oldmemo part for the held-back phone");
  assert.ok(lines.includes(`not encrypting to ${T2} device ${phone.deviceId}: its key is undecided`), "held-back devices are logged");
  assert.equal(conv.encryptionState, STATES.ENABLED, "no longer all verified");

  bridge.runCommand(conv, `trust ${phone.deviceId}`);
  await until(() => /is now approved by you/.test(lastSaid(conv)), "the approval");
  conv.dispatchMessage("third");
  await until(() => accounts[T2].received.length === 3, "delivery");
  const third = parseXml(accounts[T1].sent.filter((x) => x.startsWith("<message")).at(-1));
  const old = f.parseEncrypted(third.children.find((c) => c.ns === "eu.siacs.conversations.axolotl"));
  assert.equal(decryptMessage(phone, old, { ourJid: T2, sender: `${T1}/Thunderbird` }).body, "third");
});

test("if every one of the contact's devices is held back, nothing is sent and the chat says why", async () => {
  const { tb, bridge, accounts } = await setup();
  const conv = tb.makeConversation(accounts[T1], T2);
  conv.dispatchMessage("first");
  await until(() => accounts[T2].received.length === 1, "delivery");
  const t2 = bridge.accounts.get(accounts[T2]).store;
  bridge.runCommand(conv, `distrust ${t2.deviceId}`);
  await until(() => /is now distrusted/.test(lastSaid(conv)), "the distrust");
  conv.dispatchMessage("blocked");
  await until(() => conv.shown.some((m) => m.flags.error), "the error");
  assert.match(conv.shown.find((m) => m.flags.error).text, /none of test2@example\.org's devices are trusted yet/);
  assert.equal(accounts[T2].received.length, 1, "nothing new sent");
});

test("a message from a distrusted device is shown with a warning and no padlock", async () => {
  const { tb, bridge, accounts } = await setup();
  const conv2 = tb.makeConversation(accounts[T2], T1);
  tb.makeConversation(accounts[T1], T2).dispatchMessage("hello");
  await until(() => conv2.shown.length === 1, "first delivery");
  const t1 = bridge.accounts.get(accounts[T1]).store;
  bridge.runCommand(conv2, `distrust ${t1.deviceId}`);
  await until(() => /is now distrusted/.test(lastSaid(conv2)), "the distrust");
  tb.makeConversation(accounts[T1], T2).dispatchMessage("from a distrusted device");
  await until(() => conv2.shown.filter((m) => !m.flags.system).length === 2, "second delivery");
  const last = conv2.shown.filter((m) => !m.flags.system).at(-1);
  assert.match(last.text, /\[OMEMO\] This message came from a device you don't trust .*\nfrom a distrusted device/s);
  assert.notEqual(last.flags.isEncrypted, true);
});

test("/omemo verify refuses devices that don't exist", async () => {
  const { tb, bridge, accounts } = await setup();
  const conv = tb.makeConversation(accounts[T1], T2);
  bridge.runCommand(conv, "verify 12345");
  assert.match(lastSaid(conv), /There's no device 12345 for test2@example\.org/);
  bridge.runCommand(conv, "verify");
  assert.equal(lastSaid(conv), "[OMEMO] Add a device number: /omemo verify <device>. Type /omemo to see the device numbers.");
});

test("/omemo qr and /omemo help open the add-on's page; ownDevices lists this Thunderbird's devices", async () => {
  const server = createFakePepServer();
  const tb = createFakeThunderbird(server);
  const lines = [];
  const opened = [];
  const bridge = installBridge({
    ...tb, setTimer: setTimeout, clearTimer: clearTimeout, appName: "Thunderbird", fileAccessFor: memoryFile,
    log: (l) => lines.push(l), mode: "manual", encryptionStates: STATES, onShowPage: (section) => opened.push(section),
  });
  const account = tb.makeAccount(T1);
  const early = tb.makeConversation(account, T2);
  bridge.runCommand(early, "help");
  assert.deepEqual(opened, ["instructions"], "help works before OMEMO is ready");
  assert.match(lastSaid(early), /Opening the instructions in a new tab/);
  account.onConnection();
  await until(() => lines.some((l) => l.startsWith("OMEMO ready")), "OMEMO");
  const conv = tb.makeConversation(account, T2);
  bridge.runCommand(conv, " QR ");
  assert.deepEqual(opened, ["instructions", "verify"]);
  assert.match(lastSaid(conv), /Opening the QR code for your phone in a new tab/);

  const [own] = bridge.ownDevices();
  const store = bridge.accounts.get(account).store;
  assert.equal(own.jid, T1);
  assert.equal(own.deviceId, store.deviceId);
  assert.equal(own.fingerprint, fpOf(store));
  assert.equal(own.uri, `xmpp:${T1}?omemo-sid-${store.deviceId}=${fpOf(store).replace(/ /g, "")}`);
});

test("/omemo status says how long ago a device last wrote, and flags quiet ones", async () => {
  const server = createFakePepServer();
  const tb = createFakeThunderbird(server);
  const lines = [];
  let clock = Date.parse("2026-09-26T12:00:00Z");
  const bridge = installBridge({
    ...tb, setTimer: setTimeout, clearTimer: clearTimeout, appName: "Thunderbird", fileAccessFor: memoryFile,
    log: (l) => lines.push(l), mode: "manual", encryptionStates: STATES, now: () => clock,
  });
  const account = tb.makeAccount(T1);
  account.onConnection();
  await until(() => lines.some((l) => l.startsWith("OMEMO ready")), "OMEMO");
  const store = bridge.accounts.get(account).store;
  store.setDevices("oldmemo", T2, [{ id: 11 }, { id: 22 }, { id: 33 }]);
  store.setDevices("oldmemo", T1, [{ id: store.deviceId }, { id: 44 }]);
  const hour = 60 * 60 * 1000;
  store._now = () => clock - 3 * hour;
  store.recordMessageFrom(T2, 11);
  store._now = () => clock - 45 * 24 * hour;
  store.recordMessageFrom(T2, 22);
  store._now = () => clock - 20 * 60 * 1000;
  store.recordMessageFrom(T1, 44);
  const conv = tb.makeConversation(account, T2);
  bridge.runCommand(conv, "status");
  await until(() => /devices/.test(lastSaid(conv)), "the status");
  const status = lastSaid(conv).split("\n");
  const at = status.indexOf("test2@example.org's devices:");
  assert.deepEqual(status.slice(at + 1, at + 4).map((l) => l.replace(/;.*/, "")), [
    "- device 11, older OMEMO: last message 3 hours ago",
    "- device 22, older OMEMO: no messages for 45 days",
    "- device 33, older OMEMO: no messages from it yet",
  ]);
  assert.equal(status[at + 4], `Your other devices, on ${T1}:`);
  assert.match(status[at + 5], /^- device 44, older OMEMO: last message 20 minutes ago/);
  assert.ok(!status.some((l) => l.startsWith(`- device ${store.deviceId},`)), "this Thunderbird isn't listed as another device");
});

// --- milestone 6: stale devices, removing our own old installs, upkeep ---

const DAY = 24 * 60 * 60 * 1000;
const lastMessageStanza = (account) => parseXml(account.sent.filter((x) => x.startsWith("<message")).at(-1));
const hasOldmemoPart = (stanza) => stanza.children.some((c) => c.name === "encrypted" && c.ns === "eu.siacs.conversations.axolotl");

test("a contact's device silent for 90 days is left out, unless every device is", async () => {
  let clock = Date.parse("2026-09-26T12:00:00Z");
  const { server, tb, bridge, accounts, lines } = await setup([T1, T2], { now: () => clock });
  const t1 = bridge.accounts.get(accounts[T1]).store;
  const t2 = bridge.accounts.get(accounts[T2]).store;
  t1._now = () => clock;
  const phone = addPhone(server, bridge, accounts[T2], T2);
  t1.setDevices("oldmemo", T2, [{ id: t2.deviceId }, { id: phone.deviceId }]);
  const conv = tb.makeConversation(accounts[T1], T2);
  conv.dispatchMessage("while the phone is fresh");
  await until(() => accounts[T2].received.length === 1, "delivery");
  assert.ok(hasOldmemoPart(lastMessageStanza(accounts[T1])), "the phone gets a key");

  // 91 days on: test2's Thunderbird wrote recently, the phone never did.
  clock += 91 * DAY;
  t1.recordMessageFrom(T2, t2.deviceId);
  conv.dispatchMessage("the phone is stale now");
  await until(() => accounts[T2].received.length === 2, "delivery");
  assert.ok(!hasOldmemoPart(lastMessageStanza(accounts[T1])), "no key for the stale phone");
  assert.ok(lines.includes(`not encrypting to ${T2} device ${phone.deviceId}: no messages from it for over 90 days`));

  const before = conv.shown.length;
  bridge.runCommand(conv, "");
  await until(() => conv.shown.length > before, "the status");
  const phoneLine = lastSaid(conv).split("\n").find((l) => l.startsWith(`- device ${phone.deviceId},`));
  assert.match(phoneLine, /no messages from it yet; .*; left out when encrypting \(silent over 90 days\)$/);

  // Another 91 days with nothing from anyone: all stale, so all get keys.
  clock += 91 * DAY;
  conv.dispatchMessage("everyone is stale");
  await until(() => accounts[T2].received.length === 3, "delivery");
  assert.ok(hasOldmemoPart(lastMessageStanza(accounts[T1])), "never leave out every device");
});

test("/omemo remove takes our own old install off our device lists; nothing else can be removed", async () => {
  const { server, tb, bridge, accounts } = await setup([T1, T2]);
  const t1 = bridge.accounts.get(accounts[T1]).store;
  const t2 = bridge.accounts.get(accounts[T2]).store;
  for (const ns of ["oldmemo", "twomemo"]) {
    const { node, itemId } = f.deviceListLocation(ns);
    server.put(T1, node, itemId, f.buildDeviceList(ns, [{ id: t1.deviceId }, { id: 4242 }]));
    t1.setDevices(ns, T1, [{ id: t1.deviceId }, { id: 4242 }]);
  }
  const conv = tb.makeConversation(accounts[T1], T2);
  bridge.runCommand(conv, "remove");
  assert.match(lastSaid(conv), /Add a device number: \/omemo remove <device>/);
  bridge.runCommand(conv, `remove ${t1.deviceId}`);
  assert.match(lastSaid(conv), /is this Thunderbird, which can't remove itself/);
  bridge.runCommand(conv, `remove ${t2.deviceId}`);
  assert.match(lastSaid(conv), /isn't one of your devices \(test1@example\.org\)/);

  bridge.runCommand(conv, "remove 4242");
  await until(() => /Removed device 4242/.test(lastSaid(conv)), "the removal");
  for (const ns of ["oldmemo", "twomemo"]) {
    const node = server.accounts.get(T1).get(f.deviceListLocation(ns).node);
    assert.deepEqual(f.parseDeviceList(ns, parseXml(node.items.get("current"))).map((d) => d.id), [t1.deviceId], ns);
  }
});

test("each connected account's upkeep runs every 6 hours and republishes a rotated signed prekey", async () => {
  const upkeep = [];
  const setTimer = (fn, ms) => (ms === 6 * 60 * 60 * 1000 ? (upkeep.push(fn), { unref() {} }) : setTimeout(fn, ms));
  const { server, bridge, accounts } = await setup([T1], { allowlist: [], mode: "manual", setTimer });
  await until(() => upkeep.length === 1, "the first upkeep timer");
  const store = bridge.accounts.get(accounts[T1]).store;
  const published = () => {
    const { node, itemId } = f.bundleLocation("twomemo", store.deviceId);
    return f.parseBundle("twomemo", parseXml(server.accounts.get(T1).get(node).items.get(itemId))).signedPreKey.id;
  };
  const first = published();
  store._now = () => Date.now() + 8 * DAY;
  upkeep[0]();
  await until(() => upkeep.length === 2, "the next upkeep timer");
  assert.equal(published(), first + 1, "a new signed prekey is published");
});
