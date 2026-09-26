/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests for src/omemo/bridge.js and src/omemo/xmlnode.js, against the fake
 * Thunderbird in test/fake-thunderbird.js and the fake pubsub server.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { installBridge } from "../src/omemo/bridge.js";
import { toXmlNode, fromXmlNode, createSendIq } from "../src/omemo/xmlnode.js";
import { CAPS_NODE, NOTIFY_FEATURES, capsVer } from "../src/omemo/caps.js";
import * as f from "../src/omemo/formats.js";
import { el, parseXml, serialize } from "../src/omemo/xml.js";
import { createFakePepServer } from "./fake-pep.js";
import { createFakeThunderbird, parseToXmlNode, Stanza } from "./fake-thunderbird.js";

function memoryFile() {
  let text = null;
  return { read: async () => text, write: async (t) => { text = t; }, get text() { return text; } };
}

function setup({ connected = [] } = {}) {
  const server = createFakePepServer();
  const tb = createFakeThunderbird(server);
  const lines = [];
  const files = new Map();
  const outgoing = [];
  const originals = { ...tb.xmppBase.XMPPAccountPrototype, dispatchMessage: tb.xmppBase.XMPPConversationPrototype.dispatchMessage };
  const bridge = installBridge({
    xmppBase: tb.xmppBase,
    Stanza: tb.Stanza,
    SupportedFeatures: tb.SupportedFeatures,
    setTimer: setTimeout,
    clearTimer: clearTimeout,
    appName: "Thunderbird",
    fileAccessFor: (jid) => {
      if (!files.has(jid)) {
        files.set(jid, memoryFile());
      }
      return files.get(jid);
    },
    connectedAccounts: () => connected.map((jid) => tb.makeAccount(jid)),
    log: (l) => lines.push(l),
    onOutgoing: (id, text) => outgoing.push([id, text]),
  });
  return { server, tb, lines, files, outgoing, bridge, originals };
}

/** Waits until a log line matches (OMEMO starts asynchronously). */
async function waitFor(lines, pattern) {
  for (let i = 0; i < 200; i++) {
    const hit = lines.find((l) => pattern.test(l));
    if (hit) {
      return hit;
    }
    await new Promise((r) => setTimeout(r, 5));
  }
  assert.fail(`no log line matched ${pattern}; got:\n${lines.join("\n")}`);
}

// --- conversion ---

test("xml.js trees become XMLNodes whose getXML() parses back to the same tree, escaping included", () => {
  const tree = el("iq", "jabber:client", { type: "set", to: 'a&b"<c>' }, [
    el("pubsub", "urn:p", {}, [el("item", "urn:p", { id: "x" }, ["text & <more>"])]),
  ]);
  const node = toXmlNode(tree, Stanza);
  assert.equal(node.uri, null, "jabber:client stays implicit, as in Thunderbird's own stanzas");
  assert.equal(node.children[0].uri, "urn:p");
  assert.equal(node.children[0].children[0].uri, null, "same namespace as the parent: no xmlns");
  const back = parseXml(node.getXML());
  assert.equal(back.attributes.to, 'a&b"<c>');
  assert.equal(serialize(back.children[0]), serialize(tree.children[0]));
});

test("parsed XMLNodes convert to trees: namespaces resolved, xmlns declarations dropped, text kept", () => {
  const node = parseToXmlNode(`<message xmlns="jabber:client" from="a@b"><x xmlns="urn:x" xmlns:p="urn:p" k="v">hi</x></message>`);
  node.children[0].attributes["xmlns:p"] = "urn:p"; // as sax-js leaves it
  const tree = fromXmlNode(node);
  assert.deepEqual(tree, {
    name: "message", ns: "jabber:client", attributes: { from: "a@b" },
    children: [{ name: "x", ns: "urn:x", attributes: { k: "v" }, children: ["hi"] }],
  });
  // A node built without a namespace inherits its parent's.
  assert.equal(fromXmlNode(Stanza.node("q", null, {}, [Stanza.node("r", null)]), "urn:y").children[0].ns, "urn:y");
});

test("sendIq times out when no reply comes, and resolves with the converted reply otherwise", async () => {
  const silent = { sendStanza() {} };
  await assert.rejects(createSendIq(silent, { Stanza, setTimer: setTimeout, clearTimer: clearTimeout, timeoutMs: 20 })(el("iq", "jabber:client", { type: "get" })),
    /No reply to a PEP request within 0.02 s/);
  const echo = { sendStanza(stanza, cb) { setImmediate(() => cb(parseToXmlNode("<iq xmlns='jabber:client' type='result'/>"))); } };
  const reply = await createSendIq(echo, { Stanza, setTimer: setTimeout, clearTimer: clearTimeout })(el("iq", "jabber:client", { type: "get" }));
  assert.equal(reply.attributes.type, "result");
});

// --- the bridge ---

test("on connect: Thunderbird's own onConnection runs, then OMEMO publishes both namespaces", async () => {
  const { server, tb, lines, files } = setup();
  const account = tb.makeAccount("alice@example.org");
  account.onConnection();
  assert.deepEqual(tb.calls[0], ["onConnection", "alice@example.org"]);
  await waitFor(lines, /OMEMO ready for alice@example\.org: device \d+; published oldmemo, twomemo$/);
  assert.ok(server.accounts.get("alice@example.org").has("urn:xmpp:omemo:2:devices"));
  assert.ok(files.get("alice@example.org").text, "keys saved");
});

test("labels with XML-special characters survive Thunderbird's unescaped attributes", async () => {
  const { server, tb, lines } = setup();
  server.put("alice@example.org", "urn:xmpp:omemo:2:devices", "current",
    f.buildDeviceList("twomemo", [{ id: 5, label: `Tom & "Jerry" <phone>` }]));
  tb.makeAccount("alice@example.org").onConnection();
  await waitFor(lines, /OMEMO ready/);
  const list = f.parseDeviceList("twomemo", parseXml(server.accounts.get("alice@example.org").get("urn:xmpp:omemo:2:devices").items.get("current")));
  assert.equal(list[0].label, `Tom & "Jerry" <phone>`);
  assert.equal(list.length, 2);
});

test("presence gets our caps hash; directed and typed presence don't", () => {
  const { tb } = setup();
  const account = tb.makeAccount("alice@example.org");
  account.sendStanza(Stanza.presence({ "xml:lang": "en" }, []));
  account.sendStanza(Stanza.presence({ to: "room@muc/nick" }, []));
  account.sendStanza(Stanza.presence({ type: "unavailable" }, []));
  const ver = capsVer({ identities: [{ category: "client", type: "pc", name: "Thunderbird" }], features: tb.SupportedFeatures });
  assert.equal(account.sent[0], `<presence xml:lang="en"><c xmlns="http://jabber.org/protocol/caps" hash="sha-1" node="${CAPS_NODE}" ver="${ver}"/></presence>`);
  assert.doesNotMatch(account.sent[1], /caps/);
  assert.doesNotMatch(account.sent[2], /caps/);
  for (const feature of NOTIFY_FEATURES) {
    assert.ok(tb.SupportedFeatures.includes(feature), `${feature} advertised`);
  }
});

test("disco#info for our caps node is answered with the node; other iqs go to Thunderbird", () => {
  const { tb } = setup();
  const account = tb.makeAccount("alice@example.org");
  const ver = capsVer({ identities: [{ category: "client", type: "pc", name: "Thunderbird" }], features: tb.SupportedFeatures });
  account.onIQStanza(parseToXmlNode(`<iq xmlns="jabber:client" type="get" id="q1" from="server.example.org">
      <query xmlns="http://jabber.org/protocol/disco#info" node="${CAPS_NODE}#${ver}"/></iq>`));
  const reply = parseXml(account.sent[0]);
  assert.deepEqual([reply.attributes.type, reply.attributes.id, reply.attributes.to], ["result", "q1", "server.example.org"]);
  const query = reply.children[0];
  assert.equal(query.attributes.node, `${CAPS_NODE}#${ver}`);
  const features = query.children.filter((c) => c.name === "feature").map((c) => c.attributes.var);
  assert.deepEqual(features, tb.SupportedFeatures);
  assert.equal(capsVer({ identities: [query.children[0].attributes], features }), ver, "the reply hashes to our ver");
  assert.equal(tb.calls.filter((c) => c[0] === "onIQStanza").length, 0);

  account.onIQStanza(parseToXmlNode(`<iq xmlns="jabber:client" type="get" id="q2"><query xmlns="http://jabber.org/protocol/disco#info"/></iq>`));
  account.onIQStanza(parseToXmlNode(`<iq xmlns="jabber:client" type="get" id="q3"><ping xmlns="urn:xmpp:ping"/></iq>`));
  assert.equal(tb.calls.filter((c) => c[0] === "onIQStanza").length, 2, "everything else reaches Thunderbird");
});

test("device list pushes are handled and kept out of the conversation; chat messages pass through", async () => {
  const { tb, lines, bridge } = setup();
  const account = tb.makeAccount("alice@example.org");
  account.onConnection();
  await waitFor(lines, /OMEMO ready/);
  account.onMessageStanza(parseToXmlNode(`<message xmlns="jabber:client" from="bob@example.org" type="headline">
      <event xmlns="http://jabber.org/protocol/pubsub#event"><items node="urn:xmpp:omemo:2:devices">
        <item id="current"><devices xmlns="urn:xmpp:omemo:2"><device id="42"/></devices></item></items></event></message>`));
  await waitFor(lines, /device list push for urn:xmpp:omemo:2:devices from bob@example\.org to alice@example\.org/);
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(bridge.accounts.get(account).store.devices("twomemo", "bob@example.org").map((d) => d.id), [42]);
  assert.equal(tb.calls.filter((c) => c[0] === "onMessageStanza").length, 0, "swallowed");

  account.onMessageStanza(parseToXmlNode(`<message xmlns="jabber:client" from="bob@example.org" type="chat"><body>hi</body></message>`));
  account.onMessageStanza(parseToXmlNode(`<message xmlns="jabber:client" from="bob@example.org"><event xmlns="http://jabber.org/protocol/pubsub#event"><items node="urn:xmpp:avatar:metadata"/></event></message>`));
  assert.equal(tb.calls.filter((c) => c[0] === "onMessageStanza").length, 2, "chat and other pubsub reach Thunderbird");
  assert.match(lines.join("\n"), /onMessageStanza hook fired: from bob@example\.org, type chat, no OMEMO <encrypted>/);
});

test("disconnect saves the keys and still runs Thunderbird's own _disconnect", async () => {
  const { tb, lines, files, bridge } = setup();
  const account = tb.makeAccount("alice@example.org");
  account.onConnection();
  await waitFor(lines, /OMEMO ready/);
  const omemo = bridge.accounts.get(account);
  omemo.store.removePreKey("twomemo", 1); // a change that isn't written yet
  account._disconnect();
  assert.deepEqual(tb.calls.at(-1), ["_disconnect", "alice@example.org"]);
  assert.equal(bridge.accounts.has(account), false);
  await new Promise((r) => setTimeout(r, 20));
  const saved = JSON.parse(files.get("alice@example.org").text);
  assert.equal(saved.namespaces.twomemo.preKeys.some(([id]) => id === 1), false, "twomemo pre key 1 is gone from the saved file");
  assert.equal(saved.namespaces.oldmemo.preKeys.some(([id]) => id === 1), true);
  // Reconnecting reloads the same keys.
  const readyBefore = lines.filter((l) => /OMEMO ready/.test(l)).length;
  account.onConnection();
  for (let i = 0; i < 200 && lines.filter((l) => /OMEMO ready/.test(l)).length === readyBefore; i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
  assert.equal(bridge.accounts.get(account).store.deviceId, omemo.store.deviceId);
  assert.match(lines.filter((l) => /OMEMO ready/.test(l)).at(-1), new RegExp(`device ${omemo.store.deviceId}`));
});

test("saveAll and uninstall wait for the save a disconnect started", async () => {
  const { tb, lines, files, bridge } = setup();
  let text = null;
  let slow = false;
  let release;
  const gate = new Promise((r) => {
    release = r;
  });
  files.set("alice@example.org", {
    read: async () => text,
    write: async (t) => {
      if (slow) {
        await gate; // a disk that takes its time
      }
      text = t;
    },
  });
  const account = tb.makeAccount("alice@example.org");
  account.onConnection();
  await waitFor(lines, /OMEMO ready/);
  slow = true;
  bridge.accounts.get(account).store.removePreKey("twomemo", 1); // e.g. a message just decrypted
  account._disconnect(); // Thunderbird doesn't wait for the save
  let saved = false;
  let uninstalled = false;
  bridge.saveAll().then(() => {
    saved = true;
  });
  bridge.uninstall().then(() => {
    uninstalled = true;
  });
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(saved, false, "saveAll waits for the write");
  assert.equal(uninstalled, false, "so does uninstall");
  release();
  for (let i = 0; i < 200 && !(saved && uninstalled); i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
  assert.ok(saved && uninstalled);
  assert.equal(JSON.parse(text).namespaces.twomemo.preKeys.some(([id]) => id === 1), false, "the change is on disk");
});

test("saveAll writes connected accounts' pending changes at once", async () => {
  const { tb, lines, files, bridge } = setup();
  const account = tb.makeAccount("alice@example.org");
  account.onConnection();
  await waitFor(lines, /OMEMO ready/);
  bridge.accounts.get(account).store.removePreKey("twomemo", 1); // saved 500 ms later on its own
  await bridge.saveAll();
  const saved = JSON.parse(files.get("alice@example.org").text);
  assert.equal(saved.namespaces.twomemo.preKeys.some(([id]) => id === 1), false);
});

test("accounts already connected at install get OMEMO too", async () => {
  const { lines } = setup({ connected: ["carol@example.org"] });
  await waitFor(lines, /OMEMO ready for carol@example\.org/);
});

test("dispatchMessage: diagnostics, then Thunderbird's own send", () => {
  const { tb, outgoing, lines } = setup();
  const conversation = Object.create(tb.xmppBase.XMPPConversationPrototype);
  Object.assign(conversation, { to: "bob@example.org", id: 3 });
  conversation.dispatchMessage("hello");
  assert.deepEqual(outgoing, [[3, "hello"]]);
  assert.deepEqual(tb.calls.at(-1), ["dispatchMessage", "bob@example.org", "hello"]);
  assert.match(lines.join("\n"), /dispatchMessage hook fired: to bob@example\.org, 5 characters/);
});

test("a hook that fails logs the error and Thunderbird's original still runs", () => {
  const { tb, lines } = setup();
  const account = tb.makeAccount("alice@example.org");
  const broken = { attributes: {}, getElement() { throw new Error("boom"); }, getXML: () => "<broken/>" };
  account.onMessageStanza(broken);
  account.onIQStanza(broken);
  assert.deepEqual(tb.calls.map((c) => c[0]), ["onMessageStanza", "onIQStanza"]);
  assert.match(lines.join("\n"), /ERROR: reading an OMEMO device list push failed: boom/);
});

test("uninstall restores Thunderbird's functions and features", async () => {
  const { tb, bridge, originals } = setup();
  await bridge.uninstall();
  for (const name of ["onConnection", "_disconnect", "sendStanza", "onIQStanza", "onMessageStanza"]) {
    assert.equal(tb.xmppBase.XMPPAccountPrototype[name], originals[name], name);
  }
  assert.equal(tb.xmppBase.XMPPConversationPrototype.dispatchMessage, originals.dispatchMessage);
  assert.deepEqual(tb.SupportedFeatures, ["http://jabber.org/protocol/disco#info", "http://jabber.org/protocol/muc"]);
});

test("missing hook targets are reported by name before anything is patched", () => {
  const tb = createFakeThunderbird(createFakePepServer());
  delete tb.xmppBase.XMPPAccountPrototype._disconnect;
  const before = { ...tb.xmppBase.XMPPAccountPrototype };
  assert.throws(() => installBridge({ ...tb, setTimer: setTimeout, clearTimer: clearTimeout, appName: "T", fileAccessFor: memoryFile, log() {} }),
    /missing _disconnect/);
  assert.deepEqual({ ...tb.xmppBase.XMPPAccountPrototype }, before);
  assert.equal(tb.SupportedFeatures.length, 2);
});

test("several accounts start one after another, not all at once", async () => {
  const { tb, lines } = setup();
  for (const jid of ["a@example.org", "b@example.org", "c@example.org"]) {
    tb.makeAccount(jid).onConnection();
  }
  for (const jid of ["a", "b", "c"]) {
    await waitFor(lines, new RegExp(`OMEMO ready for ${jid}@example\.org`));
  }
  const order = lines.filter((l) => /OMEMO ready|created OMEMO keys/.test(l)).map((l) => /for (\w)@/.exec(l)[1]);
  assert.deepEqual(order, ["a", "a", "b", "b", "c", "c"], "each account finishes before the next begins");
});
