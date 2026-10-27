/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests for the background script's answers to Contacts Cleanup (the
 * address book add-on that runs chat contact names from its own tab): only
 * that add-on is answered, and setMode saves the choice like the options
 * page does. Loads src/pro.js and src/background.js the way Thunderbird
 * does, with a fake browser API.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const event = () => ({ listeners: [], addListener(f) {
  this.listeners.push(f);
} });

function loadBackground() {
  const store = {};
  const external = event();
  const runs = [];
  const groupRuns = [];
  const sectionRuns = [];
  const timers = [];
  const storageChanged = event();
  const internal = event();
  const tabs = [];
  const sent = [];
  const browser = {
    omemoXmpp: {
      onDiagnostic: event(),
      onShowPage: event(),
      onAccountConnected: event(),
      onChatContactsChanged: event(),
      setSettings: async () => {},
      install: async () => {},
      addHintCommand: async () => {},
      // The server refuses refused@example.org.
      async sendIq(account, xml) {
        sent.push([account, xml]);
        return xml.includes('jid="refused@example.org"') ? '<iq xmlns="jabber:client" type="error"/>' : '<iq xmlns="jabber:client" type="result"/>';
      },
      async sendStanza(account, xml) {
        sent.push([account, xml]);
      },
      async chatGroups(request) {
        groupRuns.push(request);
        return { accounts: [], applied: request.groups };
      },
      async chatSections(settings) {
        sectionRuns.push(settings);
        return settings.on;
      },
      async chatNames(options) {
        runs.push(options);
        return { cards: options.cards.length, accounts: [{ jid: "test1@test.snikket.chat", mode: options.modes["test1@test.snikket.chat"] ?? "off", contacts: [] }], written: options.written };
      },
    },
    storage: {
      onChanged: storageChanged,
      local: {
        async get(keys) {
          return Object.fromEntries([].concat(keys).filter((k) => k in store).map((k) => [k, structuredClone(store[k])]));
        },
        async set(values) {
          Object.assign(store, structuredClone(values));
        },
      },
    },
    contacts: { onCreated: event(), onUpdated: event(), onDeleted: event() },
    addressBooks: { list: async () => [{ contacts: [{ properties: { vCard: "BEGIN:VCARD\r\nFN:Test Two\r\nEND:VCARD" } }] }] },
    runtime: {
      onMessage: internal,
      onMessageExternal: external,
      getManifest: () => ({ name: "OMEMO for Thunderbird", version: "0.1.5", experiment_apis: { omemoXmpp: {} } }),
      getURL: (path) => `moz-extension://omemo/${path}`,
      openOptionsPage: async () => {},
    },
    tabs: { create: async (options) => tabs.push(options.url) },
  };
  const context = vm.createContext({ browser, console: { log() {} }, setTimeout: (f) => timers.push(f), clearTimeout() {}, structuredClone });
  vm.runInContext(read("src/pro.js"), context);
  vm.runInContext(read("src/background.js"), context);
  const send = (message, id = "contacts-cleanup@precisioncrab") => external.listeners[0](message, { id });
  const ask = (message) => internal.listeners[0](message, {});
  return { send, ask, store, runs, groupRuns, sectionRuns, timers, storageChanged, tabs, sent };
}

test("chat contacts: added with their names and asked for presence; refusals and bad addresses reported", async () => {
  const { send, sent } = loadBackground();
  assert.deepEqual({ ...(await send({ command: "chatContacts.hello" })) }, { add: true, remove: true });
  const result = await send({ command: "chatContacts.add", account: "test1@test.snikket.chat", contacts: [
    { jid: "+15556667777@cheogram.com", name: "Pat & Sam Roe" },
    { jid: "not an address", name: "Nobody" },
    { jid: "refused@example.org", name: "Refused" },
  ] });
  assert.deepEqual(JSON.parse(JSON.stringify(result)), {
    added: ["+15556667777@cheogram.com"],
    failed: [{ jid: "not an address", error: "not a chat address" }, { jid: "refused@example.org", error: "the server refused it" }],
  });
  assert.equal(sent.length, 3);
  assert.match(sent[0][1], /<item jid="\+15556667777@cheogram.com" name="Pat &amp; Sam Roe"\/>/);
  assert.equal(sent[1][1], '<presence xmlns="jabber:client" to="+15556667777@cheogram.com" type="subscribe"/>');
  assert.match(sent[2][1], /jid="refused@example.org"/);
});

test("chat contacts: removed with a roster remove; anything but a list is refused", async () => {
  const { send, sent } = loadBackground();
  const result = await send({ command: "chatContacts.remove", account: "test1@test.snikket.chat", jids: ["Friend@Example.org"] });
  assert.deepEqual(JSON.parse(JSON.stringify(result)), { removed: ["friend@example.org"], failed: [] });
  assert.match(sent[0][1], /<item jid="friend@example.org" subscription="remove"\/>/);
  await assert.rejects(send({ command: "chatContacts.add", account: "test1@test.snikket.chat" }));
  await assert.rejects(send({ command: "chatContacts.remove", account: "test1@test.snikket.chat", jids: "friend@example.org" }));
});

test("only Contacts Cleanup and Daynizer are answered", async () => {
  const { send } = loadBackground();
  assert.equal(send({ command: "hello" }, "someone-else@example.org"), undefined);
  assert.equal(send({ command: "chatNames.preview" }, null), undefined);
  // Daynizer's old self-distributed build isn't the add-on users have.
  assert.equal(send({ command: "hello" }, "tasks-desktop@arlis"), undefined);
  assert.equal(send({ command: "unknown" }), undefined);
  assert.equal({ ...(await send({ command: "hello" }, "daynizer@precisioncrab.com")) }.protocol, 1);
});

test("Daynizer gets the same chat contacts commands as Contacts Cleanup", async () => {
  const { send, sent } = loadBackground();
  const daynizer = (message) => send(message, "daynizer@precisioncrab.com");
  assert.deepEqual({ ...(await daynizer({ command: "chatContacts.hello" })) }, { add: true, remove: true });
  const result = await daynizer({ command: "chatContacts.add", account: "test1@test.snikket.chat", contacts: [{ jid: "test2@test.snikket.chat", name: "Test Two" }] });
  assert.deepEqual([...result.added], ["test2@test.snikket.chat"]);
  assert.match(sent[0][1], /<item jid="test2@test\.snikket\.chat" name="Test Two"\/>/);
});

test("hello says which add-on and version answers", async () => {
  const { send } = loadBackground();
  assert.deepEqual({ ...(await send({ command: "hello" })) }, { name: "OMEMO for Thunderbird", version: "0.1.5", pro: false, protocol: 1 });
});

test("hello from Contacts Cleanup notes it's installed (the options page then hides its card); others' don't", async () => {
  const { send, store } = loadBackground();
  send({ command: "hello" }, "someone-else@example.org");
  await send({ command: "hello" }, "daynizer@precisioncrab.com");
  assert.equal(store.contactsCleanup, undefined);
  await send({ command: "hello" });
  assert.deepEqual(store.contactsCleanup, { seen: true });
});

test("the options page and README say what Contacts Cleanup can ask for, and link it the same way", () => {
  const page = read("src/options/options.html");
  const readme = read("README.md");
  const access = (text, heading) => text.slice(text.indexOf(heading), text.indexOf(heading) + 4000);
  assert.match(access(page, "What this add-on can access"), /<li>Requests from Contacts Cleanup[^<]*from Daynizer for Thunderbird[^<]*and from no other add-on/);
  assert.match(access(readme, "## What this add-on can access"), /Requests from \[Contacts Cleanup\]\(#more-from-precision-crab\)[\s\S]*\[Daynizer\]\(#more-from-precision-crab\)[\s\S]*from no other add-on/);
  const url = read("src/options/options.js").match(/const CONTACTS_CLEANUP = \{\s*url: "([^"]+)"/)?.[1];
  assert.ok(url, "options.js has no Contacts Cleanup link");
  assert.ok(readme.includes(`[Contacts Cleanup](${url})`), "the README links Contacts Cleanup somewhere else than the options page");
  assert.ok(page.includes('id="cleanup"'), "the options page has no Contacts Cleanup card");
});

test("preview runs the chat names without writing", async () => {
  const { send, runs } = loadBackground();
  const result = await send({ command: "chatNames.preview" });
  assert.equal(result.cards, 1);
  assert.equal(runs.at(-1).apply, false);
});

test("setMode saves the account's choice like the options page, then writes", async () => {
  const { send, store, runs } = loadBackground();
  const result = await send({ command: "chatNames.setMode", jid: "test1@test.snikket.chat", mode: "local" });
  assert.deepEqual(store.chatNames, { accounts: { "test1@test.snikket.chat": "local" } });
  assert.equal(runs.at(-1).apply, true);
  assert.equal(result.accounts[0].mode, "local");
  // Off: nothing to write, so the answer is a preview.
  await send({ command: "chatNames.setMode", jid: "test1@test.snikket.chat", mode: "off" });
  assert.equal(runs.at(-1).apply, false);
});

test("setMode refuses anything but an account address and a known mode", async () => {
  const { send, store } = loadBackground();
  await assert.rejects(send({ command: "chatNames.setMode", jid: "test1@test.snikket.chat", mode: "everything" }));
  await assert.rejects(send({ command: "chatNames.setMode", jid: "not an address", mode: "local" }));
  await assert.rejects(send({ command: "chatNames.setMode", jid: { toString: () => "x@y" }, mode: "local" }));
  assert.equal(store.chatNames, undefined);
});

test("openOptions opens the options page at a known tab only", async () => {
  const { send, tabs } = loadBackground();
  assert.equal(await send({ command: "openOptions", section: "contacts" }), true);
  await send({ command: "openOptions", section: "../../elsewhere" });
  assert.deepEqual(tabs, ["moz-extension://omemo/src/options/options.html#contacts", "moz-extension://omemo/src/options/options.html#settings"]);
});

const plain = (x) => JSON.parse(JSON.stringify(x));

test("a section per account: on from the start, with the names chosen, and sent again when they change", async () => {
  const { ask, store, sectionRuns, storageChanged } = loadBackground();
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(plain(sectionRuns), [{ on: true, names: {} }]);
  store.chatGroups = { accounts: { "main@example.org": { name: " Main " }, "third@example.org": { name: "  " } } };
  storageChanged.listeners.forEach((f) => f({ chatGroups: {} }, "local"));
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(plain(sectionRuns.at(-1)), { on: true, names: { "main@example.org": "Main" } });
  store.chatSections = { on: false };
  assert.equal(await ask({ command: "chatSections.apply" }), false);
  assert.deepEqual(plain(sectionRuns.at(-1)), { on: false, names: { "main@example.org": "Main" } });
  storageChanged.listeners.forEach((f) => f({ settings: {} }, "local"));
  await new Promise((r) => setImmediate(r));
  assert.equal(sectionRuns.length, 3, "other settings don't resend the sections");
});

test("the groups test build 0.1.8 made are undone, and none are made", async () => {
  const { store, groupRuns, timers } = loadBackground();
  store.chatGroups = { accounts: { "main@example.org": { on: true, name: "Main" } } };
  store.chatGroupsApplied = { "main@example.org": "Main" };
  timers.forEach((f) => f());
  await new Promise((r) => setTimeout(r, 10));
  assert.deepEqual(plain(groupRuns), [{ groups: {}, applied: { "main@example.org": "Main" } }]);
  assert.deepEqual(store.chatGroupsApplied, {});
  timers.forEach((f) => f());
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(groupRuns.length, 1, "nothing left to undo: no run");
});
