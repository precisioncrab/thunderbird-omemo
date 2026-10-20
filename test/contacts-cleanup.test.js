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
  const tabs = [];
  const browser = {
    omemoXmpp: {
      onDiagnostic: event(),
      onShowPage: event(),
      onAccountConnected: event(),
      setSettings: async () => {},
      install: async () => {},
      addHintCommand: async () => {},
      async chatNames(options) {
        runs.push(options);
        return { cards: options.cards.length, accounts: [{ jid: "test1@test.snikket.chat", mode: options.modes["test1@test.snikket.chat"] ?? "off", contacts: [] }], written: options.written };
      },
    },
    storage: {
      onChanged: event(),
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
      onMessage: event(),
      onMessageExternal: external,
      getManifest: () => ({ name: "OMEMO for Thunderbird", version: "0.1.5", experiment_apis: { omemoXmpp: {} } }),
      getURL: (path) => `moz-extension://omemo/${path}`,
      openOptionsPage: async () => {},
    },
    tabs: { create: async (options) => tabs.push(options.url) },
  };
  const context = vm.createContext({ browser, console: { log() {} }, setTimeout: () => 0, clearTimeout() {}, structuredClone });
  vm.runInContext(read("src/pro.js"), context);
  vm.runInContext(read("src/background.js"), context);
  const send = (message, id = "contacts-cleanup@precisioncrab") => external.listeners[0](message, { id });
  return { send, store, runs, tabs };
}

test("only Contacts Cleanup is answered", () => {
  const { send } = loadBackground();
  assert.equal(send({ command: "hello" }, "someone-else@example.org"), undefined);
  assert.equal(send({ command: "chatNames.preview" }, null), undefined);
  assert.equal(send({ command: "unknown" }), undefined);
});

test("hello says which add-on and version answers", async () => {
  const { send } = loadBackground();
  assert.deepEqual({ ...(await send({ command: "hello" })) }, { name: "OMEMO for Thunderbird", version: "0.1.5", pro: false, protocol: 1 });
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
