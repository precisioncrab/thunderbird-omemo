/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests for src/contacts/chat-names.js, against fakes that behave like
 * Thunderbird 158's contacts (chat/modules/imContacts.sys.mjs) and XMPP
 * account buddies (chat/protocols/xmpp/xmpp-base.sys.mjs), written from
 * their behavior, not copied:
 *   - setting a contact's alias also sets serverAlias on each of its
 *     account buddies;
 *   - an account buddy's serverAlias setter puts the name on its roster item
 *     and sends a roster set; the roster name shows once the server's push
 *     comes back (here: at once).
 */

import test from "node:test";
import assert from "node:assert/strict";
import { chatNames, setLocalName, writtenKey } from "../src/contacts/chat-names.js";

const vcard = (...lines) => ["BEGIN:VCARD", "VERSION:4.0", ...lines, "END:VCARD"].join("\r\n");

const AccountBuddyPrototype = {
  _rosterAlias: "",
  get serverAlias() {
    return this._rosterAlias;
  },
  set serverAlias(name) {
    if (!this._rosterItem) {
      return;
    }
    this._rosterItem.attributes.name = name;
    this._account.sent.push({ jid: this.normalizedName, name });
    this._rosterAlias = name;
  },
};

class Contact {
  constructor() {
    this._alias = "";
    this._buddies = [];
  }
  get alias() {
    return this._alias;
  }
  set alias(name) {
    this._alias = name;
    for (const buddy of this._buddies) {
      for (const accountBuddy of buddy._accounts) {
        accountBuddy.serverAlias = name;
      }
    }
  }
  getBuddies() {
    return this._buddies;
  }
}

function makeAccount(jid) {
  return { jid, _buddies: new Map(), sent: [] };
}

/** Adds a chat contact to an account; `contact` merges it with another's. */
function addBuddy(account, jid, { roster = "", onRoster = true, contact = new Contact() } = {}) {
  const accountBuddy = Object.create(AccountBuddyPrototype);
  Object.assign(accountBuddy, {
    _account: account,
    normalizedName: jid,
    _rosterAlias: roster,
    _rosterItem: onRoster ? { attributes: { jid, ...(roster ? { name: roster } : {}) } } : undefined,
  });
  let buddy = contact._buddies.find((b) => b.jid === jid);
  if (!buddy) {
    buddy = { jid, _accounts: [], contact, getAccountBuddies() {
      return this._accounts;
    } };
    contact._buddies.push(buddy);
  }
  buddy._accounts.push(accountBuddy);
  accountBuddy.buddy = buddy;
  account._buddies.set(jid, accountBuddy);
  return accountBuddy;
}

const CARDS = [
  vcard("FN:Alice", "TEL:(555) 234-5678"),
  vcard("FN:Bob", "IMPP:xmpp:test2@test.snikket.chat"),
  vcard("FN:Shop", "TEL:555-999-0000"),
  vcard("FN:Other shop", "TEL:+1 555 999 0000"),
];
const ALICE = "+15552345678@cheogram.com";
const SHOP = "+15559990000@cheogram.com";
const BOB = "test2@test.snikket.chat";
const ME = "test1@test.snikket.chat";

const run = (accounts, options) => chatNames({ accounts, jidOf: (a) => a.jid, cards: CARDS, ...options });
const byJid = (result, jid) => result.accounts[0].contacts.find((c) => c.jid === jid);

test("the preview names nothing, whatever the mode", () => {
  for (const mode of ["off", "local", "server"]) {
    const account = makeAccount(ME);
    const alice = addBuddy(account, ALICE);
    const result = run([account], { modes: { [ME]: mode } });
    assert.equal(result.cards, 4);
    assert.equal(byJid(result, ALICE).status, "set");
    assert.equal(byJid(result, ALICE).name, "Alice");
    assert.equal(alice.buddy.contact.alias, "");
    assert.deepEqual(account.sent, []);
    assert.deepEqual(result.written, {});
  }
});

test("Thunderbird only: the contact gets the name, the server nothing", () => {
  const account = makeAccount(ME);
  const alice = addBuddy(account, ALICE);
  const result = run([account], { modes: { [ME]: "local" }, apply: true });
  assert.equal(byJid(result, ALICE).done, true);
  assert.equal(alice.buddy.contact.alias, "Alice");
  assert.deepEqual(account.sent, [], "no roster set");
  assert.equal(alice._rosterItem.attributes.name, undefined);
  assert.equal(Object.hasOwn(alice, "serverAlias"), false, "Thunderbird's setter is back");
  assert.deepEqual(result.written, { [writtenKey(ME, ALICE)]: { name: "Alice", where: "local" } });
  // A rename by the user afterwards goes to the server again, as in Thunderbird.
  alice.buddy.contact.alias = "Al";
  assert.deepEqual(account.sent, [{ jid: ALICE, name: "Al" }]);
});

test("also the server: one roster set with the name", () => {
  const account = makeAccount(ME);
  const bob = addBuddy(account, BOB);
  const result = run([account], { modes: { [ME]: "server" }, apply: true });
  assert.equal(byJid(result, BOB).status, "set");
  assert.equal(byJid(result, BOB).by, "xmpp");
  assert.deepEqual(account.sent, [{ jid: BOB, name: "Bob" }]);
  assert.equal(bob.buddy.contact.alias, "", "no local name");
  assert.deepEqual(result.written, { [writtenKey(ME, BOB)]: { name: "Bob", where: "server" } });
  // Run again: already named, nothing sent.
  const again = run([account], { modes: { [ME]: "server" }, apply: true, written: result.written });
  assert.equal(byJid(again, BOB).status, "named");
  assert.equal(account.sent.length, 1);
});

test("off writes nothing", () => {
  const account = makeAccount(ME);
  const alice = addBuddy(account, ALICE);
  const result = run([account], { apply: true });
  assert.equal(result.accounts[0].mode, "off");
  assert.equal(alice.buddy.contact.alias, "");
  assert.deepEqual(account.sent, []);
});

test("names a contact already has are kept", () => {
  for (const mode of ["local", "server"]) {
    const account = makeAccount(ME);
    const rostered = addBuddy(account, ALICE, { roster: "Ally" });
    const renamed = addBuddy(account, BOB);
    renamed.buddy.contact._alias = "Bobby";
    const result = run([account], { modes: { [ME]: mode }, apply: true });
    assert.deepEqual([byJid(result, ALICE).status, byJid(result, ALICE).current], ["kept", "Ally"]);
    assert.deepEqual([byJid(result, BOB).status, byJid(result, BOB).current], ["kept", "Bobby"]);
    assert.equal(rostered.buddy.contact.alias, "");
    assert.equal(renamed.buddy.contact.alias, "Bobby");
    assert.deepEqual(account.sent, []);
  }
});

test("Thunderbird only keeps a roster name from another account of the same contact", () => {
  const work = makeAccount(ME);
  const home = makeAccount("test3@test.snikket.chat");
  const contact = new Contact();
  addBuddy(work, BOB, { contact });
  addBuddy(home, BOB, { contact, roster: "Robert" });
  const result = run([work], { modes: { [ME]: "local" }, apply: true });
  assert.deepEqual([byJid(result, BOB).status, byJid(result, BOB).current], ["kept", "Robert"]);
  assert.equal(contact.alias, "");
});

test("different names for one number: no name", () => {
  const account = makeAccount(ME);
  const shop = addBuddy(account, SHOP);
  const result = run([account], { modes: { [ME]: "local" }, apply: true });
  assert.equal(byJid(result, SHOP).status, "ambiguous");
  assert.deepEqual(byJid(result, SHOP).names, ["Shop", "Other shop"]);
  assert.equal(shop.buddy.contact.alias, "");
});

test("unmatched contacts, and contacts the server's roster doesn't have", () => {
  const account = makeAccount(ME);
  addBuddy(account, "+15550001111@cheogram.com");
  addBuddy(account, ALICE, { onRoster: false });
  const result = run([account], { modes: { [ME]: "server" }, apply: true });
  assert.equal(byJid(result, "+15550001111@cheogram.com").status, "unmatched");
  assert.equal(byJid(result, ALICE).status, "no-roster");
  assert.deepEqual(account.sent, []);
});

test("a name this add-on wrote follows the card; one the user changed doesn't", () => {
  for (const mode of ["local", "server"]) {
    const account = makeAccount(ME);
    const alice = addBuddy(account, ALICE);
    const first = run([account], { modes: { [ME]: mode }, apply: true });
    const renamed = [vcard("FN:Alice Smith", "TEL:(555) 234-5678")];
    const second = chatNames({ accounts: [account], jidOf: (a) => a.jid, cards: renamed, modes: { [ME]: mode }, apply: true, written: first.written });
    assert.deepEqual([byJid(second, ALICE).status, byJid(second, ALICE).current], ["update", "Alice"]);
    const shown = mode === "local" ? alice.buddy.contact.alias : alice._rosterAlias;
    assert.equal(shown, "Alice Smith");
    assert.deepEqual(second.written[writtenKey(ME, ALICE)], { name: "Alice Smith", where: mode });
    // The user renames the contact: the next card change leaves it alone.
    if (mode === "local") {
      alice.buddy.contact._alias = "Mom";
    } else {
      alice._rosterAlias = "Mom";
    }
    const third = chatNames({ accounts: [account], jidOf: (a) => a.jid, cards: [vcard("FN:A. Smith", "TEL:(555) 234-5678")], modes: { [ME]: mode }, apply: true, written: second.written });
    assert.deepEqual([byJid(third, ALICE).status, byJid(third, ALICE).current], ["kept", "Mom"]);
  }
});

test("a contact on two accounts is named once", () => {
  const work = makeAccount(ME);
  const home = makeAccount("test3@test.snikket.chat");
  const contact = new Contact();
  addBuddy(work, BOB, { contact });
  addBuddy(home, BOB, { contact });
  const result = run([work, home], { modes: { [ME]: "local", "test3@test.snikket.chat": "local" }, apply: true });
  assert.equal(result.accounts[0].contacts[0].status, "set");
  assert.equal(result.accounts[1].contacts[0].status, "named");
  assert.equal(contact.alias, "Bob");
  assert.deepEqual([...work.sent, ...home.sent], []);
});

test("setLocalName leaves a buddy's own serverAlias alone and restores the rest", () => {
  const account = makeAccount(ME);
  const contact = new Contact();
  const one = addBuddy(account, BOB, { contact });
  addBuddy(makeAccount("test3@test.snikket.chat"), BOB, { contact });
  setLocalName(contact, "Bob");
  assert.equal(contact.alias, "Bob");
  assert.equal(one.serverAlias, "", "the getter works again");
  for (const buddy of contact.getBuddies()[0].getAccountBuddies()) {
    assert.equal(Object.hasOwn(buddy, "serverAlias"), false);
  }
});

test("a write that fails is reported, and the rest go on", () => {
  const account = makeAccount(ME);
  const alice = addBuddy(account, ALICE);
  addBuddy(account, BOB);
  Object.defineProperty(alice.buddy.contact, "alias", { get: () => "", set() {
    throw new Error("database busy");
  } });
  const lines = [];
  const result = run([account], { modes: { [ME]: "local" }, apply: true, log: (l) => lines.push(l) });
  assert.equal(byJid(result, ALICE).status, "error");
  assert.equal(byJid(result, BOB).done, true);
  assert.equal(result.written[writtenKey(ME, ALICE)], undefined);
  assert.ok(lines.some((l) => l.startsWith("ERROR:") && !l.includes("Alice")));
});
