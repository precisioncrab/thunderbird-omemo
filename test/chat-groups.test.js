/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests for src/contacts/chat-groups.js, against fakes that behave like
 * Thunderbird 158's tags service and XMPP account buddies (chat/modules/
 * imContacts.sys.mjs, chat/protocols/xmpp/xmpp-base.sys.mjs), written from
 * their behavior, not copied:
 *   - createTag returns the existing tag of that name, else a new one;
 *   - an account buddy's tag setter would also send a roster set, so the
 *     fake's setter records that, and the tests check it's never used.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { chatGroups, defaultGroupName, groupName } from "../src/contacts/chat-groups.js";

function makeTags() {
  const byName = new Map();
  const createTag = (name) => {
    if (!byName.has(name)) {
      byName.set(name, { id: byName.size + 1, name });
    }
    return byName.get(name);
  };
  return { createTag, defaultTag: createTag("Contacts"), byName };
}

function makeAccount(jid, tags, contacts) {
  const account = { jid, _buddies: new Map(), rosterSets: [] };
  for (const [contactJid, serverGroups = []] of contacts) {
    const accountBuddy = {
      normalizedName: contactJid,
      _tag: serverGroups.length ? tags.createTag(serverGroups[0]) : tags.defaultTag,
      _rosterItem: {
        getChildren: (name) => (name === "group" ? serverGroups.map((g) => ({ innerText: g })) : []),
      },
      // Thunderbird's setter changes the server's roster; never to be used here.
      set tag(t) {
        account.rosterSets.push([contactJid, t.name]);
        this._tag = t;
      },
      get tag() {
        return this._tag;
      },
    };
    account._buddies.set(contactJid, accountBuddy);
  }
  return account;
}

function run(accounts, tags, groups, applied = {}) {
  const moves = [];
  const result = chatGroups({
    accounts,
    jidOf: (a) => a.jid,
    groups,
    applied,
    tags,
    moved: (accountBuddy, oldTag, newTag) => moves.push([accountBuddy.normalizedName, oldTag.name, newTag.name]),
  });
  return { result, moves };
}

const tagOf = (account, jid) => account._buddies.get(jid)._tag.name;

test("the default group name is the part of the address before the @, and names are trimmed", () => {
  assert.equal(defaultGroupName("rcc@rcc.example"), "rcc");
  assert.equal(defaultGroupName("noat"), "noat");
  assert.equal(groupName("  Main  "), "Main");
  assert.equal(groupName("x".repeat(80)).length, 64);
  assert.equal(groupName(undefined), "");
});

test("each account's chat contacts move into its own group, in Thunderbird only", () => {
  const tags = makeTags();
  const main = makeAccount("main@example.org", tags, [["alice@example.org"], ["+15551234567@cheogram.com", ["Family"]]]);
  const second = makeAccount("second@example.org", tags, [["bob@example.org"]]);
  const { result, moves } = run([main, second], tags, { "main@example.org": "Main", "second@example.org": "second" });
  assert.equal(tagOf(main, "alice@example.org"), "Main");
  assert.equal(tagOf(main, "+15551234567@cheogram.com"), "Main");
  assert.equal(tagOf(second, "bob@example.org"), "second");
  assert.deepEqual(moves, [
    ["alice@example.org", "Contacts", "Main"],
    ["+15551234567@cheogram.com", "Family", "Main"],
    ["bob@example.org", "Contacts", "second"],
  ]);
  assert.deepEqual(main.rosterSets, []);
  assert.deepEqual(second.rosterSets, []);
  assert.deepEqual(result.applied, { "main@example.org": "Main", "second@example.org": "second" });
  assert.deepEqual(result.accounts.map((a) => [a.jid, a.group, a.contacts, a.moved]), [
    ["main@example.org", "Main", 2, 2],
    ["second@example.org", "second", 1, 1],
  ]);
});

test("a second run moves nothing, so the contact-tag-added notification settles", () => {
  const tags = makeTags();
  const main = makeAccount("main@example.org", tags, [["alice@example.org"]]);
  run([main], tags, { "main@example.org": "Main" });
  const { moves } = run([main], tags, { "main@example.org": "Main" }, { "main@example.org": "Main" });
  assert.deepEqual(moves, []);
});

test("a contact Thunderbird moved back to its server group at connect goes into the group again", () => {
  const tags = makeTags();
  const main = makeAccount("main@example.org", tags, [["alice@example.org", ["Friends"]]]);
  run([main], tags, { "main@example.org": "Main" });
  main._buddies.get("alice@example.org")._tag = tags.createTag("Friends");
  const { moves } = run([main], tags, { "main@example.org": "Main" }, { "main@example.org": "Main" });
  assert.deepEqual(moves, [["alice@example.org", "Friends", "Main"]]);
});

test("turned off, contacts go back to their server group, or Contacts when they have none", () => {
  const tags = makeTags();
  const main = makeAccount("main@example.org", tags, [["alice@example.org"], ["bob@example.org", ["Work"]]]);
  run([main], tags, { "main@example.org": "Main" });
  const { result, moves } = run([main], tags, {}, { "main@example.org": "Main" });
  assert.equal(tagOf(main, "alice@example.org"), "Contacts");
  assert.equal(tagOf(main, "bob@example.org"), "Work");
  assert.equal(moves.length, 2);
  assert.deepEqual(result.applied, {});
  assert.deepEqual(main.rosterSets, []);
});

test("renamed, contacts move from the old group to the new one", () => {
  const tags = makeTags();
  const main = makeAccount("main@example.org", tags, [["alice@example.org"]]);
  run([main], tags, { "main@example.org": "rcc" });
  const { result } = run([main], tags, { "main@example.org": "Main" }, { "main@example.org": "rcc" });
  assert.equal(tagOf(main, "alice@example.org"), "Main");
  assert.deepEqual(result.applied, { "main@example.org": "Main" });
});

test("off and never on: nothing moves, and an account that isn't connected keeps its applied group", () => {
  const tags = makeTags();
  const main = makeAccount("main@example.org", tags, [["alice@example.org", ["Friends"]]]);
  const { result, moves } = run([main], tags, {}, { "offline@example.org": "Old" });
  assert.deepEqual(moves, []);
  assert.equal(tagOf(main, "alice@example.org"), "Friends");
  assert.deepEqual(result.applied, { "offline@example.org": "Old" });
});
