/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests for src/contacts/chat-sections.js, against fakes that behave like
 * Thunderbird 158's chat contact list (messenger.xhtml's #contactlistbox and
 * chat-group.js) and contacts (imContacts.sys.mjs), written from their
 * behavior, not copied:
 *   - the list is flat: a group is a header row, its contacts the rows after it;
 *   - a group's addContact makes a row for a contact once (contactsById),
 *     keeps its rows sorted online first, then by name, and returns the row;
 *   - removeContact takes the row out by the contact's id;
 *   - a group keeps its name in displayName once it has shown it.
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  planSections, syncSections, removeSections, repositionContact, sectionLabel,
  accountIdsOf, accountBuddyOn, sectionGroups, SECTIONS_ATTR, ROW_ATTR, SECTION_ATTR, SECTIONS_CSS,
} from "../src/contacts/chat-sections.js";

class FakeElement {
  constructor() {
    this.attributes = new Map();
    this.parent = null;
  }
  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }
  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }
  hasAttribute(name) {
    return this.attributes.has(name);
  }
  removeAttribute(name) {
    this.attributes.delete(name);
  }
  remove() {
    this.parent?.children.splice(this.parent.children.indexOf(this), 1);
    this.parent = null;
  }
}

class FakeList extends FakeElement {
  constructor() {
    super();
    this.children = [];
  }
  append(el) {
    el.parent = this;
    this.children.push(el);
  }
  insertAfter(el, before) {
    el.parent = this;
    this.children.splice(this.children.indexOf(before) + 1, 0, el);
  }
}

class FakeRow extends FakeElement {
  constructor(contact) {
    super();
    this.contact = contact;
    this.destroyed = false;
  }
  destroy() {
    this.destroyed = true;
  }
}

const order = (a, b) => (b.statusType - a.statusType) || a.displayName.toLowerCase().localeCompare(b.displayName.toLowerCase());

class FakeGroup extends FakeElement {
  constructor() {
    super();
    this.contacts = [];
    this.contactsById = {};
    this.displayName = "";
  }
  _updateGroupLabel() {
    if (!this.displayName) {
      this.displayName = this.getAttribute("name");
    }
    this.setAttribute("name", this.displayName);
  }
  addContact(contact) {
    if (this.contactsById[contact.id]) {
      return null;
    }
    const row = new FakeRow(contact);
    let at = this.contacts.findIndex((r) => order(contact, r.contact) < 0);
    if (at < 0) {
      at = this.contacts.length;
    }
    this.parent.insertAfter(row, at === 0 ? this : this.contacts[at - 1]);
    this.contacts.splice(at, 0, row);
    this.contactsById[contact.id] = row;
    this._updateGroupLabel();
    return row;
  }
  removeContact(contactForId) {
    const row = this.contactsById[contactForId.id];
    if (!row) {
      throw new Error(`no row for ${contactForId.id}`);
    }
    this.contacts = this.contacts.filter((r) => r !== row);
    delete this.contactsById[row.contact.id];
    row.remove();
    row.destroy();
    return row;
  }
  updateContactPosition(contact) {
    const row = this.removeContact(contact);
    this.addContact(row.contact);
  }
}

// Thunderbird's own groups, which the sections hide.
function makeList() {
  const list = new FakeList();
  for (const id of ["conversationsGroup", "onlinecontactsGroup", "offlinecontactsGroup"]) {
    const group = new FakeGroup();
    group.id = id;
    list.append(group);
  }
  return list;
}

let nextId = 1;
function makeContact(name, accountIds, { online = false } = {}) {
  const accountBuddies = accountIds.map((id) => ({ account: { id }, normalizedName: `${name.toLowerCase()}@example.org` }));
  return {
    id: nextId++,
    displayName: name,
    statusType: online ? 7 : 1,
    getBuddies: () => [{ getAccountBuddies: () => accountBuddies }],
  };
}

const accounts = [{ id: "1", label: "test1" }, { id: "2", label: "test2" }];
const sync = (list, plan) => syncSections(list, plan, { createGroup: () => new FakeGroup() });
// What the list shows: section names and the names under each.
function shown(list) {
  return sectionGroups(list).map((g) => [g.getAttribute("name"), ...g.contacts.map((r) => r.contact.displayName)]);
}

test("a section per account, in account order, online contacts first", () => {
  const list = makeList();
  const contacts = [
    makeContact("Zed", ["1"], { online: true }),
    makeContact("Amy", ["1"]),
    makeContact("Bob", ["1", "2"]),
    makeContact("Cat", ["2"], { online: true }),
  ];
  const result = sync(list, planSections(accounts, contacts));
  assert.deepEqual(shown(list), [["test1", "Zed", "Amy", "Bob"], ["test2", "Cat", "Bob"]]);
  assert.deepEqual(result, { sections: 2, added: 5, removed: 0 });
  assert.equal(list.getAttribute(SECTIONS_ATTR), "true");
  // Rows follow their header in the flat list.
  const names = list.children.map((el) => el.id ?? el.getAttribute(SECTION_ATTR) ?? el.contact.displayName);
  assert.deepEqual(names, ["conversationsGroup", "onlinecontactsGroup", "offlinecontactsGroup", "1", "Zed", "Amy", "Bob", "2", "Cat", "Bob"]);
  assert.ok(list.children.filter((el) => el instanceof FakeRow).every((row) => row.getAttribute(ROW_ATTR)));
});

test("a contact on two accounts is in both sections, each row knowing its account", () => {
  const list = makeList();
  const both = makeContact("Both", ["1", "2"]);
  const seen = [];
  syncSections(list, planSections(accounts, [both]), { createGroup: () => new FakeGroup(), onRow: (row, id) => seen.push([row.contact.displayName, id]) });
  assert.deepEqual(seen, [["Both", "1"], ["Both", "2"]]);
  assert.deepEqual(accountIdsOf(both), new Set(["1", "2"]));
  assert.equal(accountBuddyOn(both, "2").account.id, "2");
  assert.equal(accountBuddyOn(both, "3"), null);
});

test("a second run changes only what changed", () => {
  const list = makeList();
  const amy = makeContact("Amy", ["1"]);
  const bob = makeContact("Bob", ["1"]);
  sync(list, planSections(accounts, [amy, bob]));
  const amyRow = sectionGroups(list)[0].contactsById[amy.id];
  const cat = makeContact("Cat", ["2"]);
  const result = sync(list, planSections(accounts, [amy, cat]));
  assert.deepEqual(result, { sections: 2, added: 1, removed: 1 });
  assert.equal(sectionGroups(list)[0].contactsById[amy.id], amyRow);
  assert.deepEqual(shown(list), [["test1", "Amy"], ["test2", "Cat"]]);
  assert.deepEqual(sync(list, planSections(accounts, [amy, cat])), { sections: 2, added: 0, removed: 0 });
});

test("renaming a section keeps its rows; new accounts make the sections again", () => {
  const list = makeList();
  const amy = makeContact("Amy", ["1"]);
  sync(list, planSections(accounts, [amy]));
  const group = sectionGroups(list)[0];
  sync(list, planSections([{ id: "1", label: "Main" }, accounts[1]], [amy]));
  assert.equal(sectionGroups(list)[0], group);
  assert.deepEqual(shown(list), [["Main", "Amy"], ["test2"]]);
  sync(list, planSections([...accounts, { id: "3", label: "test3" }], [amy]));
  assert.notEqual(sectionGroups(list)[0], group);
  assert.deepEqual(shown(list), [["test1", "Amy"], ["test2"], ["test3"]]);
  assert.ok(group.contacts.length === 0 && !group.parent);
});

test("a contact that stopped being a dummy (new id) is replaced, not left behind", () => {
  const list = makeList();
  const amy = makeContact("Amy", ["1"]);
  sync(list, planSections(accounts, [amy]));
  const oldId = amy.id;
  amy.id = 999;
  sync(list, planSections(accounts, [amy]));
  const group = sectionGroups(list)[0];
  assert.deepEqual(Object.keys(group.contactsById), ["999"]);
  assert.equal(group.contactsById[oldId], undefined);
  assert.deepEqual(shown(list), [["test1", "Amy"], ["test2"]]);
});

test("turning the sections off takes them out and shows Thunderbird's groups again", () => {
  const list = makeList();
  const rows = [];
  syncSections(list, planSections(accounts, [makeContact("Amy", ["1", "2"])]), { createGroup: () => new FakeGroup(), onRow: (row) => rows.push(row) });
  removeSections(list);
  assert.deepEqual(list.children.map((el) => el.id), ["conversationsGroup", "onlinecontactsGroup", "offlinecontactsGroup"]);
  assert.equal(list.hasAttribute(SECTIONS_ATTR), false);
  assert.ok(rows.every((r) => r.destroyed));
});

test("signing on moves a contact up in each section it's in", () => {
  const list = makeList();
  const amy = makeContact("Amy", ["1", "2"]);
  const bob = makeContact("Bob", ["1", "2"]);
  sync(list, planSections(accounts, [amy, bob]));
  bob.statusType = 7;
  repositionContact(list, bob);
  assert.deepEqual(shown(list), [["test1", "Bob", "Amy"], ["test2", "Bob", "Amy"]]);
});

test("section names: chosen, else the address before the @, else the account's name", () => {
  assert.equal(sectionLabel({ jid: "Test1@test.snikket.chat" }, { "test1@test.snikket.chat": "  Work  " }), "Work");
  assert.equal(sectionLabel({ jid: "test1@test.snikket.chat" }, { "test1@test.snikket.chat": "  " }), "test1");
  assert.equal(sectionLabel({ jid: "", name: "irc.example.org" }), "irc.example.org");
});

test("the style sheet hides only Thunderbird's own contact groups and rows", () => {
  assert.match(SECTIONS_CSS, /#onlinecontactsGroup/);
  assert.match(SECTIONS_CSS, /#offlinecontactsGroup/);
  assert.match(SECTIONS_CSS, /:not\(\[omemo-section-row\]\)/);
  assert.doesNotMatch(SECTIONS_CSS, /conversationsGroup|chat-imconv/);
});
