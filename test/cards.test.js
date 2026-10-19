/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests for src/contacts/cards.js: reading address book cards and matching
 * chat addresses to their names.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { indexCards, nameFor, parseVCard, phoneNumber, phoneOfChatAddress, readCard } from "../src/contacts/cards.js";

const vcard = (...lines) => ["BEGIN:VCARD", "VERSION:4.0", ...lines, "END:VCARD"].join("\r\n");

test("vCard lines: folding, groups, parameters and quoted colons", () => {
  const props = parseVCard("BEGIN:VCARD\r\nitem1.TEL;TYPE=\"cell,voice\";PREF=1:+1 555\r\n  123 4567\r\nNOTE:a: b\r\nEND:VCARD");
  const tel = props.find((p) => p.name === "TEL");
  assert.equal(tel.value, "+1 555 123 4567");
  assert.equal(tel.params.TYPE, "cell,voice");
  assert.equal(tel.params.PREF, "1");
  assert.equal(props.find((p) => p.name === "NOTE").value, "a: b");
});

test("a card's name: FN, else the name parts, else the organization", () => {
  assert.equal(readCard(vcard("FN:Alice  Example", "N:Other;Name;;;")).name, "Alice Example");
  assert.equal(readCard(vcard("N:Example;Bob;Q.;Dr.;Jr.")).name, "Dr. Bob Q. Example Jr.");
  assert.equal(readCard(vcard("ORG:Corner Shop;Sales")).name, "Corner Shop");
  assert.equal(readCard(vcard("FN:Smith\\, Jane")).name, "Smith, Jane");
});

test("a card's phones, chat addresses and emails", () => {
  const card = readCard(vcard(
    "FN:Alice",
    "TEL;TYPE=cell:(555) 234-5678",
    "TEL;VALUE=uri:tel:+44-20-7946-0958",
    "TEL:555-1234",
    "IMPP:xmpp:Alice@Example.org?message",
    "IMPP:sip:alice@example.org",
    "EMAIL;TYPE=home:Alice@Mail.example",
  ));
  assert.deepEqual(card.phones, ["+15552345678", "+442079460958"]);
  assert.deepEqual(card.xmpp, ["alice@example.org"]);
  assert.deepEqual(card.emails, ["alice@mail.example"]);
});

test("phone numbers in any format, to +E.164", () => {
  assert.equal(phoneNumber("+1 (555) 234-5678"), "+15552345678");
  assert.equal(phoneNumber("555.234.5678"), "+15552345678");
  assert.equal(phoneNumber("1-555-234-5678"), "+15552345678");
  assert.equal(phoneNumber("tel:+1-555-234-5678;ext=12"), "+15552345678");
  assert.equal(phoneNumber("555-234-5678 x12"), "+15552345678");
  assert.equal(phoneNumber("555-234-5678 ext. 12"), "+15552345678");
  assert.equal(phoneNumber("0044 20 7946 0958"), "+442079460958");
  assert.equal(phoneNumber("+49 30 1234567"), "+49301234567");
  // Can't be placed: too short, no country code, letters.
  assert.equal(phoneNumber("234-5678"), null);
  assert.equal(phoneNumber("020 7946 0958"), null);
  assert.equal(phoneNumber("1-800-FLOWERS"), null);
  assert.equal(phoneNumber(""), null);
});

test("chat addresses that are phone numbers", () => {
  assert.equal(phoneOfChatAddress("+15552345678@cheogram.com"), "+15552345678");
  assert.equal(phoneOfChatAddress("+442079460958@quicksy.im"), "+442079460958");
  assert.equal(phoneOfChatAddress("15552345678@cheogram.com"), null);
  assert.equal(phoneOfChatAddress("test1@test.snikket.chat"), null);
  assert.equal(phoneOfChatAddress("+15552345678"), null);
});

test("names by phone number, chat address, then email", () => {
  const index = indexCards([
    vcard("FN:Alice", "TEL:555-234-5678", "EMAIL:test1@test.snikket.chat"),
    vcard("FN:Bob", "IMPP:xmpp:test1@test.snikket.chat"),
    vcard("FN:Carol", "EMAIL:carol@example.org"),
  ]);
  assert.equal(index.cards, 3);
  assert.deepEqual(nameFor(index, "+15552345678@cheogram.com"), { name: "Alice", by: "phone" });
  // The chat address wins over an email address.
  assert.deepEqual(nameFor(index, "test1@test.snikket.chat"), { name: "Bob", by: "xmpp" });
  assert.deepEqual(nameFor(index, "Carol@Example.org"), { name: "Carol", by: "email" });
  assert.deepEqual(nameFor(index, "+15550000000@cheogram.com"), { name: null, by: null });
  // A phone-number address only matches phones, never an email.
  assert.deepEqual(nameFor(indexCards([vcard("FN:Dan", "EMAIL:+15552345678@cheogram.com")]), "+15552345678@cheogram.com"), { name: null, by: null });
});

test("cards with different names for one number give no name", () => {
  const index = indexCards([
    vcard("FN:Alice", "TEL:+1 555 234 5678"),
    vcard("FN:Shop", "TEL:(555) 234-5678"),
    vcard("FN:Eve", "TEL:+1 555 999 0000"),
    vcard("FN:eve", "TEL:555 999 0000"),
  ]);
  assert.deepEqual(nameFor(index, "+15552345678@cheogram.com"), { name: null, by: "phone", names: ["Alice", "Shop"] });
  // The same name twice (duplicate cards, any case) is still one name.
  assert.deepEqual(nameFor(index, "+15559990000@cheogram.com"), { name: "Eve", by: "phone" });
});

test("cards without a real name are left out", () => {
  const index = indexCards([
    vcard("FN:+1 555 234 5678", "TEL:+1 555 234 5678"),
    vcard("FN:someone@example.org", "EMAIL:someone@example.org"),
    vcard("TEL:+1 555 777 8888"),
  ]);
  assert.equal(index.cards, 0);
  assert.equal(nameFor(index, "+15552345678@cheogram.com").name, null);
});
