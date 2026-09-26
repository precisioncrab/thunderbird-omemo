/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests for src/omemo/caps.js: the XEP-0115 verification string, against
 * the XEP's own example (section 5.2).
 */

import test from "node:test";
import assert from "node:assert/strict";
import { capsVer, NOTIFY_FEATURES, CAPS_NODE } from "../src/omemo/caps.js";

const EXODUS = {
  identities: [{ category: "client", type: "pc", name: "Exodus 0.9.1" }],
  features: [
    "http://jabber.org/protocol/disco#info",
    "http://jabber.org/protocol/muc",
    "http://jabber.org/protocol/disco#items",
    "http://jabber.org/protocol/caps",
  ],
};

test("matches XEP-0115's worked example (section 5.2)", () => {
  assert.equal(capsVer(EXODUS), "QgayPKawpkPSDYmwT/WM94uAlu0=");
});

test("order and duplicates don't matter; content does", () => {
  const shuffled = { identities: EXODUS.identities, features: [...EXODUS.features].reverse().concat(EXODUS.features[0]) };
  assert.equal(capsVer(shuffled), "QgayPKawpkPSDYmwT/WM94uAlu0=");
  const withOmemo = { ...EXODUS, features: [...EXODUS.features, ...NOTIFY_FEATURES] };
  assert.notEqual(capsVer(withOmemo), capsVer(EXODUS));
  const renamed = { identities: [{ category: "client", type: "pc", name: "Thunderbird" }], features: EXODUS.features };
  assert.notEqual(capsVer(renamed), capsVer(EXODUS));
});

test("several identities sort by category, type and language", () => {
  const a = { category: "client", type: "pc", lang: "en", name: "A" };
  const b = { category: "client", type: "pc", lang: "de", name: "B" };
  const c = { category: "automation", type: "x" };
  assert.equal(capsVer({ identities: [a, b, c], features: [] }), capsVer({ identities: [c, b, a], features: [] }));
});

test("OMEMO's +notify features and our caps node", () => {
  assert.deepEqual([...NOTIFY_FEATURES], ["eu.siacs.conversations.axolotl.devicelist+notify", "urn:xmpp:omemo:2:devices+notify"]);
  assert.match(CAPS_NODE, /^https:\/\//);
});
