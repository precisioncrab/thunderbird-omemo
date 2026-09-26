/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/** Tests for src/omemo/trust.js: blind trust before verification. */

import test from "node:test";
import assert from "node:assert/strict";
import { createStore } from "../src/omemo/store.js";
import { decideTrust, noticeText } from "../src/omemo/trust.js";

const fp = (c) => `${c.repeat(8)} ${c.repeat(8)} ${c.repeat(8)} ${c.repeat(8)} ${c.repeat(8)} ${c.repeat(8)} ${c.repeat(8)} ${c.repeat(8)}`;
const BOB = "bob@example.org";

test("before anything is verified, new devices are trusted automatically and quietly", () => {
  const store = createStore();
  assert.deepEqual(decideTrust(store, BOB, 1, fp("a")), { use: true, state: "blind", notices: [] });
  assert.deepEqual(decideTrust(store, BOB, 2, fp("b")), { use: true, state: "blind", notices: [] });
  assert.equal(store.deviceKey(BOB, 1), fp("a"));
  // Seen again: same answer, nothing new recorded.
  assert.deepEqual(decideTrust(store, BOB, 1, fp("a")), { use: true, state: "blind", notices: [] });
});

test("once one device is verified, a new device is held back and reported", () => {
  const store = createStore();
  decideTrust(store, BOB, 1, fp("a"));
  store.setTrust(BOB, fp("a"), "verified");
  const d = decideTrust(store, BOB, 2, fp("b"));
  assert.equal(d.use, false);
  assert.equal(d.state, "undecided");
  assert.deepEqual(d.notices.map((n) => n.type), ["new-undecided"]);
  assert.match(noticeText(d.notices[0]), /has a new device \(2, bbbbbbbb .*\)\. Messages aren't encrypted to it until you check it: \/omemo verify 2 or \/omemo trust 2/);
  // The user approves it.
  store.setTrust(BOB, fp("b"), "trusted");
  assert.equal(decideTrust(store, BOB, 2, fp("b")).use, true);
  // Other contacts are unaffected.
  assert.equal(decideTrust(store, "carol@example.org", 9, fp("c")).state, "blind");
});

test("a changed key is always reported; without verification it's still used", () => {
  const store = createStore();
  decideTrust(store, BOB, 1, fp("a"));
  const d = decideTrust(store, BOB, 1, fp("c"));
  assert.deepEqual([d.use, d.state], [true, "blind"]);
  assert.deepEqual(d.notices.map((n) => n.type), ["key-changed"]);
  assert.equal(d.notices[0].previous, fp("a"));
  assert.match(noticeText(d.notices[0]), /security key of bob@example\.org's device 1 has changed/);
  assert.equal(store.deviceKey(BOB, 1), fp("c"));
});

test("with a verified device, a changed key is reported and held back", () => {
  const store = createStore();
  decideTrust(store, BOB, 1, fp("a"));
  store.setTrust(BOB, fp("a"), "verified");
  const d = decideTrust(store, BOB, 1, fp("d"));
  assert.deepEqual([d.use, d.state], [false, "undecided"]);
  assert.deepEqual(d.notices.map((n) => n.type), ["key-changed", "new-undecided"]);
});

test("distrusted keys are never used", () => {
  const store = createStore();
  decideTrust(store, BOB, 1, fp("a"));
  store.setTrust(BOB, fp("a"), "distrusted");
  assert.deepEqual(decideTrust(store, BOB, 1, fp("a")), { use: false, state: "distrusted", notices: [] });
});
