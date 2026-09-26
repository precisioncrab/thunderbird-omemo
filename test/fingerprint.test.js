/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import test from "node:test";
import assert from "node:assert/strict";
import * as keys from "../src/crypto/keys.js";
import { formatFingerprint, fingerprintOfWireKey } from "../src/omemo/fingerprint.js";
import { load, h } from "./helpers.js";

test("fingerprints are the Curve25519 key in hex, in groups of eight, like Conversations shows them", () => {
  const v = load("twomemo");
  const fp = formatFingerprint(h(v.bob.identity.curve25519_pub));
  assert.equal(fp.replace(/ /g, ""), v.bob.identity.curve25519_pub);
  assert.match(fp, /^([0-9a-f]{8} ){7}[0-9a-f]{8}$/);
});

test("the same identity key reads the same in both namespaces", () => {
  const identity = keys.generateIdentityKeyPair();
  const old = fingerprintOfWireKey("oldmemo", keys.encodeIdentityKey("oldmemo", identity.publicKey));
  const two = fingerprintOfWireKey("twomemo", keys.encodeIdentityKey("twomemo", identity.publicKey));
  assert.equal(old, two);
  assert.equal(old, formatFingerprint(identity.publicKey.curve25519));
});

test("the verification link has the form Conversations scans", async () => {
  const { verificationUri } = await import("../src/omemo/fingerprint.js");
  const fp = "01234567 89abcdef 01234567 89abcdef 01234567 89abcdef 01234567 89abcdef";
  assert.equal(verificationUri("test1@example.org", [{ deviceId: 448295335, fingerprint: fp }]),
    "xmpp:test1@example.org?omemo-sid-448295335=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
  assert.equal(verificationUri("a@b", [{ deviceId: 1, fingerprint: fp }, { deviceId: 2, fingerprint: fp }]).split(";").length, 2);
});
