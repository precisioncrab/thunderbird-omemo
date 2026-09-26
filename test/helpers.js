/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Helpers shared by the tests. Not a test file itself (npm test runs
 * test/**\/*.test.js).
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

/** A reference vector file from test/vectors/, parsed. */
export const load = (name) => JSON.parse(readFileSync(new URL(`vectors/${name}.json`, import.meta.url)));

export const h = (hex) => Uint8Array.from(Buffer.from(hex, "hex"));
export const hex = (bytes) => Buffer.from(bytes).toString("hex");
export const b64 = (s) => Uint8Array.from(Buffer.from(s, "base64"));
export const text = (s) => new TextEncoder().encode(s);

/**
 * A random(n) that hands out the given draws in order, checking each size.
 * Draws are byte arrays or vector records ({ value: hex }).
 * `random.remaining()` tells how many are left.
 */
export function replay(...draws) {
  const values = draws.map((d) => (d instanceof Uint8Array ? d : h(d.value)));
  let i = 0;
  const random = (n) => {
    assert.ok(i < values.length, "ran out of recorded random draws");
    assert.equal(values[i].length, n, `draw ${i} has the wrong size`);
    return values[i++];
  };
  random.remaining = () => values.length - i;
  return random;
}

/** A vector party's identity as an IdentityKeyPair (x3dh.js). */
export const identityOf = (party) => ({
  privateKey: h(party.identity.priv),
  publicKey: { curve25519: h(party.identity.curve25519_pub), ed25519: h(party.identity.ed25519_pub) },
});
