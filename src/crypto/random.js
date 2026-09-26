/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * The crypto core's one source of randomness: every module's default
 * `random(n)` is randomBytes below. By default it's noble's, which uses
 * globalThis.crypto.getRandomValues. Thunderbird's privileged module scope
 * may not have Web Crypto, so the Experiment can plug in Thunderbird's own
 * secure generator (nsIRandomGenerator) with setRandomSource.
 */

import { randomBytes as webCryptoRandomBytes } from "@noble/hashes/utils";

let source = null;

/** @returns {boolean} whether this scope has Web Crypto's getRandomValues. */
export function hasWebCrypto() {
  return typeof globalThis.crypto?.getRandomValues === "function";
}

/**
 * @param {((n: number) => Uint8Array|number[])|null} fn - a cryptographically
 *   secure source of n random bytes, or null to go back to Web Crypto.
 */
export function setRandomSource(fn) {
  if (fn !== null && typeof fn !== "function") {
    throw new Error("setRandomSource takes a function or null.");
  }
  source = fn;
}

/**
 * @param {number} n
 * @returns {Uint8Array} n random bytes.
 * @throws if the source returns the wrong number of bytes, or there's no
 *   source at all.
 */
export function randomBytes(n) {
  if (!source) {
    if (!hasWebCrypto()) {
      throw new Error("No source of randomness: this scope has no crypto.getRandomValues; call setRandomSource.");
    }
    return webCryptoRandomBytes(n);
  }
  const bytes = Uint8Array.from(source(n));
  if (bytes.length !== n) {
    throw new Error(`The random source returned ${bytes.length} bytes; ${n} were asked for.`);
  }
  return bytes;
}
