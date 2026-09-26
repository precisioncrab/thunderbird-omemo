/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Crypto core public surface. See docs/PLAN.md milestone 2 and
 * docs/TASKS.md. Every module is checked against the reference vectors in
 * test/vectors/: byte for byte for twomemo, and for oldmemo as far as the
 * vectors reach (the key schedule; framing waits for real clients, task
 * 4.12). envelope has no reference data; its format follows XEP-0384.
 *
 * src/core.js re-exports this for the bundle the Experiment loads
 * (scripts/build.mjs), and the Experiment runs selfTest() after loading it.
 */

export * as xeddsa from "./xeddsa.js";
export * as keys from "./keys.js";
export * as protobuf from "./protobuf.js";
export * as x3dh from "./x3dh.js";
export * as doubleRatchet from "./double-ratchet.js";
export * as payload from "./payload.js";
export * as envelope from "./envelope.js";
export { selfTest } from "./self-test.js";
export { hasWebCrypto, setRandomSource } from "./random.js";
