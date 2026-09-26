/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * OMEMO fingerprints for people to compare (docs/TASKS.md milestone 5).
 *
 * Conversations and its forks (Cheogram, Snikket) show a device's
 * fingerprint as the hex of its Curve25519 identity key, without libsignal's
 * 0x05 type byte, in groups of eight. We show the same form for both
 * namespaces (a twomemo identity key is converted from its Ed25519 form), so
 * a Thunderbird device's fingerprint reads the same as on a phone.
 */

import * as keys from "../crypto/keys.js";

/**
 * @param {Uint8Array} curve25519 - a 32-byte X25519 public key.
 * @returns {string} e.g. "a1b2c3d4 e5f60718 ..." (8 groups of 8 hex digits).
 */
export function formatFingerprint(curve25519) {
  const hex = Array.from(curve25519, (b) => b.toString(16).padStart(2, "0")).join("");
  return hex.match(/.{8}/g).join(" ");
}

/**
 * The fingerprint of a peer's identity key as it came in a session or
 * bundle.
 *
 * @param {"oldmemo"|"twomemo"} ns
 * @param {Uint8Array} wireIdentityKey - keys.encodeIdentityKey's form.
 * @returns {string}
 */
export function fingerprintOfWireKey(ns, wireIdentityKey) {
  return formatFingerprint(keys.decodeIdentityKey(ns, wireIdentityKey).curve25519);
}

/**
 * The link Conversations-family clients (Cheogram, Snikket) put in a QR code
 * to verify devices: scanning it marks these keys verified for this JID.
 * Parameters are separated by ";", fingerprints without spaces.
 *
 * @param {string} jid - a bare JID.
 * @param {{ deviceId: number, fingerprint: string }[]} devices
 * @returns {string} e.g. "xmpp:alice@example.org?omemo-sid-123=abcd..."
 */
export function verificationUri(jid, devices) {
  const params = devices.map((d) => `omemo-sid-${d.deviceId}=${d.fingerprint.replace(/ /g, "")}`);
  return `xmpp:${jid}?${params.join(";")}`;
}
