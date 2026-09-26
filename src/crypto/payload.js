/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * OMEMO payload encryption (XEP-0384), docs/TASKS.md 2.8. A message's body
 * is encrypted once with a fresh key; the resulting key material is then
 * encrypted for each recipient device with its Double Ratchet session
 * (double-ratchet.js). The ciphertext goes in <payload>.
 *
 *   oldmemo: AES-128-GCM with a random 16-byte key and 12-byte IV (sent in
 *     <iv>). Key material = key || 16-byte tag (32 B); <payload> holds the
 *     ciphertext without the tag. The plaintext is the body text.
 *   twomemo: a random 32-byte key, HKDF-SHA-256(salt = 32 zero bytes,
 *     info "OMEMO Payload", 80 B) = AES key 32 || MAC key 32 || IV 16;
 *     AES-256-CBC, then HMAC-SHA-256(MAC key, ciphertext) truncated to 16 B.
 *     Key material = key || MAC (48 B). The plaintext is an XEP-0420
 *     envelope (envelope.js).
 *
 * An empty OMEMO message has no <payload>; its ratchet message only moves
 * the session along (emptyKeyMaterial).
 *
 * twomemo is checked byte for byte against python-twomemo
 * (test/payload.test.js). oldmemo has no permissive reference, so it is
 * checked with a published AES-GCM test vector and gets confirmed against
 * real clients in task 4.12. Randomness is injectable, as in keys.js.
 */

import { hkdf } from "@noble/hashes/hkdf";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "./random.js";
import { cbc, gcm } from "@noble/ciphers/aes";
import * as keys from "./keys.js";

const TWOMEMO_INFO = "OMEMO Payload";
const TWOMEMO_MAC_LENGTH = 16;
const GCM_TAG_LENGTH = 16;
const ZERO_SALT = new Uint8Array(32);

/**
 * @typedef {object} EncryptedPayload
 * @property {Uint8Array} keyMaterial - what the ratchet encrypts per device.
 * @property {Uint8Array} ciphertext - the <payload> content.
 * @property {Uint8Array} [iv] - oldmemo only: the <iv> content.
 */

/**
 * @param {"oldmemo"|"twomemo"} namespace
 * @param {Uint8Array} plaintext - oldmemo: the UTF-8 body; twomemo: the
 *   envelope from envelope.buildEnvelope.
 * @param {object} [options]
 * @param {(n: number) => Uint8Array} [options.random] - oldmemo: the key
 *   (16 bytes), then the IV (12 bytes); twomemo: the key (32 bytes).
 * @returns {EncryptedPayload}
 */
export function encrypt(namespace, plaintext, { random = randomBytes } = {}) {
  assertNamespace(namespace);
  if (!(plaintext instanceof Uint8Array)) {
    throw new Error("Payload plaintext must be a Uint8Array.");
  }
  if (namespace === "oldmemo") {
    const key = draw(random, 16, "payload key");
    const iv = draw(random, 12, "payload IV");
    const sealed = gcm(key, iv).encrypt(plaintext);
    const ciphertext = sealed.slice(0, sealed.length - GCM_TAG_LENGTH);
    const tag = sealed.slice(sealed.length - GCM_TAG_LENGTH);
    return { keyMaterial: concatBytes(key, tag), ciphertext, iv };
  }

  const key = draw(random, 32, "payload key");
  const { aesKey, macKey, iv } = expandTwomemoKey(key);
  const ciphertext = cbc(aesKey, iv).encrypt(plaintext);
  const mac = hmac(sha256, macKey, ciphertext).slice(0, TWOMEMO_MAC_LENGTH);
  return { keyMaterial: concatBytes(key, mac), ciphertext };
}

/**
 * @param {"oldmemo"|"twomemo"} namespace
 * @param {object} encrypted
 * @param {Uint8Array} encrypted.keyMaterial - as the ratchet decrypted it.
 * @param {Uint8Array} encrypted.ciphertext - from <payload>.
 * @param {Uint8Array} [encrypted.iv] - oldmemo: from <iv>.
 * @returns {Uint8Array} plaintext
 * @throws on a wrong-sized key or IV, a failed tag or MAC, or bad padding.
 */
export function decrypt(namespace, { keyMaterial, ciphertext, iv }) {
  assertNamespace(namespace);
  assertBytes(keyMaterial, "key material");
  assertBytes(ciphertext, "payload ciphertext");

  if (namespace === "oldmemo") {
    assertBytes(iv, "payload IV");
    // Current clients send a 12-byte IV; older Conversations versions sent
    // 16 bytes, which GCM also defines.
    if (iv.length !== 12 && iv.length !== 16) {
      throw new Error(`oldmemo IV must be 12 or 16 bytes; got ${iv.length}.`);
    }
    // Key material is key || tag. Some old clients sent only the key and
    // appended the tag to <payload> instead.
    let sealed;
    if (keyMaterial.length === 16 + GCM_TAG_LENGTH) {
      sealed = concatBytes(ciphertext, keyMaterial.subarray(16));
    } else if (keyMaterial.length === 16) {
      sealed = ciphertext;
    } else {
      throw new Error(`oldmemo key material must be 32 (or legacy 16) bytes; got ${keyMaterial.length}.`);
    }
    return gcm(keyMaterial.subarray(0, 16), iv).decrypt(sealed);
  }

  if (keyMaterial.length !== 32 + TWOMEMO_MAC_LENGTH) {
    throw new Error(`twomemo key material must be 48 bytes; got ${keyMaterial.length}.`);
  }
  const { aesKey, macKey, iv: cbcIv } = expandTwomemoKey(keyMaterial.subarray(0, 32));
  const mac = hmac(sha256, macKey, ciphertext).slice(0, TWOMEMO_MAC_LENGTH);
  if (!constantTimeEqual(mac, keyMaterial.subarray(32))) {
    throw new Error("Payload authentication failed.");
  }
  return cbc(aesKey, cbcIv).decrypt(ciphertext);
}

/**
 * What the ratchet encrypts for an empty OMEMO message (no <payload>).
 *
 * @param {"oldmemo"|"twomemo"} namespace
 * @param {object} [options]
 * @param {(n: number) => Uint8Array} [options.random] - oldmemo only: 16 bytes.
 * @returns {Uint8Array} oldmemo: 16 random bytes, like Conversations' key
 *   transport messages; twomemo: 32 zero bytes, as python-twomemo sends.
 */
export function emptyKeyMaterial(namespace, { random = randomBytes } = {}) {
  assertNamespace(namespace);
  return namespace === "oldmemo" ? draw(random, 16, "empty message key") : new Uint8Array(32);
}

// --- internals ---

function expandTwomemoKey(key) {
  const out = hkdf(sha256, key, ZERO_SALT, TWOMEMO_INFO, 80);
  return { aesKey: out.slice(0, 32), macKey: out.slice(32, 64), iv: out.slice(64, 80) };
}

function draw(random, n, what) {
  const bytes = Uint8Array.from(random(n));
  if (bytes.length !== n) {
    throw new Error(`The ${what} must be ${n} bytes.`);
  }
  return bytes;
}

function assertBytes(value, what) {
  if (!(value instanceof Uint8Array)) {
    throw new Error(`The ${what} must be a Uint8Array.`);
  }
}

function assertNamespace(namespace) {
  if (!keys.NAMESPACES.includes(namespace)) {
    throw new Error(`Unknown OMEMO namespace "${namespace}"; expected "oldmemo" or "twomemo".`);
  }
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

function concatBytes(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}
