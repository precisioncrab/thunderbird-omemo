/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Key generation and per-namespace public key encodings for OMEMO
 * (XEP-0384), see docs/TASKS.md 2.4 and the constants table there.
 *
 * Our identity key is a Curve25519 private scalar, used for X25519 in X3DH
 * and for XEdDSA signatures, like libsignal clients. Its public half has two
 * forms: the X25519 key (Montgomery u), which oldmemo publishes as
 * 0x05 || u, and the Edwards key with sign bit 0, which twomemo publishes.
 *
 * Every generator takes an optional `random(n)` so tests can inject the
 * reference implementation's random draws (test/vectors/). It is called in
 * the same order the reference consumes randomness: a signed prekey's
 * private key (32 bytes), then its signature nonce (64 bytes); one 32-byte
 * draw per pre key.
 *
 * Nothing here stores keys or tracks which ids are used; that is the key
 * store's job (docs/TASKS.md 3.2). Keep separate signed prekeys and pre keys
 * per namespace, as python-omemo does, since each namespace publishes its
 * own bundle.
 */

import { x25519 } from "@noble/curves/ed25519";
import { randomBytes } from "./random.js";
import * as xeddsa from "./xeddsa.js";

export const NAMESPACES = Object.freeze(["oldmemo", "twomemo"]);

/**
 * Highest pre key / signed prekey id. libsignal, which oldmemo clients such
 * as Conversations are built on, keeps ids in 1..0xFFFFFE and wraps around.
 * Staying in that range is safe for twomemo too.
 */
export const MAX_KEY_ID = 0xfffffe;

// libsignal's type byte for Curve25519 public keys (Curve.DJB_TYPE).
const DJB_TYPE = 0x05;

/**
 * @typedef {object} IdentityPublicKey
 * @property {Uint8Array} curve25519 - 32-byte X25519 public key.
 * @property {Uint8Array|null} ed25519 - 32-byte Ed25519 public key; null for
 *   a peer's oldmemo key, whose wire form carries no sign bit.
 */

/**
 * @param {object} [options]
 * @param {(n: number) => Uint8Array} [options.random]
 * @returns {{ privateKey: Uint8Array, publicKey: IdentityPublicKey }}
 */
export function generateIdentityKeyPair({ random = randomBytes } = {}) {
  const privateKey = clamp(random(32));
  return { privateKey, publicKey: identityPublicKey(privateKey) };
}

/**
 * Both public forms of our identity key.
 *
 * @param {Uint8Array} privateKey - 32-byte Curve25519 private key.
 * @returns {IdentityPublicKey} ed25519 has sign bit 0, as XEdDSA signs with.
 */
export function identityPublicKey(privateKey) {
  return {
    curve25519: x25519.getPublicKey(privateKey),
    ed25519: xeddsa.calculateKeyPair(privateKey).A,
  };
}

/**
 * A signed prekey for one namespace. The signature covers the key's wire
 * encoding, which differs between namespaces, so a signed prekey belongs to
 * one namespace's bundle.
 *
 * @param {Uint8Array} identityPrivateKey
 * @param {number} id - 1..MAX_KEY_ID; never reuse one.
 * @param {"oldmemo"|"twomemo"} namespace
 * @param {object} [options]
 * @param {(n: number) => Uint8Array} [options.random]
 * @param {() => number} [options.now] - milliseconds since the epoch.
 * @returns {{ id: number, privateKey: Uint8Array, publicKey: Uint8Array,
 *   signature: Uint8Array, createdAt: number }}
 */
export function generateSignedPreKey(
  identityPrivateKey,
  id,
  namespace,
  { random = randomBytes, now = Date.now } = {}
) {
  assertKeyId(id);
  const privateKey = clamp(random(32));
  const publicKey = x25519.getPublicKey(privateKey);
  const signature = xeddsa.sign(identityPrivateKey, encodePublicKey(namespace, publicKey), random(64));
  return { id, privateKey, publicKey, signature, createdAt: now() };
}

/**
 * One-time pre keys with consecutive ids, wrapping from MAX_KEY_ID to 1.
 *
 * @param {number} firstId - 1..MAX_KEY_ID.
 * @param {number} count
 * @param {object} [options]
 * @param {(n: number) => Uint8Array} [options.random]
 * @returns {{ id: number, privateKey: Uint8Array, publicKey: Uint8Array }[]}
 */
export function generatePreKeys(firstId, count, { random = randomBytes } = {}) {
  assertKeyId(firstId);
  const keys = [];
  let id = firstId;
  for (let i = 0; i < count; i++) {
    const privateKey = clamp(random(32));
    keys.push({ id, privateKey, publicKey: x25519.getPublicKey(privateKey) });
    id = nextKeyId(id);
  }
  return keys;
}

/**
 * @param {number} id - 1..MAX_KEY_ID.
 * @returns {number} the id after `id`, wrapping from MAX_KEY_ID to 1.
 */
export function nextKeyId(id) {
  assertKeyId(id);
  return (id % MAX_KEY_ID) + 1;
}

// --- wire encodings ---

/**
 * Wire form of a signed prekey, pre key or ratchet public key.
 *
 * @param {"oldmemo"|"twomemo"} namespace
 * @param {Uint8Array} publicKey - 32-byte X25519 public key.
 * @returns {Uint8Array} oldmemo: 0x05 || key (33 bytes); twomemo: the key.
 */
export function encodePublicKey(namespace, publicKey) {
  assertNamespace(namespace);
  assertLength(publicKey, 32, "X25519 public key");
  return namespace === "oldmemo" ? withTypeByte(publicKey) : Uint8Array.from(publicKey);
}

/**
 * Inverse of encodePublicKey.
 *
 * @param {"oldmemo"|"twomemo"} namespace
 * @param {Uint8Array} bytes
 * @returns {Uint8Array} 32-byte X25519 public key.
 * @throws on a wrong length or missing type byte.
 */
export function decodePublicKey(namespace, bytes) {
  assertNamespace(namespace);
  return namespace === "oldmemo" ? withoutTypeByte(bytes) : assertLength(bytes, 32, "public key").slice();
}

/**
 * Wire form of an identity key, as published in bundles and used in the
 * X3DH associated data.
 *
 * @param {"oldmemo"|"twomemo"} namespace
 * @param {IdentityPublicKey} identityKey
 * @returns {Uint8Array} oldmemo: 0x05 || X25519 key (33 bytes); twomemo: the
 *   Ed25519 key (32 bytes).
 */
export function encodeIdentityKey(namespace, identityKey) {
  assertNamespace(namespace);
  if (namespace === "oldmemo") {
    return withTypeByte(assertLength(identityKey.curve25519, 32, "X25519 identity key"));
  }
  if (!identityKey.ed25519) {
    throw new Error("A twomemo identity key needs its Ed25519 form.");
  }
  return assertLength(identityKey.ed25519, 32, "Ed25519 identity key").slice();
}

/**
 * Inverse of encodeIdentityKey, for a peer's published identity key.
 *
 * @param {"oldmemo"|"twomemo"} namespace
 * @param {Uint8Array} bytes
 * @returns {IdentityPublicKey} for oldmemo, ed25519 is null (the wire form
 *   has no sign bit; it travels in signatures instead, see xeddsa.verify).
 * @throws on a wrong length, missing type byte, or a twomemo key that is not
 *   a valid Ed25519 point.
 */
export function decodeIdentityKey(namespace, bytes) {
  assertNamespace(namespace);
  if (namespace === "oldmemo") {
    return { curve25519: withoutTypeByte(bytes), ed25519: null };
  }
  const ed25519 = assertLength(bytes, 32, "Ed25519 identity key").slice();
  return { curve25519: xeddsa.edwardsToMontgomery(ed25519), ed25519 };
}

/**
 * Checks a peer's signed prekey signature, as found in their bundle.
 *
 * @param {"oldmemo"|"twomemo"} namespace
 * @param {IdentityPublicKey} identityKey - from decodeIdentityKey.
 * @param {Uint8Array} signedPreKey - 32-byte X25519 public key.
 * @param {Uint8Array} signature - 64 bytes, as published.
 * @returns {boolean} never throws.
 */
export function verifySignedPreKey(namespace, identityKey, signedPreKey, signature) {
  try {
    const message = encodePublicKey(namespace, signedPreKey);
    if (namespace === "oldmemo") {
      return xeddsa.verify(identityKey.curve25519, message, signature);
    }
    return Boolean(identityKey.ed25519) && xeddsa.verifyEdwards(identityKey.ed25519, message, signature);
  } catch {
    return false;
  }
}

// --- internals ---

function clamp(bytes) {
  const k = Uint8Array.from(assertLength(bytes, 32, "private key"));
  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;
  return k;
}

function withTypeByte(publicKey) {
  const out = new Uint8Array(33);
  out[0] = DJB_TYPE;
  out.set(publicKey, 1);
  return out;
}

function withoutTypeByte(bytes) {
  assertLength(bytes, 33, "oldmemo public key");
  if (bytes[0] !== DJB_TYPE) {
    throw new Error("oldmemo public key must start with the 0x05 type byte.");
  }
  return bytes.slice(1);
}

function assertLength(bytes, length, what) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== length) {
    throw new Error(`${what} must be ${length} bytes.`);
  }
  return bytes;
}

function assertNamespace(namespace) {
  if (!NAMESPACES.includes(namespace)) {
    throw new Error(`Unknown OMEMO namespace "${namespace}"; expected "oldmemo" or "twomemo".`);
  }
}

function assertKeyId(id) {
  if (!Number.isInteger(id) || id < 1 || id > MAX_KEY_ID) {
    throw new Error(`Key id must be an integer from 1 to ${MAX_KEY_ID}; got ${id}.`);
  }
}
