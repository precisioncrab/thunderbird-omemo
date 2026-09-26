/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * X3DH key agreement for OMEMO (XEP-0384), per Signal's spec
 * (https://signal.org/docs/specifications/x3dh/) and docs/TASKS.md 2.6.
 *
 * The initiator builds a session from a peer's published bundle; the
 * responder rebuilds the same secret from the initiator's key exchange
 * message. Both namespaces compute
 *
 *   SK = HKDF-SHA-256(salt = 32 zero bytes,
 *                     ikm = 0xFF x 32 || DH1 || DH2 || DH3 || DH4,
 *                     info = "WhisperText" (oldmemo) / "OMEMO X3DH" (twomemo),
 *                     32 bytes)
 *   AD = initiator's identity key || responder's identity key
 *
 * with identity keys in the namespace's wire form (keys.encodeIdentityKey).
 * SK becomes the Double Ratchet's first root key (task 2.7). DH4 is left out
 * when no one-time pre key was used: X3DH allows that and so does oldmemo,
 * but twomemo's key exchange always names a pre key.
 *
 * Checked byte for byte against the reference in both namespaces
 * (test/x3dh.test.js). Like keys.js, randomness is injectable.
 *
 * encodeKeyExchange/decodeKeyExchange frame the key exchange message the
 * initiator sends until the responder first replies: the X3DH values around
 * the first framed ratchet message (double-ratchet.js).
 */

import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "./random.js";
import * as keys from "./keys.js";
import * as pb from "./protobuf.js";

// libsignal's message version byte, also in front of PreKeySignalMessage.
const OLDMEMO_VERSION = 0x33;

const INFO = Object.freeze({ oldmemo: "WhisperText", twomemo: "OMEMO X3DH" });

// X3DH's F: 32 0xFF bytes ahead of the DH outputs, for domain separation
// from XEdDSA, which uses the same keys.
const PREFIX = new Uint8Array(32).fill(0xff);

/**
 * @typedef {import("./keys.js").IdentityPublicKey} IdentityPublicKey
 *
 * @typedef {object} IdentityKeyPair
 * @property {Uint8Array} privateKey - 32-byte Curve25519 private key.
 * @property {IdentityPublicKey} publicKey - for twomemo, ed25519 must be set.
 *
 * @typedef {object} Bundle - a peer's published bundle, decoded.
 * @property {IdentityPublicKey} identityKey - from keys.decodeIdentityKey.
 * @property {{ id: number, publicKey: Uint8Array, signature: Uint8Array }} signedPreKey
 *   - publicKey from keys.decodePublicKey; signature as published.
 * @property {{ id: number, publicKey: Uint8Array }} [preKey] - one of the
 *   bundle's pre keys, picked at random by the caller.
 *
 * @typedef {object} Handshake
 * @property {Uint8Array} sharedSecret - 32 bytes, the ratchet's first root key.
 * @property {Uint8Array} associatedData - initiator IK || responder IK.
 */

/**
 * The initiator's side: verifies the bundle's signed prekey, then derives
 * the shared secret with a fresh ephemeral key.
 *
 * @param {"oldmemo"|"twomemo"} namespace
 * @param {IdentityKeyPair} ourIdentity
 * @param {Bundle} bundle
 * @param {object} [options]
 * @param {(n: number) => Uint8Array} [options.random] - one 32-byte draw,
 *   the ephemeral private key.
 * @returns {Handshake & { ephemeralPublicKey: Uint8Array,
 *   signedPreKeyId: number, preKeyId: number|null }} what the key exchange
 *   message carries, besides our identity key. ephemeralPublicKey is the
 *   raw 32-byte X25519 key; frame it with keys.encodePublicKey.
 * @throws if the signed prekey signature doesn't verify, or on a malformed
 *   or low-order key.
 */
export function initiateHandshake(namespace, ourIdentity, bundle, { random = randomBytes } = {}) {
  assertNamespace(namespace);
  const { identityKey, signedPreKey, preKey } = bundle;
  if (!keys.verifySignedPreKey(namespace, identityKey, signedPreKey.publicKey, signedPreKey.signature)) {
    throw new Error("The bundle's signed prekey signature does not verify.");
  }

  // x25519 clamps the scalar itself, and the private half is discarded.
  const ephemeralPrivateKey = random(32);
  const dh = (priv, pub) => x25519.getSharedSecret(priv, pub);
  const sharedSecret = deriveSecret(namespace, [
    dh(ourIdentity.privateKey, signedPreKey.publicKey),
    dh(ephemeralPrivateKey, identityKey.curve25519),
    dh(ephemeralPrivateKey, signedPreKey.publicKey),
    ...(preKey ? [dh(ephemeralPrivateKey, preKey.publicKey)] : []),
  ]);

  return {
    sharedSecret,
    associatedData: associatedData(namespace, ourIdentity.publicKey, identityKey),
    ephemeralPublicKey: x25519.getPublicKey(ephemeralPrivateKey),
    signedPreKeyId: signedPreKey.id,
    preKeyId: preKey ? preKey.id : null,
  };
}

/**
 * The responder's side, run on receiving a key exchange message. The caller
 * looks up our signed prekey and pre key by the ids the message names, and
 * deletes the pre key afterwards.
 *
 * @param {"oldmemo"|"twomemo"} namespace
 * @param {object} ours
 * @param {IdentityKeyPair} ours.identity
 * @param {{ privateKey: Uint8Array }} ours.signedPreKey
 * @param {{ privateKey: Uint8Array }} [ours.preKey] - only if the message
 *   names one. Leaving it out when it does gives a different secret, which
 *   shows up later as a failed MAC, so fail the lookup loudly instead.
 * @param {object} theirs - from the key exchange message.
 * @param {IdentityPublicKey} theirs.identityKey - from keys.decodeIdentityKey.
 * @param {Uint8Array} theirs.ephemeralKey - 32-byte X25519 key, from
 *   keys.decodePublicKey.
 * @returns {Handshake}
 * @throws on a malformed or low-order key.
 */
export function respondToHandshake(namespace, ours, theirs) {
  assertNamespace(namespace);
  const { identity, signedPreKey, preKey } = ours;
  const dh = (priv, pub) => x25519.getSharedSecret(priv, pub);
  const sharedSecret = deriveSecret(namespace, [
    dh(signedPreKey.privateKey, theirs.identityKey.curve25519),
    dh(identity.privateKey, theirs.ephemeralKey),
    dh(signedPreKey.privateKey, theirs.ephemeralKey),
    ...(preKey ? [dh(preKey.privateKey, theirs.ephemeralKey)] : []),
  ]);

  return {
    sharedSecret,
    associatedData: associatedData(namespace, theirs.identityKey, identity.publicKey),
  };
}

/**
 * @typedef {object} KeyExchange
 * @property {number} preKeyId
 * @property {number} signedPreKeyId
 * @property {IdentityPublicKey} identityKey - the initiator's.
 * @property {Uint8Array} ephemeralKey - 32-byte X25519 key.
 * @property {Uint8Array} message - the framed ratchet message, from
 *   doubleRatchet.encrypt.
 */

/**
 * Frames a key exchange message: what goes in a <key prekey="true"> (oldmemo)
 * or <key kex="true"> (twomemo) element.
 *
 * @param {"oldmemo"|"twomemo"} namespace
 * @param {KeyExchange} keyExchange
 * @returns {Uint8Array} oldmemo: 0x33 || PreKeySignalMessage (no
 *   registration id, which OMEMO doesn't use); twomemo: OMEMOKeyExchange.
 */
export function encodeKeyExchange(namespace, { preKeyId, signedPreKeyId, identityKey, ephemeralKey, message }) {
  assertNamespace(namespace);
  const value = {
    preKeyId,
    signedPreKeyId,
    identityKey: keys.encodeIdentityKey(namespace, identityKey),
    ephemeralKey: keys.encodePublicKey(namespace, ephemeralKey),
  };
  if (namespace === "oldmemo") {
    const body = pb.encode(pb.oldmemo.OMEMOKeyExchange, { ...value, message });
    return concatBytes(Uint8Array.of(OLDMEMO_VERSION), body);
  }
  // twomemo nests the OMEMOAuthenticatedMessage as a message field.
  return pb.encode(pb.twomemo.OMEMOKeyExchange, {
    ...value,
    message: pb.decode(pb.twomemo.OMEMOAuthenticatedMessage, message),
  });
}

/**
 * Inverse of encodeKeyExchange, for a received key exchange. Nothing here is
 * authenticated yet: the caller runs respondToHandshake, starts a session
 * and decrypts `message`, whose MAC covers the X3DH associated data.
 *
 * @param {"oldmemo"|"twomemo"} namespace
 * @param {Uint8Array} bytes
 * @returns {KeyExchange} identityKey from keys.decodeIdentityKey, so for
 *   oldmemo its ed25519 is null.
 * @throws on malformed input.
 */
export function decodeKeyExchange(namespace, bytes) {
  assertNamespace(namespace);
  let kex;
  let message;
  if (namespace === "oldmemo") {
    if (!(bytes instanceof Uint8Array) || bytes.length < 1 || bytes[0] >> 4 !== OLDMEMO_VERSION >> 4) {
      throw new Error("oldmemo key exchange must start with version byte 0x33.");
    }
    kex = pb.decode(pb.oldmemo.OMEMOKeyExchange, bytes.subarray(1));
    message = kex.message;
  } else {
    kex = pb.decode(pb.twomemo.OMEMOKeyExchange, bytes);
    message = pb.encode(pb.twomemo.OMEMOAuthenticatedMessage, kex.message);
  }
  return {
    preKeyId: kex.preKeyId,
    signedPreKeyId: kex.signedPreKeyId,
    identityKey: keys.decodeIdentityKey(namespace, kex.identityKey),
    ephemeralKey: keys.decodePublicKey(namespace, kex.ephemeralKey),
    message,
  };
}

// --- internals ---

function deriveSecret(namespace, dhOutputs) {
  const ikm = concatBytes(PREFIX, ...dhOutputs);
  return hkdf(sha256, ikm, new Uint8Array(32), INFO[namespace], 32);
}

function associatedData(namespace, initiatorIdentityKey, responderIdentityKey) {
  return concatBytes(
    keys.encodeIdentityKey(namespace, initiatorIdentityKey),
    keys.encodeIdentityKey(namespace, responderIdentityKey)
  );
}

function assertNamespace(namespace) {
  if (!keys.NAMESPACES.includes(namespace)) {
    throw new Error(`Unknown OMEMO namespace "${namespace}"; expected "oldmemo" or "twomemo".`);
  }
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
