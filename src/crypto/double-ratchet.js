/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Double Ratchet sessions for OMEMO (XEP-0384), per Signal's spec
 * (https://signal.org/docs/specifications/doubleratchet/) and
 * docs/TASKS.md 2.7. One state machine, with a per-namespace profile for
 * the parts that differ (see the constants table in docs/TASKS.md):
 *
 *   root KDF     HKDF-SHA-256(salt = root key, ikm = DH output, info, 64 B)
 *                  = new root key || chain key
 *   chain KDF    HMAC-SHA-256(CK, 0x01) = message key, HMAC(CK, 0x02) = next CK
 *   message key  HKDF-SHA-256(salt = 32 zero bytes, ikm = message key, info,
 *                  80 B) = AES key 32 || MAC key 32 || IV 16
 *   cipher       AES-256-CBC with PKCS#7 padding
 *   MAC          HMAC-SHA-256(MAC key, AD || framed message), truncated
 *
 *   oldmemo (libsignal): info "WhisperRatchet" / "WhisperMessageKeys";
 *     framed = 0x33 || SignalMessage, then the 8-byte MAC appended; public
 *     keys carry the 0x05 type byte; AD = sender IK || recipient IK.
 *   twomemo: info "OMEMO Root Chain" / "OMEMO Message Key Material";
 *     OMEMOAuthenticatedMessage { mac (16 B), message = OMEMOMessage };
 *     AD = initiator IK || responder IK for the whole session.
 *
 * Sessions start from x3dh.js: the root key is the X3DH secret, and the
 * initiator does one DH ratchet step against the responder's signed prekey
 * before its first message. The responder can't send until it has received
 * one. (libsignal also derives a first chain key from X3DH that would let
 * the responder send first; OMEMO never uses it, since the responder learns
 * of the session from the initiator's first message.)
 *
 * twomemo is checked byte for byte against all 9 of python-twomemo's
 * messages (test/double-ratchet.test.js). oldmemo's key schedule and
 * associated data are checked against test/vectors/oldmemo.json; its framing
 * follows libsignal and gets confirmed against real clients in task 4.12.
 *
 * decrypt() works on a copy of the state and only commits it once the MAC
 * checks out, so a forged or corrupted message can't damage the session.
 * Randomness is injectable, as in keys.js: the initiator draws its first
 * ratchet key in initSender, and after that a new one is drawn whenever
 * decrypt() meets a new ratchet public key from the peer.
 *
 * serializeState/deserializeState turn a session into plain JSON data and
 * back, for the key store (task 3.2); the vector replay also runs with a
 * save and reload after every step.
 */

import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "./random.js";
import { cbc } from "@noble/ciphers/aes";
import * as keys from "./keys.js";
import * as pb from "./protobuf.js";

/**
 * Most message keys one message may make us skip in a chain. libsignal
 * allows 2000 and python-doubleratchet 1000; the lower one is plenty for
 * chat.
 */
export const MAX_SKIP = 1000;

/**
 * Most skipped message keys a session keeps across all chains. Past it the
 * oldest are dropped, so a message that arrives very late can no longer be
 * decrypted, but a peer can't make the stored session grow without bound.
 * At least MAX_SKIP, so one legitimate gap always fits.
 */
export const MAX_SKIPPED_TOTAL = 2000;

/** Format version of serializeState's output. */
export const STATE_VERSION = 1;

// libsignal's message version byte: current version 3 in both nibbles.
const OLDMEMO_VERSION = 0x33;

const ZERO_SALT = new Uint8Array(32);

/**
 * @typedef {object} Profile
 * @property {string} rootInfo
 * @property {string} messageKeyInfo
 * @property {number} macLength - bytes of HMAC-SHA-256 kept.
 * @property {boolean} senderFirstAd - true: AD = sender IK || recipient IK
 *   per message; false: the X3DH order (initiator || responder) throughout.
 * @property {(pn: number) => number} wirePn - our previous chain length as sent.
 * @property {(pn: number) => number} skipUntil - how many keys of the
 *   previous chain a received pn accounts for.
 * @property {(header: Header, ciphertext: Uint8Array, mac: (data: Uint8Array) => Uint8Array) => Uint8Array} frame
 * @property {(bytes: Uint8Array) => Parsed} parse
 *
 * @typedef {object} Header
 * @property {Uint8Array} dhPublicKey - 32-byte X25519 key.
 * @property {number} n - index in the sender's current chain.
 * @property {number} pn - the sender's previous chain length, as on the wire.
 *
 * @typedef {object} Parsed
 * @property {Header} header
 * @property {Uint8Array} ciphertext
 * @property {Uint8Array} macInput - the framed bytes the MAC covers, after AD.
 * @property {Uint8Array} mac
 */

/** @type {Record<"oldmemo"|"twomemo", Profile>} */
export const PROFILES = Object.freeze({
  oldmemo: Object.freeze({
    rootInfo: "WhisperRatchet",
    messageKeyInfo: "WhisperMessageKeys",
    macLength: 8,
    senderFirstAd: true,
    // libsignal sends the index of the previous chain's last message, not its
    // length (max(length - 1, 0)), and ignores the field on receive. Match it
    // on send, and on receive keep one key past it, which covers both
    // readings at the cost of at most one unused key. Unverified against real
    // clients until task 4.12.
    wirePn: (pn) => Math.max(pn - 1, 0),
    skipUntil: (pn) => pn + 1,
    frame(header, ciphertext, mac) {
      const body = concatBytes(
        Uint8Array.of(OLDMEMO_VERSION),
        pb.encode(pb.oldmemo.OMEMOMessage, {
          dhPub: keys.encodePublicKey("oldmemo", header.dhPublicKey),
          n: header.n,
          pn: header.pn,
          ciphertext,
        })
      );
      return concatBytes(body, mac(body));
    },
    parse(bytes) {
      if (!(bytes instanceof Uint8Array) || bytes.length < 1 + 8) {
        throw new Error("oldmemo message is too short.");
      }
      if (bytes[0] >> 4 !== OLDMEMO_VERSION >> 4) {
        throw new Error(`Unsupported oldmemo message version ${bytes[0] >> 4}.`);
      }
      const body = bytes.subarray(0, bytes.length - 8);
      const message = pb.decode(pb.oldmemo.OMEMOMessage, body.subarray(1));
      return {
        header: { dhPublicKey: keys.decodePublicKey("oldmemo", message.dhPub), n: message.n, pn: message.pn },
        ciphertext: message.ciphertext,
        macInput: body,
        mac: bytes.subarray(bytes.length - 8),
      };
    },
  }),
  twomemo: Object.freeze({
    rootInfo: "OMEMO Root Chain",
    messageKeyInfo: "OMEMO Message Key Material",
    macLength: 16,
    senderFirstAd: false,
    wirePn: (pn) => pn,
    skipUntil: (pn) => pn,
    frame(header, ciphertext, mac) {
      const message = pb.encode(pb.twomemo.OMEMOMessage, {
        n: header.n,
        pn: header.pn,
        dhPub: keys.encodePublicKey("twomemo", header.dhPublicKey),
        ciphertext,
      });
      return pb.encode(pb.twomemo.OMEMOAuthenticatedMessage, { mac: mac(message), message });
    },
    parse(bytes) {
      const authenticated = pb.decode(pb.twomemo.OMEMOAuthenticatedMessage, bytes);
      const message = pb.decode(pb.twomemo.OMEMOMessage, authenticated.message);
      return {
        header: { dhPublicKey: keys.decodePublicKey("twomemo", message.dhPub), n: message.n, pn: message.pn },
        ciphertext: message.ciphertext,
        macInput: authenticated.message,
        mac: authenticated.mac,
      };
    },
  }),
});

/**
 * @typedef {object} RatchetState
 * @property {"oldmemo"|"twomemo"} namespace
 * @property {"initiator"|"responder"} role - our side of the X3DH handshake.
 * @property {Uint8Array} associatedData - from X3DH: initiator IK || responder IK.
 * @property {Uint8Array} rootKey
 * @property {{ privateKey: Uint8Array, publicKey: Uint8Array }} dhSelf
 * @property {Uint8Array|null} dhRemote
 * @property {Uint8Array|null} chainKeySend
 * @property {Uint8Array|null} chainKeyRecv
 * @property {number} nSend
 * @property {number} nRecv
 * @property {number} prevChainLength - messages sent in our previous chain.
 * @property {Map<string, Uint8Array>} skippedMessageKeys - keyed by
 *   `${hex(dhPublicKey)}:${n}`.
 *
 * @typedef {object} Handshake - from x3dh.initiateHandshake / respondToHandshake.
 * @property {Uint8Array} sharedSecret
 * @property {Uint8Array} associatedData
 */

/**
 * The initiator's session, right after x3dh.initiateHandshake.
 *
 * @param {"oldmemo"|"twomemo"} namespace
 * @param {Handshake} handshake
 * @param {Uint8Array} theirSignedPreKey - 32-byte X25519 key from the bundle,
 *   their first ratchet public key.
 * @param {object} [options]
 * @param {(n: number) => Uint8Array} [options.random] - one 32-byte draw,
 *   our first ratchet private key.
 * @returns {RatchetState}
 */
export function initSender(namespace, handshake, theirSignedPreKey, { random = randomBytes } = {}) {
  const profile = profileOf(namespace);
  const dhSelf = generateDhKeyPair(random);
  const { rootKey, chainKey } = kdfRoot(profile, handshake.sharedSecret, dh(dhSelf.privateKey, theirSignedPreKey));
  return {
    namespace,
    role: "initiator",
    associatedData: Uint8Array.from(handshake.associatedData),
    rootKey,
    dhSelf,
    dhRemote: Uint8Array.from(theirSignedPreKey),
    chainKeySend: chainKey,
    chainKeyRecv: null,
    nSend: 0,
    nRecv: 0,
    prevChainLength: 0,
    skippedMessageKeys: new Map(),
  };
}

/**
 * The responder's session, right after x3dh.respondToHandshake. Decrypt the
 * key exchange's message with it before sending anything.
 *
 * @param {"oldmemo"|"twomemo"} namespace
 * @param {Handshake} handshake
 * @param {{ privateKey: Uint8Array, publicKey: Uint8Array }} ourSignedPreKey
 *   - the pair the key exchange names, our first ratchet key.
 * @returns {RatchetState}
 */
export function initReceiver(namespace, handshake, ourSignedPreKey) {
  profileOf(namespace);
  return {
    namespace,
    role: "responder",
    associatedData: Uint8Array.from(handshake.associatedData),
    rootKey: Uint8Array.from(handshake.sharedSecret),
    dhSelf: { privateKey: Uint8Array.from(ourSignedPreKey.privateKey), publicKey: Uint8Array.from(ourSignedPreKey.publicKey) },
    dhRemote: null,
    chainKeySend: null,
    chainKeyRecv: null,
    nSend: 0,
    nRecv: 0,
    prevChainLength: 0,
    skippedMessageKeys: new Map(),
  };
}

/**
 * Encrypts one message and advances the sending chain.
 *
 * @param {RatchetState} state - mutated in place.
 * @param {Uint8Array} plaintext - for OMEMO, the payload key material
 *   (task 2.8), not the chat text.
 * @returns {Uint8Array} the framed message: what goes in a <key> element,
 *   or inside a key exchange (x3dh.encodeKeyExchange).
 * @throws if we're the responder and haven't received a message yet.
 */
export function encrypt(state, plaintext) {
  const profile = profileOf(state.namespace);
  if (!state.chainKeySend) {
    throw new Error("No sending chain yet: the responder must decrypt the initiator's first message before sending.");
  }
  const { chainKey, messageKey } = kdfChain(state.chainKeySend);
  const header = { dhPublicKey: state.dhSelf.publicKey, n: state.nSend, pn: profile.wirePn(state.prevChainLength) };
  const { aesKey, macKey, iv } = expandMessageKey(profile, messageKey);
  const ciphertext = cbc(aesKey, iv).encrypt(plaintext);
  const ad = associatedDataFor(state, profile, "send");
  const framed = profile.frame(header, ciphertext, (data) => computeMac(profile, macKey, ad, data));

  state.chainKeySend = chainKey;
  state.nSend += 1;
  return framed;
}

/**
 * Decrypts one framed message, doing a DH ratchet step if it carries a new
 * ratchet key and using or storing skipped message keys for out-of-order
 * delivery. The state changes only if the message authenticates.
 *
 * @param {RatchetState} state - updated in place on success.
 * @param {Uint8Array} framed - as produced by encrypt().
 * @param {object} [options]
 * @param {(n: number) => Uint8Array} [options.random] - a 32-byte draw for
 *   our next ratchet key, taken only when the message starts a new chain.
 * @returns {Uint8Array} plaintext
 * @throws on malformed input, a failed MAC, bad padding, a replayed or
 *   too-old message, or too many skipped messages. The state is unchanged.
 */
export function decrypt(state, framed, { random = randomBytes } = {}) {
  const profile = profileOf(state.namespace);
  const { header, ciphertext, macInput, mac } = profile.parse(framed);
  if (!ciphertext) {
    throw new Error("Message has no ciphertext.");
  }
  if (mac.length !== profile.macLength) {
    throw new Error(`MAC must be ${profile.macLength} bytes.`);
  }

  const work = { ...state, skippedMessageKeys: new Map(state.skippedMessageKeys) };
  const messageKey = messageKeyFor(work, profile, header, random);

  const { aesKey, macKey, iv } = expandMessageKey(profile, messageKey);
  const ad = associatedDataFor(work, profile, "receive");
  if (!constantTimeEqual(computeMac(profile, macKey, ad, macInput), mac)) {
    throw new Error("Message authentication failed.");
  }
  const plaintext = cbc(aesKey, iv).decrypt(ciphertext);

  Object.assign(state, work);
  return plaintext;
}

// --- persistence ---

/**
 * @typedef {object} SerializedState - plain JSON: byte strings are base64,
 *   skipped keys are [ratchet public key, n, message key] triples, oldest
 *   first.
 * @property {number} version - STATE_VERSION.
 */

/**
 * A session as plain JSON data, for the key store (docs/TASKS.md 3.2).
 * It holds private keys, so store it like the identity key.
 *
 * @param {RatchetState} state
 * @returns {SerializedState}
 */
export function serializeState(state) {
  const b64 = (bytes) => (bytes ? bytesToBase64(bytes) : null);
  return {
    version: STATE_VERSION,
    namespace: state.namespace,
    role: state.role,
    associatedData: b64(state.associatedData),
    rootKey: b64(state.rootKey),
    dhSelf: { privateKey: b64(state.dhSelf.privateKey), publicKey: b64(state.dhSelf.publicKey) },
    dhRemote: b64(state.dhRemote),
    chainKeySend: b64(state.chainKeySend),
    chainKeyRecv: b64(state.chainKeyRecv),
    nSend: state.nSend,
    nRecv: state.nRecv,
    prevChainLength: state.prevChainLength,
    skippedMessageKeys: [...state.skippedMessageKeys].map(([id, key]) => {
      const [hex, n] = id.split(":");
      return [bytesToBase64(hexToBytes(hex)), Number(n), bytesToBase64(key)];
    }),
  };
}

/**
 * Inverse of serializeState. The input comes from disk, so it is checked
 * strictly: a corrupted session fails loudly here rather than producing
 * wrong keys later.
 *
 * @param {SerializedState} data - e.g. JSON.parse of the stored text.
 * @returns {RatchetState}
 * @throws on an unknown version or any malformed or inconsistent field.
 */
export function deserializeState(data) {
  const fail = (what) => {
    throw new Error(`Stored session is invalid: ${what}.`);
  };
  if (!data || typeof data !== "object") {
    fail("not an object");
  }
  if (data.version !== STATE_VERSION) {
    fail(`unsupported version ${data.version}`);
  }
  if (!keys.NAMESPACES.includes(data.namespace)) {
    fail("unknown namespace");
  }
  if (data.role !== "initiator" && data.role !== "responder") {
    fail("unknown role");
  }
  const bytes = (value, length, what, { nullable = false } = {}) => {
    if (value === null && nullable) {
      return null;
    }
    const out = typeof value === "string" ? base64ToBytes(value) : null;
    if (!out || out.length !== length) {
      fail(`${what} must be ${length} bytes of base64`);
    }
    return out;
  };
  const counter = (value, what) => {
    if (!Number.isSafeInteger(value) || value < 0) {
      fail(`${what} must be a non-negative integer`);
    }
    return value;
  };

  // Identity keys in AD: 33 bytes each in oldmemo, 32 in twomemo.
  const adLength = data.namespace === "oldmemo" ? 66 : 64;
  const dhSelf = {
    privateKey: bytes(data.dhSelf?.privateKey, 32, "dhSelf.privateKey"),
    publicKey: bytes(data.dhSelf?.publicKey, 32, "dhSelf.publicKey"),
  };
  if (!bytesEqual(x25519.getPublicKey(dhSelf.privateKey), dhSelf.publicKey)) {
    fail("dhSelf's public key doesn't match its private key");
  }
  const state = {
    namespace: data.namespace,
    role: data.role,
    associatedData: bytes(data.associatedData, adLength, "associatedData"),
    rootKey: bytes(data.rootKey, 32, "rootKey"),
    dhSelf,
    dhRemote: bytes(data.dhRemote, 32, "dhRemote", { nullable: true }),
    chainKeySend: bytes(data.chainKeySend, 32, "chainKeySend", { nullable: true }),
    chainKeyRecv: bytes(data.chainKeyRecv, 32, "chainKeyRecv", { nullable: true }),
    nSend: counter(data.nSend, "nSend"),
    nRecv: counter(data.nRecv, "nRecv"),
    prevChainLength: counter(data.prevChainLength, "prevChainLength"),
    skippedMessageKeys: new Map(),
  };
  // A sending chain exists exactly when the peer's ratchet key is known,
  // and a receiving chain only after that.
  if ((state.dhRemote === null) !== (state.chainKeySend === null)) {
    fail("dhRemote and chainKeySend must both be set or both be null");
  }
  if (state.chainKeyRecv && !state.dhRemote) {
    fail("a receiving chain needs dhRemote");
  }
  if (state.role === "initiator" && !state.dhRemote) {
    fail("an initiator always knows the peer's ratchet key");
  }

  if (!Array.isArray(data.skippedMessageKeys) || data.skippedMessageKeys.length > MAX_SKIPPED_TOTAL) {
    fail(`skippedMessageKeys must be an array of at most ${MAX_SKIPPED_TOTAL} entries`);
  }
  for (const entry of data.skippedMessageKeys) {
    if (!Array.isArray(entry) || entry.length !== 3) {
      fail("each skipped key must be [ratchet key, n, message key]");
    }
    const id = skippedKeyId(bytes(entry[0], 32, "a skipped key's ratchet key"), counter(entry[1], "a skipped key's n"));
    if (state.skippedMessageKeys.has(id)) {
      fail("duplicate skipped key");
    }
    state.skippedMessageKeys.set(id, bytes(entry[2], 32, "a skipped message key"));
  }
  return state;
}

// --- internals ---

function messageKeyFor(state, profile, header, random) {
  const id = skippedKeyId(header.dhPublicKey, header.n);
  const skipped = state.skippedMessageKeys.get(id);
  if (skipped) {
    state.skippedMessageKeys.delete(id);
    return skipped;
  }

  if (!state.dhRemote || !bytesEqual(header.dhPublicKey, state.dhRemote)) {
    skipMessageKeys(state, profile.skipUntil(header.pn));
    dhRatchetStep(state, profile, header.dhPublicKey, random);
  }
  if (!state.chainKeyRecv) {
    // Only the initiator gets here, before any reply, for a message claiming
    // the responder's signed prekey as its ratchet key. libsignal would have
    // a chain for that; OMEMO responders never send on it.
    throw new Error("Message uses a ratchet key we have no receiving chain for.");
  }
  if (header.n < state.nRecv) {
    throw new Error("Duplicate or too-old message: its key is already used or gone.");
  }
  skipMessageKeys(state, header.n);

  const { chainKey, messageKey } = kdfChain(state.chainKeyRecv);
  state.chainKeyRecv = chainKey;
  state.nRecv += 1;
  return messageKey;
}

function dhRatchetStep(state, profile, theirPublicKey, random) {
  state.prevChainLength = state.nSend;
  state.nSend = 0;
  state.nRecv = 0;
  state.dhRemote = Uint8Array.from(theirPublicKey);

  const recv = kdfRoot(profile, state.rootKey, dh(state.dhSelf.privateKey, state.dhRemote));
  state.chainKeyRecv = recv.chainKey;

  state.dhSelf = generateDhKeyPair(random);
  const send = kdfRoot(profile, recv.rootKey, dh(state.dhSelf.privateKey, state.dhRemote));
  state.rootKey = send.rootKey;
  state.chainKeySend = send.chainKey;
}

function skipMessageKeys(state, until) {
  if (!state.chainKeyRecv) {
    return;
  }
  if (until - state.nRecv > MAX_SKIP) {
    throw new Error("Too many skipped messages; refusing (possible attack or desync).");
  }
  while (state.nRecv < until) {
    const { chainKey, messageKey } = kdfChain(state.chainKeyRecv);
    state.chainKeyRecv = chainKey;
    state.skippedMessageKeys.set(skippedKeyId(state.dhRemote, state.nRecv), messageKey);
    state.nRecv += 1;
    if (state.skippedMessageKeys.size > MAX_SKIPPED_TOTAL) {
      // A Map iterates in insertion order, so the first key is the oldest.
      state.skippedMessageKeys.delete(state.skippedMessageKeys.keys().next().value);
    }
  }
}

function associatedDataFor(state, profile, direction) {
  const ad = state.associatedData;
  if (!profile.senderFirstAd) {
    return ad;
  }
  // AD from X3DH is initiator || responder. With the sender first, it
  // stays as is when the initiator sends or the responder receives, and
  // swaps halves otherwise.
  const weAreSender = direction === "send";
  const initiatorSends = weAreSender === (state.role === "initiator");
  if (initiatorSends) {
    return ad;
  }
  const half = ad.length / 2;
  return concatBytes(ad.subarray(half), ad.subarray(0, half));
}

function kdfRoot(profile, rootKey, dhOutput) {
  const out = hkdf(sha256, dhOutput, rootKey, profile.rootInfo, 64);
  return { rootKey: out.slice(0, 32), chainKey: out.slice(32, 64) };
}

function kdfChain(chainKey) {
  return {
    messageKey: hmac(sha256, chainKey, Uint8Array.of(0x01)),
    chainKey: hmac(sha256, chainKey, Uint8Array.of(0x02)),
  };
}

function expandMessageKey(profile, messageKey) {
  const out = hkdf(sha256, messageKey, ZERO_SALT, profile.messageKeyInfo, 80);
  return { aesKey: out.slice(0, 32), macKey: out.slice(32, 64), iv: out.slice(64, 80) };
}

function computeMac(profile, macKey, associatedData, data) {
  return hmac(sha256, macKey, concatBytes(associatedData, data)).slice(0, profile.macLength);
}

// x25519 clamps the scalar itself, so the raw draw is stored as is.
function generateDhKeyPair(random) {
  const privateKey = Uint8Array.from(random(32));
  if (privateKey.length !== 32) {
    throw new Error("A ratchet private key must be 32 bytes.");
  }
  return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}

// noble throws on a low-order public key (all-zero output).
function dh(privateKey, publicKey) {
  return x25519.getSharedSecret(privateKey, publicKey);
}

function profileOf(namespace) {
  const profile = PROFILES[namespace];
  if (!keys.NAMESPACES.includes(namespace) || !profile) {
    throw new Error(`Unknown OMEMO namespace "${namespace}"; expected "oldmemo" or "twomemo".`);
  }
  return profile;
}

function skippedKeyId(dhPublicKey, n) {
  let hex = "";
  for (const b of dhPublicKey) {
    hex += b.toString(16).padStart(2, "0");
  }
  return `${hex}:${n}`;
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}

// btoa/atob exist in Node and in Gecko's module scopes.
function bytesToBase64(bytes) {
  let s = "";
  for (const b of bytes) {
    s += String.fromCharCode(b);
  }
  return btoa(s);
}

/** Strict base64 decode; returns null for anything not canonical base64. */
function base64ToBytes(text) {
  if (text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) {
    return null;
  }
  const s = atob(text);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    out[i] = s.charCodeAt(i);
  }
  return bytesToBase64(out) === text ? out : null;
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

function bytesEqual(a, b) {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
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
