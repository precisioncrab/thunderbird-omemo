/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * The OMEMO message layer: encrypting one chat message for a set of
 * devices, and decrypting what arrives for ours (the crypto side of
 * docs/TASKS.md 4.3, 4.7, 4.9 and 4.10). It works on a key store
 * (store.js) and xml/formats.js structures; sending stanzas, queueing and
 * UI belong to the Experiment.
 *
 * Sending: the body is encrypted once (payload.js; for twomemo inside an
 * XEP-0420 envelope), and its key material once per device with that
 * device's session. A device without a session gets one from its bundle
 * (X3DH with a random pre key), and until the peer replies our messages to
 * it carry the key exchange.
 *
 * Receiving: a key exchange starts a session, or, if it repeats the one
 * that started the current session, reuses it. Any message from the peer on
 * a session we started confirms it, so we stop sending the key exchange.
 * After starting a session from a key exchange the result asks for an
 * empty message back, which confirms it on the peer's side (4.10).
 *
 * Trust (milestone 5) isn't decided here: results carry the peer's
 * identity key for the caller to check.
 */

import * as keys from "../crypto/keys.js";
import * as x3dh from "../crypto/x3dh.js";
import * as doubleRatchet from "../crypto/double-ratchet.js";
import * as payload from "../crypto/payload.js";
import * as envelope from "../crypto/envelope.js";
import { randomBytes } from "../crypto/random.js";
import { bareJid } from "./store.js";
import { findOurKey } from "./formats.js";

/** A failure the caller shows to the user (docs/TASKS.md 4.9); `code` says which. */
export class OmemoError extends Error {
  /**
   * @param {"not-for-this-device"|"no-session"|"unknown-signed-prekey"|"unknown-pre-key"|"decryption-failed"|"bad-payload"|"sender-mismatch"} code
   * @param {string} message
   * @param {unknown} [cause]
   */
  constructor(code, message, cause) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "OmemoError";
    this.code = code;
  }
}

/**
 * @typedef {object} Recipient
 * @property {string} jid - the contact's (or our own) JID.
 * @property {number} deviceId
 * @property {ReturnType<import("./formats.js").parseBundle>} [bundle] -
 *   needed only for a device we have no session with yet.
 */

/**
 * Encrypts one message for the given devices.
 *
 * @param {import("./store.js").OmemoStore} store
 * @param {"oldmemo"|"twomemo"} ns
 * @param {object} message
 * @param {string} message.ourJid
 * @param {string|null} message.body - null sends an empty OMEMO message.
 * @param {Recipient[]} message.recipients
 * @param {object} [options]
 * @param {(n: number) => Uint8Array} [options.random]
 * @returns {{ encrypted: import("./formats.js").Encrypted,
 *   skipped: { jid: string, deviceId: number, reason: string }[] }}
 *   encrypted goes to formats.buildEncrypted. skipped lists devices we
 *   couldn't encrypt for (no or bad bundle); the caller decides whether
 *   the message may go out without them. Our own device is always left out.
 */
export function encryptMessage(store, ns, { ourJid, body, recipients }, { random = randomBytes } = {}) {
  assertNamespace(ns);
  const us = bareJid(ourJid);
  let keyMaterial;
  let sealed = null;
  if (body === null) {
    keyMaterial = payload.emptyKeyMaterial(ns, { random });
  } else {
    const plaintext = ns === "twomemo"
      ? envelope.buildEnvelope({ body, from: us }, { random })
      : new TextEncoder().encode(body);
    sealed = payload.encrypt(ns, plaintext, { random });
    keyMaterial = sealed.keyMaterial;
  }

  const entries = [];
  const skipped = [];
  for (const { jid, deviceId, bundle } of recipients) {
    const peer = bareJid(jid);
    if (peer === us && deviceId === store.deviceId) {
      continue;
    }
    try {
      let session = store.session(ns, peer, deviceId);
      if (!session) {
        if (!bundle) {
          throw new Error("no session and no bundle");
        }
        session = startSession(store, ns, bundle, random);
      }
      let data = doubleRatchet.encrypt(session.state, keyMaterial);
      const kex = session.pendingKeyExchange;
      if (kex) {
        data = x3dh.encodeKeyExchange(ns, { ...kex, identityKey: store.identityKeyPair().publicKey, message: data });
      }
      store.setSession(ns, peer, deviceId, session);
      entries.push({ jid: ns === "twomemo" ? peer : null, rid: deviceId, kex: Boolean(kex), data });
    } catch (e) {
      skipped.push({ jid: peer, deviceId, reason: e?.message ?? String(e) });
    }
  }
  return {
    encrypted: { namespace: ns, sid: store.deviceId, keys: entries, iv: sealed?.iv ?? null, payload: sealed?.ciphertext ?? null },
    skipped,
  };
}

/**
 * @typedef {object} Decrypted
 * @property {string|null} body - null for an empty OMEMO message.
 * @property {Uint8Array} peerIdentityKey - the sender device's identity key
 *   (namespace wire form), for trust checks.
 * @property {boolean} sessionStarted - this message started a new session:
 *   send the device an empty message back (encryptMessage with body null)
 *   so it stops sending the key exchange.
 * @property {number|null} preKeyUsed - a one-time pre key this used up; it
 *   is already removed and the store refilled, so republish the bundle.
 */

/**
 * Decrypts a message for our device. The store changes only on success.
 *
 * @param {import("./store.js").OmemoStore} store
 * @param {import("./formats.js").Encrypted} message - from formats.parseEncrypted.
 * @param {object} context
 * @param {string} context.ourJid
 * @param {string} context.sender - the stanza's from (full or bare JID).
 * @param {object} [options]
 * @param {(n: number) => Uint8Array} [options.random]
 * @returns {Decrypted}
 * @throws {OmemoError}
 */
export function decryptMessage(store, message, { ourJid, sender }, { random = randomBytes } = {}) {
  const ns = message.namespace;
  assertNamespace(ns);
  const key = findOurKey(message, { jid: ourJid, deviceId: store.deviceId });
  if (!key) {
    throw new OmemoError("not-for-this-device", "The message wasn't encrypted for this device.");
  }
  const peer = bareJid(sender);
  const deviceId = message.sid;
  const existing = store.session(ns, peer, deviceId);

  let session;
  let framed;
  let sessionStarted = false;
  let preKeyUsed = null;
  if (key.kex) {
    let kex;
    try {
      kex = x3dh.decodeKeyExchange(ns, key.data);
    } catch (e) {
      throw new OmemoError("decryption-failed", "The key exchange is malformed.", e);
    }
    framed = kex.message;
    if (existing?.peerBaseKey && equalBytes(existing.peerBaseKey, kex.ephemeralKey)) {
      session = copySession(existing);
    } else {
      const spk = store.signedPreKey(ns, kex.signedPreKeyId);
      if (!spk) {
        throw new OmemoError("unknown-signed-prekey", `The key exchange names signed prekey ${kex.signedPreKeyId}, which we don't have.`);
      }
      const pk = store.preKey(ns, kex.preKeyId);
      if (!pk) {
        throw new OmemoError("unknown-pre-key", `The key exchange names pre key ${kex.preKeyId}, which is used up or unknown.`);
      }
      let handshake;
      try {
        handshake = x3dh.respondToHandshake(ns, { identity: store.identityKeyPair(), signedPreKey: spk, preKey: pk },
          { identityKey: kex.identityKey, ephemeralKey: kex.ephemeralKey });
      } catch (e) {
        throw new OmemoError("decryption-failed", "The key exchange's keys are invalid.", e);
      }
      session = {
        state: doubleRatchet.initReceiver(ns, handshake, spk),
        peerIdentityKey: keys.encodeIdentityKey(ns, kex.identityKey),
        pendingKeyExchange: null,
        peerBaseKey: kex.ephemeralKey,
      };
      sessionStarted = true;
      preKeyUsed = kex.preKeyId;
    }
  } else {
    if (!existing) {
      throw new OmemoError("no-session", "There's no session with the sending device; it needs to start one.");
    }
    session = copySession(existing);
    framed = key.data;
  }

  let keyMaterial;
  try {
    keyMaterial = doubleRatchet.decrypt(session.state, framed, { random });
  } catch (e) {
    throw new OmemoError("decryption-failed", "The message couldn't be decrypted (tampered, replayed or out of sync).", e);
  }
  // Any message from the peer confirms a session we started.
  session.pendingKeyExchange = null;

  // Commit before opening the payload: the ratchet has moved on either way.
  store.setSession(ns, peer, deviceId, session);
  if (preKeyUsed !== null) {
    store.removePreKey(ns, preKeyUsed);
    store.refillPreKeys(ns);
  }

  const result = { body: null, peerIdentityKey: session.peerIdentityKey, sessionStarted, preKeyUsed };
  if (message.payload === null) {
    return result;
  }
  let plaintext;
  try {
    plaintext = payload.decrypt(ns, { keyMaterial, ciphertext: message.payload, iv: message.iv ?? undefined });
  } catch (e) {
    throw new OmemoError("bad-payload", "The message body couldn't be decrypted.", e);
  }
  if (ns === "twomemo") {
    let opened;
    try {
      opened = envelope.parseEnvelope(plaintext, { sender });
    } catch (e) {
      const code = /does not match the sender/.test(e?.message) ? "sender-mismatch" : "bad-payload";
      throw new OmemoError(code, code === "sender-mismatch"
        ? "The encrypted message claims a different sender."
        : "The encrypted message's envelope is malformed.", e);
    }
    result.body = opened.body;
  } else {
    try {
      result.body = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
    } catch (e) {
      throw new OmemoError("bad-payload", "The message body isn't valid UTF-8.", e);
    }
  }
  return result;
}

// --- internals ---

/** A new session with a device from its bundle: X3DH with a random pre key. */
function startSession(store, ns, bundle, random) {
  if (!bundle.preKeys.length) {
    throw new Error("the bundle has no pre keys");
  }
  const b = random(4);
  const index = (((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0) % bundle.preKeys.length;
  const preKey = bundle.preKeys[index];
  const hs = x3dh.initiateHandshake(ns, store.identityKeyPair(), { ...bundle, preKey }, { random });
  return {
    state: doubleRatchet.initSender(ns, hs, bundle.signedPreKey.publicKey, { random }),
    peerIdentityKey: keys.encodeIdentityKey(ns, bundle.identityKey),
    pendingKeyExchange: { preKeyId: hs.preKeyId, signedPreKeyId: hs.signedPreKeyId, ephemeralKey: hs.ephemeralPublicKey },
    peerBaseKey: null,
  };
}

// decrypt() leaves the state alone on failure, but we also change other
// fields, so work on a shallow copy and let setSession commit it.
function copySession(record) {
  return { ...record, state: { ...record.state, skippedMessageKeys: new Map(record.state.skippedMessageKeys) } };
}

function equalBytes(a, b) {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

function assertNamespace(ns) {
  if (!keys.NAMESPACES.includes(ns)) {
    throw new Error(`Unknown OMEMO namespace "${ns}"; expected "oldmemo" or "twomemo".`);
  }
}
