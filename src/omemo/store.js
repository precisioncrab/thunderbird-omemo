/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * One account's OMEMO key store (docs/TASKS.md 3.2, 3.3): our device id,
 * identity key, per-namespace signed prekey and one-time pre keys, the
 * Double Ratchet sessions with peers' devices, and the devices we know of.
 *
 * It lives in memory while the account is connected, so the synchronous
 * receive hook can decrypt without waiting on disk. Every change calls
 * `onChange`, which the caller wires to a batched background write
 * (persist.js). toJSON/fromJSON give the on-disk form: plain JSON, byte
 * strings in base64, private keys unencrypted, as other desktop OMEMO
 * clients store them (see the README).
 *
 * createStore is the first-connect setup: a random device id that isn't
 * already in our published device list, one identity key for both
 * namespaces, and per namespace a signed prekey and PRE_KEY_TARGET pre
 * keys, each namespace with its own id counters (as python-omemo keeps them).
 */

import { x25519 } from "@noble/curves/ed25519";
import * as keys from "../crypto/keys.js";
import * as doubleRatchet from "../crypto/double-ratchet.js";
import { randomBytes } from "../crypto/random.js";

export const STORE_VERSION = 1;

/** How many one-time pre keys each namespace's bundle offers. */
export const PRE_KEY_TARGET = 100;

/** Device ids are 1..2^31-1 (XEP-0384). */
export const MAX_DEVICE_ID = 0x7fffffff;

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * A signed prekey older than this is replaced (milestone 6). The X3DH spec
 * (signal.org/docs/specifications/x3dh, section 3.2) has it replaced "at some
 * interval (e.g. once a week, or once a month)". Only new sessions use it;
 * the identity key, and so every fingerprint and verification, never changes.
 */
export const SIGNED_PRE_KEY_ROTATE_MS = 7 * DAY_MS;

/**
 * How long a replaced signed prekey still answers key exchanges: a peer may
 * have fetched our bundle before the rotation and write only later.
 */
export const SIGNED_PRE_KEY_KEEP_MS = 30 * DAY_MS;

/**
 * Trust in an identity key (milestone 5), as Conversations models it:
 * "blind" accepted automatically, "trusted" approved by the user, "verified"
 * fingerprint compared, "undecided" held back until the user decides,
 * "distrusted" never encrypted to.
 */
export const TRUST_STATES = Object.freeze(["blind", "trusted", "verified", "undecided", "distrusted"]);

// fingerprint.js's form: 8 groups of 8 hex digits.
const FINGERPRINT = /^([0-9a-f]{8} ){7}[0-9a-f]{8}$/;

/**
 * @typedef {object} SessionRecord
 * @property {import("../crypto/double-ratchet.js").RatchetState} state -
 *   live; encrypt/decrypt mutate it, so call setSession afterwards.
 * @property {Uint8Array} peerIdentityKey - the peer's identity key in the
 *   namespace's wire form, for trust decisions (milestone 5).
 * @property {{ preKeyId: number, signedPreKeyId: number, ephemeralKey: Uint8Array }|null} pendingKeyExchange
 *   - for sessions we started: what to wrap our messages in until the peer
 *   replies (x3dh.encodeKeyExchange), then null.
 * @property {Uint8Array|null} peerBaseKey - for sessions the peer started:
 *   the ephemeral key of their key exchange, so a repeat of it (they send it
 *   until we reply) reuses this session instead of starting a new one.
 *
 * @typedef {object} Device
 * @property {number} id
 * @property {string|null} label - twomemo devices may have one.
 * @property {number} lastSeen - ms since the epoch we last saw it listed.
 * @property {number} firstSeen - when it first appeared on the list (for
 *   stores from before 0.0.15: when that version first loaded it).
 */

/**
 * First-connect setup: a new store with fresh keys.
 *
 * @param {object} [options]
 * @param {Iterable<number>} [options.avoidDeviceIds] - ids already in our
 *   device lists, which the new id must not collide with.
 * @param {(n: number) => Uint8Array} [options.random]
 * @param {() => number} [options.now]
 * @param {() => void} [options.onChange]
 * @returns {OmemoStore}
 */
export function createStore({ avoidDeviceIds = [], random = randomBytes, now = Date.now, onChange } = {}) {
  const avoid = new Set(avoidDeviceIds);
  let deviceId = 0;
  for (let attempt = 0; attempt < 100 && (deviceId === 0 || avoid.has(deviceId)); attempt++) {
    const b = random(4);
    deviceId = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) & MAX_DEVICE_ID;
  }
  if (deviceId === 0 || avoid.has(deviceId)) {
    throw new Error("Couldn't draw an unused device id.");
  }

  const identity = keys.generateIdentityKeyPair({ random });
  const namespaces = {};
  for (const ns of keys.NAMESPACES) {
    const signedPreKey = keys.generateSignedPreKey(identity.privateKey, 1, ns, { random, now });
    const preKeys = keys.generatePreKeys(1, PRE_KEY_TARGET, { random });
    namespaces[ns] = {
      signedPreKey: { id: signedPreKey.id, privateKey: signedPreKey.privateKey, signature: signedPreKey.signature, createdAt: signedPreKey.createdAt },
      oldSignedPreKeys: [],
      preKeys: new Map(preKeys.map((k) => [k.id, k.privateKey])),
      nextPreKeyId: keys.nextKeyId(preKeys.at(-1).id),
      nextSignedPreKeyId: keys.nextKeyId(signedPreKey.id),
    };
  }
  const store = new OmemoStore(
    { deviceId, identityPrivateKey: identity.privateKey, namespaces, sessions: new Map(), devices: new Map(), encryption: new Map(), trust: new Map(), deviceKeys: new Map(), lastMessages: new Map() },
    { random, now, onChange }
  );
  store._changed();
  return store;
}

export class OmemoStore {
  /** Use createStore or OmemoStore.fromJSON. */
  constructor(data, { random = randomBytes, now = Date.now, onChange } = {}) {
    this._data = data;
    this._random = random;
    this._now = now;
    this._onChange = onChange ?? null;
    this._identity = null;
    this._publicKeys = new Map(); // private key (hex) -> public key, cached
  }

  get deviceId() {
    return this._data.deviceId;
  }

  /** @returns {{ privateKey: Uint8Array, publicKey: import("../crypto/keys.js").IdentityPublicKey }} */
  identityKeyPair() {
    this._identity ??= {
      privateKey: this._data.identityPrivateKey,
      publicKey: keys.identityPublicKey(this._data.identityPrivateKey),
    };
    return this._identity;
  }

  /**
   * What we publish for one namespace (docs/TASKS.md 3.8).
   *
   * @param {"oldmemo"|"twomemo"} ns
   * @returns {{ identityKey: import("../crypto/keys.js").IdentityPublicKey,
   *   signedPreKey: { id: number, publicKey: Uint8Array, signature: Uint8Array },
   *   preKeys: { id: number, publicKey: Uint8Array }[] }}
   */
  bundle(ns) {
    const n = this._ns(ns);
    return {
      identityKey: this.identityKeyPair().publicKey,
      signedPreKey: { id: n.signedPreKey.id, publicKey: this._publicKey(n.signedPreKey.privateKey), signature: n.signedPreKey.signature },
      preKeys: [...n.preKeys].map(([id, privateKey]) => ({ id, publicKey: this._publicKey(privateKey) })),
    };
  }

  /**
   * Our signed prekey with this id, as a key exchange names it: the current
   * one, or one replaced less than SIGNED_PRE_KEY_KEEP_MS ago.
   *
   * @returns {{ id: number, privateKey: Uint8Array, publicKey: Uint8Array }|null}
   */
  signedPreKey(ns, id) {
    const n = this._ns(ns);
    const spk = n.signedPreKey.id === id ? n.signedPreKey : n.oldSignedPreKeys.find((k) => k.id === id);
    return spk ? { id, privateKey: spk.privateKey, publicKey: this._publicKey(spk.privateKey) } : null;
  }

  /**
   * Milestone 6: replaces the namespace's signed prekey once it's older
   * than SIGNED_PRE_KEY_ROTATE_MS, keeping the old one for late key
   * exchanges, and forgets replaced ones kept longer than
   * SIGNED_PRE_KEY_KEEP_MS.
   *
   * @returns {boolean} whether a new one was made (republish the bundle).
   */
  rotateSignedPreKeyIfDue(ns) {
    const n = this._ns(ns);
    const now = this._now();
    const kept = n.oldSignedPreKeys.filter((k) => now - k.retiredAt < SIGNED_PRE_KEY_KEEP_MS);
    let changed = kept.length !== n.oldSignedPreKeys.length;
    n.oldSignedPreKeys = kept;
    let rotated = false;
    if (now - n.signedPreKey.createdAt >= SIGNED_PRE_KEY_ROTATE_MS) {
      const fresh = keys.generateSignedPreKey(this._data.identityPrivateKey, n.nextSignedPreKeyId, ns, { random: this._random, now: this._now });
      n.oldSignedPreKeys.push({ ...n.signedPreKey, retiredAt: now });
      n.signedPreKey = { id: fresh.id, privateKey: fresh.privateKey, signature: fresh.signature, createdAt: fresh.createdAt };
      n.nextSignedPreKeyId = keys.nextKeyId(fresh.id);
      changed = rotated = true;
    }
    if (changed) {
      this._changed();
    }
    return rotated;
  }

  /** @returns {{ id: number, privateKey: Uint8Array, publicKey: Uint8Array }|null} */
  preKey(ns, id) {
    const privateKey = this._ns(ns).preKeys.get(id);
    return privateKey ? { id, privateKey, publicKey: this._publicKey(privateKey) } : null;
  }

  /** Deletes a used one-time pre key. @returns {boolean} whether it existed. */
  removePreKey(ns, id) {
    const removed = this._ns(ns).preKeys.delete(id);
    if (removed) {
      this._changed();
    }
    return removed;
  }

  /**
   * Tops the namespace's pre keys back up to PRE_KEY_TARGET with new ids.
   *
   * @returns {number} how many were generated; republish the bundle if > 0.
   */
  refillPreKeys(ns) {
    const n = this._ns(ns);
    const missing = PRE_KEY_TARGET - n.preKeys.size;
    if (missing <= 0) {
      return 0;
    }
    const fresh = keys.generatePreKeys(n.nextPreKeyId, missing, { random: this._random });
    for (const k of fresh) {
      n.preKeys.set(k.id, k.privateKey);
    }
    n.nextPreKeyId = keys.nextKeyId(fresh.at(-1).id);
    this._changed();
    return missing;
  }

  /** @returns {SessionRecord|null} */
  session(ns, jid, deviceId) {
    return this._data.sessions.get(sessionKey(ns, jid, deviceId)) ?? null;
  }

  /** Stores or updates a session; call after every encrypt/decrypt. */
  setSession(ns, jid, deviceId, record) {
    assertNamespace(ns);
    if (record.state.namespace !== ns) {
      throw new Error("The session belongs to a different namespace.");
    }
    this._data.sessions.set(sessionKey(ns, jid, deviceId), {
      state: record.state,
      peerIdentityKey: Uint8Array.from(record.peerIdentityKey),
      pendingKeyExchange: record.pendingKeyExchange ?? null,
      peerBaseKey: record.peerBaseKey ? Uint8Array.from(record.peerBaseKey) : null,
    });
    this._changed();
  }

  deleteSession(ns, jid, deviceId) {
    if (this._data.sessions.delete(sessionKey(ns, jid, deviceId))) {
      this._changed();
    }
  }

  /** @returns {Device[]} a copy of the devices we know for this contact. */
  devices(ns, jid) {
    return (this._data.devices.get(listKey(ns, jid)) ?? []).map((d) => ({ ...d }));
  }

  /**
   * Replaces a contact's (or our own) device list, as last published.
   *
   * @param {{ id: number, label?: string|null }[]} list
   */
  setDevices(ns, jid, list) {
    assertNamespace(ns);
    const seen = this._now();
    const before = this._data.devices.get(listKey(ns, jid)) ?? [];
    const devices = [];
    for (const d of list) {
      assertDeviceId(d.id);
      if (!devices.some((x) => x.id === d.id)) {
        const firstSeen = before.find((x) => x.id === d.id)?.firstSeen ?? seen;
        devices.push({ id: d.id, label: d.label ?? null, lastSeen: seen, firstSeen });
      }
    }
    this._data.devices.set(listKey(ns, jid), devices);
    this._changed();
  }

  /**
   * The user's choice for conversations with this contact (docs/TASKS.md
   * 4.1): "on", "off", or null to follow the add-on's mode.
   *
   * @returns {"on"|"off"|null}
   */
  encryptionChoice(jid) {
    return this._data.encryption.get(bareJid(jid)) ?? null;
  }

  /** @param {"on"|"off"|null} choice */
  setEncryptionChoice(jid, choice) {
    if (choice !== null && choice !== "on" && choice !== "off") {
      throw new Error(`An encryption choice is "on", "off" or null; got ${choice}.`);
    }
    const key = bareJid(jid);
    if (choice === null) {
      this._data.encryption.delete(key);
    } else {
      this._data.encryption.set(key, choice);
    }
    this._changed();
  }

  /** @returns {boolean} whether the choice is "on". */
  encryptionEnabled(jid) {
    return this.encryptionChoice(jid) === "on";
  }

  /** Sets the choice to "on", or back to following the mode. */
  setEncryptionEnabled(jid, enabled) {
    this.setEncryptionChoice(jid, enabled ? "on" : null);
  }

  /**
   * Our trust in a contact's identity key (milestone 5), by its fingerprint
   * (fingerprint.js). null: never seen.
   *
   * @returns {"blind"|"trusted"|"verified"|"undecided"|"distrusted"|null}
   */
  trustOf(jid, fingerprint) {
    return this._data.trust.get(`${bareJid(jid)} ${fingerprint}`) ?? null;
  }

  /** @param {"blind"|"trusted"|"verified"|"undecided"|"distrusted"} state */
  setTrust(jid, fingerprint, state) {
    if (!TRUST_STATES.includes(state)) {
      throw new Error(`Unknown trust state "${state}".`);
    }
    this._data.trust.set(`${bareJid(jid)} ${fingerprint}`, state);
    this._changed();
  }

  /** @returns {boolean} whether any of this contact's keys is verified. */
  hasVerified(jid) {
    const prefix = `${bareJid(jid)} `;
    return [...this._data.trust].some(([key, state]) => key.startsWith(prefix) && state === "verified");
  }

  /** @returns {string|null} the fingerprint we last saw for this device. */
  deviceKey(jid, deviceId) {
    return this._data.deviceKeys.get(`${bareJid(jid)} ${deviceId}`) ?? null;
  }

  setDeviceKey(jid, deviceId, fingerprint) {
    assertDeviceId(deviceId);
    this._data.deviceKeys.set(`${bareJid(jid)} ${deviceId}`, fingerprint);
    this._changed();
  }

  /**
   * When we last decrypted a message from this device (for /omemo status,
   * and to spot old installs that never write any more).
   *
   * @returns {number|null} ms since the epoch; null: none since 0.0.11.
   */
  lastMessageFrom(jid, deviceId) {
    return this._data.lastMessages.get(`${bareJid(jid)} ${deviceId}`) ?? null;
  }

  recordMessageFrom(jid, deviceId) {
    assertDeviceId(deviceId);
    this._data.lastMessages.set(`${bareJid(jid)} ${deviceId}`, this._now());
    this._changed();
  }

  // --- persistence ---

  /** @returns {object} plain JSON data; see fromJSON. */
  toJSON() {
    const b64 = toBase64;
    const namespaces = {};
    for (const [ns, n] of Object.entries(this._data.namespaces)) {
      namespaces[ns] = {
        signedPreKey: {
          id: n.signedPreKey.id,
          privateKey: b64(n.signedPreKey.privateKey),
          signature: b64(n.signedPreKey.signature),
          createdAt: n.signedPreKey.createdAt,
        },
        oldSignedPreKeys: n.oldSignedPreKeys.map((k) => ({
          id: k.id,
          privateKey: b64(k.privateKey),
          signature: b64(k.signature),
          createdAt: k.createdAt,
          retiredAt: k.retiredAt,
        })),
        preKeys: [...n.preKeys].map(([id, privateKey]) => [id, b64(privateKey)]),
        nextPreKeyId: n.nextPreKeyId,
        nextSignedPreKeyId: n.nextSignedPreKeyId,
      };
    }
    return {
      version: STORE_VERSION,
      deviceId: this._data.deviceId,
      identityPrivateKey: b64(this._data.identityPrivateKey),
      namespaces,
      sessions: [...this._data.sessions].map(([key, r]) => {
        const [ns, jid, deviceId] = splitKey(key);
        return {
          namespace: ns,
          jid,
          deviceId: Number(deviceId),
          state: doubleRatchet.serializeState(r.state),
          peerIdentityKey: b64(r.peerIdentityKey),
          pendingKeyExchange: r.pendingKeyExchange && {
            preKeyId: r.pendingKeyExchange.preKeyId,
            signedPreKeyId: r.pendingKeyExchange.signedPreKeyId,
            ephemeralKey: b64(r.pendingKeyExchange.ephemeralKey),
          },
          peerBaseKey: r.peerBaseKey && b64(r.peerBaseKey),
        };
      }),
      devices: [...this._data.devices].map(([key, list]) => {
        const [ns, jid] = splitKey(key);
        return { namespace: ns, jid, devices: list.map((d) => ({ ...d })) };
      }),
      encryption: [...this._data.encryption],
      // The key is "<jid> <fingerprint>", and fingerprints contain spaces.
      trust: [...this._data.trust].map(([key, state]) => [key.slice(0, key.indexOf(" ")), key.slice(key.indexOf(" ") + 1), state]),
      deviceKeys: [...this._data.deviceKeys].map(([key, fp]) => {
        const [jid, id] = splitKey(key);
        return [jid, Number(id), fp];
      }),
      lastMessages: [...this._data.lastMessages].map(([key, time]) => {
        const [jid, id] = splitKey(key);
        return [jid, Number(id), time];
      }),
    };
  }

  /**
   * Loads a stored key store, strictly: a corrupted file fails here, not
   * later as wrong keys.
   *
   * @param {object} data - JSON.parse of the stored text.
   * @param {object} [options] - as for createStore.
   * @returns {OmemoStore}
   * @throws on an unknown version or any malformed field.
   */
  static fromJSON(data, options) {
    const fail = (what) => {
      throw new Error(`Stored key store is invalid: ${what}.`);
    };
    if (!data || typeof data !== "object" || data.version !== STORE_VERSION) {
      fail(`unsupported version ${data?.version}`);
    }
    const bytes = (value, length, what) => {
      const out = typeof value === "string" ? fromBase64(value) : null;
      if (!out || out.length !== length) {
        fail(`${what} must be ${length} bytes of base64`);
      }
      return out;
    };
    const keyId = (value, what) => {
      if (!Number.isInteger(value) || value < 1 || value > keys.MAX_KEY_ID) {
        fail(`${what} must be a key id`);
      }
      return value;
    };
    const jidOf = (value) => {
      if (typeof value !== "string" || !value || value.includes("/") || value !== value.toLowerCase()) {
        fail("a jid must be a lowercase bare JID");
      }
      return value;
    };
    try {
      assertDeviceId(data.deviceId);
    } catch {
      fail("deviceId");
    }
    const loadedAt = (options?.now ?? Date.now)();

    const namespaces = {};
    for (const ns of keys.NAMESPACES) {
      const n = data.namespaces?.[ns];
      if (!n || !Array.isArray(n.preKeys)) {
        fail(`namespace ${ns} is missing`);
      }
      const preKeys = new Map();
      for (const entry of n.preKeys) {
        if (!Array.isArray(entry) || entry.length !== 2) {
          fail(`${ns} pre keys must be [id, private key] pairs`);
        }
        const id = keyId(entry[0], `${ns} pre key id`);
        if (preKeys.has(id)) {
          fail(`${ns} pre key ${id} appears twice`);
        }
        preKeys.set(id, bytes(entry[1], 32, `${ns} pre key ${id}`));
      }
      const spk = n.signedPreKey;
      if (!Number.isSafeInteger(spk?.createdAt)) {
        fail(`${ns} signed prekey createdAt`);
      }
      // Replaced signed prekeys (0.0.15), optional for older stores.
      if (n.oldSignedPreKeys !== undefined && !Array.isArray(n.oldSignedPreKeys)) {
        fail(`${ns} oldSignedPreKeys must be an array`);
      }
      const oldSignedPreKeys = (n.oldSignedPreKeys ?? []).map((k) => {
        if (!Number.isSafeInteger(k?.createdAt) || !Number.isSafeInteger(k.retiredAt)) {
          fail(`${ns} replaced signed prekey times`);
        }
        return {
          id: keyId(k.id, `${ns} replaced signed prekey id`),
          privateKey: bytes(k.privateKey, 32, `${ns} replaced signed prekey`),
          signature: bytes(k.signature, 64, `${ns} replaced signed prekey signature`),
          createdAt: k.createdAt,
          retiredAt: k.retiredAt,
        };
      });
      namespaces[ns] = {
        signedPreKey: {
          id: keyId(spk.id, `${ns} signed prekey id`),
          privateKey: bytes(spk.privateKey, 32, `${ns} signed prekey`),
          signature: bytes(spk.signature, 64, `${ns} signed prekey signature`),
          createdAt: spk.createdAt,
        },
        oldSignedPreKeys,
        preKeys,
        nextPreKeyId: keyId(n.nextPreKeyId, `${ns} nextPreKeyId`),
        nextSignedPreKeyId: keyId(n.nextSignedPreKeyId, `${ns} nextSignedPreKeyId`),
      };
    }

    const sessions = new Map();
    if (!Array.isArray(data.sessions)) {
      fail("sessions must be an array");
    }
    for (const s of data.sessions) {
      assertNamespaceOr(s?.namespace, fail);
      try {
        assertDeviceId(s.deviceId);
      } catch {
        fail("a session's device id");
      }
      const key = sessionKey(s.namespace, jidOf(s.jid), s.deviceId);
      if (sessions.has(key)) {
        fail("duplicate session");
      }
      const state = doubleRatchet.deserializeState(s.state);
      if (state.namespace !== s.namespace) {
        fail("a session's state is from another namespace");
      }
      const ikLength = s.namespace === "oldmemo" ? 33 : 32;
      const kex = s.pendingKeyExchange;
      sessions.set(key, {
        state,
        peerIdentityKey: bytes(s.peerIdentityKey, ikLength, "a peer identity key"),
        pendingKeyExchange: kex === null ? null : {
          preKeyId: keyId(kex?.preKeyId, "a pending key exchange's pre key id"),
          signedPreKeyId: keyId(kex.signedPreKeyId, "a pending key exchange's signed prekey id"),
          ephemeralKey: bytes(kex.ephemeralKey, 32, "a pending key exchange's ephemeral key"),
        },
        peerBaseKey: s.peerBaseKey === null ? null : bytes(s.peerBaseKey, 32, "a peer base key"),
      });
    }

    const devices = new Map();
    if (!Array.isArray(data.devices)) {
      fail("devices must be an array");
    }
    for (const entry of data.devices) {
      assertNamespaceOr(entry?.namespace, fail);
      const key = listKey(entry.namespace, jidOf(entry.jid));
      if (devices.has(key) || !Array.isArray(entry.devices)) {
        fail("device lists must be unique arrays");
      }
      devices.set(key, entry.devices.map((d) => {
        try {
          assertDeviceId(d?.id);
        } catch {
          fail("a device id");
        }
        if ((d.label !== null && typeof d.label !== "string") || !Number.isSafeInteger(d.lastSeen)
            || (d.firstSeen !== undefined && !Number.isSafeInteger(d.firstSeen))) {
          fail("a device's label, lastSeen or firstSeen");
        }
        // firstSeen came with 0.0.15; older entries count from this load.
        return { id: d.id, label: d.label, lastSeen: d.lastSeen, firstSeen: d.firstSeen ?? loadedAt };
      }));
    }

    // Added after the first stores were written, so it may be missing. 0.0.6
    // wrote plain JIDs (meaning "on"); later versions [jid, "on"|"off"] pairs.
    const encryption = new Map();
    if (data.encryption !== undefined) {
      if (!Array.isArray(data.encryption)) {
        fail("encryption must be an array");
      }
      for (const entry of data.encryption) {
        const [jid, choice] = typeof entry === "string" ? [entry, "on"] : Array.isArray(entry) ? entry : [];
        if (choice !== "on" && choice !== "off") {
          fail("an encryption choice must be [jid, \"on\" or \"off\"]");
        }
        encryption.set(jidOf(jid), choice);
      }
    }

    // Trust (milestone 5), also optional for older stores.
    const trust = new Map();
    for (const entry of data.trust ?? []) {
      if (!Array.isArray(entry) || entry.length !== 3 || !FINGERPRINT.test(entry[1]) || !TRUST_STATES.includes(entry[2])) {
        fail("a trust entry must be [jid, fingerprint, state]");
      }
      trust.set(`${jidOf(entry[0])} ${entry[1]}`, entry[2]);
    }
    const deviceKeys = new Map();
    for (const entry of data.deviceKeys ?? []) {
      if (!Array.isArray(entry) || entry.length !== 3 || !FINGERPRINT.test(entry[2])) {
        fail("a device key entry must be [jid, device id, fingerprint]");
      }
      try {
        assertDeviceId(entry[1]);
      } catch {
        fail("a device key's device id");
      }
      deviceKeys.set(`${jidOf(entry[0])} ${entry[1]}`, entry[2]);
    }
    // Added in 0.0.11, so optional too.
    const lastMessages = new Map();
    for (const entry of data.lastMessages ?? []) {
      if (!Array.isArray(entry) || entry.length !== 3 || !Number.isSafeInteger(entry[2])) {
        fail("a last-message entry must be [jid, device id, time]");
      }
      try {
        assertDeviceId(entry[1]);
      } catch {
        fail("a last-message entry's device id");
      }
      lastMessages.set(`${jidOf(entry[0])} ${entry[1]}`, entry[2]);
    }

    return new OmemoStore(
      { deviceId: data.deviceId, identityPrivateKey: bytes(data.identityPrivateKey, 32, "identityPrivateKey"), namespaces, sessions, devices, encryption, trust, deviceKeys, lastMessages },
      options
    );
  }

  // --- internals ---

  _ns(ns) {
    assertNamespace(ns);
    return this._data.namespaces[ns];
  }

  _publicKey(privateKey) {
    const id = toBase64(privateKey);
    let pub = this._publicKeys.get(id);
    if (!pub) {
      pub = x25519.getPublicKey(privateKey);
      this._publicKeys.set(id, pub);
    }
    return pub;
  }

  _changed() {
    this._onChange?.();
  }
}

// --- helpers ---

/** The lowercase bare form of a JID. */
export function bareJid(jid) {
  if (typeof jid !== "string" || !jid) {
    throw new Error("A JID must be a non-empty string.");
  }
  const slash = jid.indexOf("/");
  return (slash < 0 ? jid : jid.slice(0, slash)).toLowerCase();
}

// Keys join fields with a space, which a bare JID can't contain.
function sessionKey(ns, jid, deviceId) {
  assertNamespace(ns);
  assertDeviceId(deviceId);
  return `${ns} ${bareJid(jid)} ${deviceId}`;
}

function listKey(ns, jid) {
  assertNamespace(ns);
  return `${ns} ${bareJid(jid)}`;
}

function splitKey(key) {
  return key.split(" ");
}

function assertNamespace(ns) {
  if (!keys.NAMESPACES.includes(ns)) {
    throw new Error(`Unknown OMEMO namespace "${ns}"; expected "oldmemo" or "twomemo".`);
  }
}

function assertNamespaceOr(ns, fail) {
  if (!keys.NAMESPACES.includes(ns)) {
    fail(`unknown namespace ${ns}`);
  }
}

function assertDeviceId(id) {
  if (!Number.isInteger(id) || id < 1 || id > MAX_DEVICE_ID) {
    throw new Error(`Device id must be an integer from 1 to ${MAX_DEVICE_ID}; got ${id}.`);
  }
}

function toBase64(bytes) {
  let s = "";
  for (const b of bytes) {
    s += String.fromCharCode(b);
  }
  return btoa(s);
}

function fromBase64(text) {
  if (text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) {
    return null;
  }
  const s = atob(text);
  const out = Uint8Array.from(s, (c) => c.charCodeAt(0));
  return toBase64(out) === text ? out : null;
}
