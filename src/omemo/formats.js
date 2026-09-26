/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * OMEMO's XML formats, per namespace (XEP-0384): device lists and bundles
 * published over PEP (docs/TASKS.md 3.7-3.9), and the <encrypted> element
 * in messages (4.4, 4.6, 4.7). Builders return xml.js elements; parsers
 * take them (from xml.parseXml, or converted from Thunderbird's XMLNode).
 *
 *   oldmemo   device list: node "eu.siacs.conversations.axolotl.devicelist",
 *               item "current", <list><device id/></list>
 *             bundle: node "eu.siacs.conversations.axolotl.bundles:<device id>",
 *               item "current", <bundle> with <signedPreKeyPublic
 *               signedPreKeyId>, <signedPreKeySignature>, <identityKey> and
 *               <prekeys><preKeyPublic preKeyId/></prekeys>; keys carry the
 *               0x05 type byte
 *             message: <encrypted><header sid><key rid prekey?/>...<iv/></header>
 *               <payload/>?</encrypted>
 *   twomemo   device list: node "urn:xmpp:omemo:2:devices", item "current",
 *               <devices><device id label?/></devices>
 *             bundle: node "urn:xmpp:omemo:2:bundles", item = device id,
 *               <bundle> with <spk id>, <spks>, <ik> and <prekeys><pk id/></prekeys>
 *             message: <encrypted><header sid><keys jid><key rid kex?/>...</keys>...
 *               </header><payload/>?</encrypted>
 *
 * Parsing a contact's data is forgiving where it can be (a device list
 * entry or pre key that doesn't parse is skipped) and strict where it
 * must be (a bundle without a valid signed prekey is rejected).
 *
 * twomemo's builders match python-twomemo's XML byte for byte
 * (test/formats.test.js); oldmemo's follow XEP-0384 version 0.3 and get
 * checked against real clients in task 4.12.
 */

import * as keys from "../crypto/keys.js";
import { el, children, onlyChild, textOf } from "./xml.js";

export const NS = Object.freeze({ oldmemo: "eu.siacs.conversations.axolotl", twomemo: "urn:xmpp:omemo:2" });

const MAX_DEVICE_ID = 0x7fffffff;

/** @returns {"oldmemo"|"twomemo"|null} the namespace an element belongs to. */
export function namespaceOf(element) {
  return element?.ns === NS.oldmemo ? "oldmemo" : element?.ns === NS.twomemo ? "twomemo" : null;
}

// --- PEP locations ---

/** @returns {{ node: string, itemId: string }} where the device list lives. */
export function deviceListLocation(ns) {
  assertNamespace(ns);
  return { node: ns === "oldmemo" ? `${NS.oldmemo}.devicelist` : `${NS.twomemo}:devices`, itemId: "current" };
}

/** @returns {{ node: string, itemId: string }} where a device's bundle lives. */
export function bundleLocation(ns, deviceId) {
  assertNamespace(ns);
  assertDeviceId(deviceId);
  return ns === "oldmemo"
    ? { node: `${NS.oldmemo}.bundles:${deviceId}`, itemId: "current" }
    : { node: `${NS.twomemo}:bundles`, itemId: String(deviceId) };
}

// --- device lists ---

/**
 * @param {"oldmemo"|"twomemo"} ns
 * @param {{ id: number, label?: string|null }[]} devices
 */
export function buildDeviceList(ns, devices) {
  assertNamespace(ns);
  const items = devices.map((d) => {
    assertDeviceId(d.id);
    return el("device", NS[ns], ns === "twomemo" ? { id: d.id, label: d.label ?? null } : { id: d.id });
  });
  return el(ns === "oldmemo" ? "list" : "devices", NS[ns], {}, items);
}

/**
 * @returns {{ id: number, label: string|null }[]} entries with a bad id are
 *   skipped, duplicates dropped.
 * @throws if the element isn't the namespace's device list.
 */
export function parseDeviceList(ns, element) {
  assertNamespace(ns);
  expectElement(element, ns, ns === "oldmemo" ? "list" : "devices");
  const out = [];
  for (const d of children(element, NS[ns], "device")) {
    const id = parseDeviceId(d.attributes.id);
    if (id !== null && !out.some((x) => x.id === id)) {
      out.push({ id, label: ns === "twomemo" ? (d.attributes.label ?? null) : null });
    }
  }
  return out;
}

// --- bundles ---

/**
 * @param {"oldmemo"|"twomemo"} ns
 * @param {ReturnType<import("./store.js").OmemoStore["bundle"]>} bundle
 */
export function buildBundle(ns, { identityKey, signedPreKey, preKeys }) {
  assertNamespace(ns);
  const spk = b64(keys.encodePublicKey(ns, signedPreKey.publicKey));
  const ik = b64(keys.encodeIdentityKey(ns, identityKey));
  const x = NS[ns];
  if (ns === "oldmemo") {
    return el("bundle", x, {}, [
      el("signedPreKeyPublic", x, { signedPreKeyId: signedPreKey.id }, [spk]),
      el("signedPreKeySignature", x, {}, [b64(signedPreKey.signature)]),
      el("identityKey", x, {}, [ik]),
      el("prekeys", x, {}, preKeys.map((k) => el("preKeyPublic", x, { preKeyId: k.id }, [b64(keys.encodePublicKey(ns, k.publicKey))]))),
    ]);
  }
  return el("bundle", x, {}, [
    el("spk", x, { id: signedPreKey.id }, [spk]),
    el("spks", x, {}, [b64(signedPreKey.signature)]),
    el("ik", x, {}, [ik]),
    el("prekeys", x, {}, preKeys.map((k) => el("pk", x, { id: k.id }, [b64(keys.encodePublicKey(ns, k.publicKey))]))),
  ]);
}

/**
 * A contact's bundle, decoded and with its signed prekey signature checked
 * (docs/TASKS.md 3.9).
 *
 * @returns {{ identityKey: import("../crypto/keys.js").IdentityPublicKey,
 *   signedPreKey: { id: number, publicKey: Uint8Array, signature: Uint8Array },
 *   preKeys: { id: number, publicKey: Uint8Array }[] }} pre keys that don't
 *   parse are skipped; the list can be empty.
 * @throws on a missing or malformed identity key or signed prekey, or a
 *   signature that doesn't verify.
 */
export function parseBundle(ns, element) {
  assertNamespace(ns);
  expectElement(element, ns, "bundle");
  const x = NS[ns];
  const names = ns === "oldmemo"
    ? { spk: "signedPreKeyPublic", spkId: "signedPreKeyId", spks: "signedPreKeySignature", ik: "identityKey", pk: "preKeyPublic", pkId: "preKeyId" }
    : { spk: "spk", spkId: "id", spks: "spks", ik: "ik", pk: "pk", pkId: "id" };

  const required = (name) => {
    const found = onlyChild(element, x, name);
    if (!found) {
      throw new Error(`The bundle has no <${name}>.`);
    }
    return found;
  };
  const spkElement = required(names.spk);
  const spkId = parseKeyId(spkElement.attributes[names.spkId]);
  if (spkId === null) {
    throw new Error("The bundle's signed prekey has no valid id.");
  }
  const identityKey = keys.decodeIdentityKey(ns, unb64(textOf(required(names.ik)), "identity key"));
  const signedPreKey = {
    id: spkId,
    publicKey: keys.decodePublicKey(ns, unb64(textOf(spkElement), "signed prekey")),
    signature: unb64(textOf(required(names.spks)), "signed prekey signature"),
  };
  if (signedPreKey.signature.length !== 64
      || !keys.verifySignedPreKey(ns, identityKey, signedPreKey.publicKey, signedPreKey.signature)) {
    throw new Error("The bundle's signed prekey signature does not verify.");
  }

  const preKeys = [];
  const list = onlyChild(element, x, "prekeys");
  for (const pk of list ? children(list, x, names.pk) : []) {
    const id = parseKeyId(pk.attributes[names.pkId]);
    try {
      if (id !== null && !preKeys.some((k) => k.id === id)) {
        preKeys.push({ id, publicKey: keys.decodePublicKey(ns, unb64(textOf(pk), "pre key")) });
      }
    } catch {
      // skip a pre key that doesn't decode
    }
  }
  return { identityKey, signedPreKey, preKeys };
}

// --- <encrypted> ---

/**
 * @typedef {object} EncryptedKey
 * @property {string|null} jid - twomemo: the bare JID the key is for;
 *   oldmemo: null (keys aren't grouped by JID).
 * @property {number} rid - the recipient device.
 * @property {boolean} kex - a key exchange (oldmemo's prekey="true").
 * @property {Uint8Array} data
 *
 * @typedef {object} Encrypted
 * @property {"oldmemo"|"twomemo"} namespace
 * @property {number} sid - the sending device.
 * @property {EncryptedKey[]} keys
 * @property {Uint8Array|null} iv - oldmemo only.
 * @property {Uint8Array|null} payload - null for an empty OMEMO message.
 */

/**
 * @param {"oldmemo"|"twomemo"} ns
 * @param {Omit<Encrypted, "namespace">} message - twomemo keys need a jid;
 *   oldmemo needs an iv when there is a payload.
 */
export function buildEncrypted(ns, { sid, keys: entries, iv = null, payload = null }) {
  assertNamespace(ns);
  assertDeviceId(sid);
  const x = NS[ns];
  const keyElement = (k) => {
    assertDeviceId(k.rid);
    const flag = k.kex ? (ns === "oldmemo" ? { prekey: "true" } : { kex: "true" }) : {};
    return el("key", x, { rid: k.rid, ...flag }, [b64(k.data)]);
  };

  let headerChildren;
  if (ns === "oldmemo") {
    if (payload && !iv) {
      throw new Error("An oldmemo message with a payload needs an IV.");
    }
    headerChildren = entries.map(keyElement);
    if (iv) {
      headerChildren.push(el("iv", x, {}, [b64(iv)]));
    }
  } else {
    // Group by JID, keeping first-appearance order.
    const byJid = new Map();
    for (const k of entries) {
      if (typeof k.jid !== "string" || !k.jid || k.jid.includes("/")) {
        throw new Error("twomemo keys need the recipient's bare JID.");
      }
      if (!byJid.has(k.jid)) {
        byJid.set(k.jid, []);
      }
      byJid.get(k.jid).push(keyElement(k));
    }
    headerChildren = [...byJid].map(([jid, list]) => el("keys", x, { jid }, list));
  }
  const parts = [el("header", x, { sid }, headerChildren)];
  if (payload) {
    parts.push(el("payload", x, {}, [b64(payload)]));
  }
  return el("encrypted", x, {}, parts);
}

/**
 * @param {object} element - an <encrypted> element in either namespace.
 * @returns {Encrypted} keys that don't parse are skipped.
 * @throws if it isn't an OMEMO <encrypted> element, or its header, sid, IV
 *   or payload is malformed.
 */
export function parseEncrypted(element) {
  const ns = namespaceOf(element);
  if (!ns || element.name !== "encrypted") {
    throw new Error("Not an OMEMO <encrypted> element.");
  }
  const x = NS[ns];
  const header = onlyChild(element, x, "header");
  if (!header) {
    throw new Error("The <encrypted> element has no <header>.");
  }
  const sid = parseDeviceId(header.attributes.sid);
  if (sid === null) {
    throw new Error("The <header> has no valid sid.");
  }

  const parsed = [];
  const addKey = (k, jid) => {
    const rid = parseDeviceId(k.attributes.rid);
    const kex = parseBoolean(k.attributes[ns === "oldmemo" ? "prekey" : "kex"]);
    if (rid === null || kex === null) {
      return;
    }
    try {
      parsed.push({ jid, rid, kex, data: unb64(textOf(k), "key") });
    } catch {
      // skip a key that doesn't decode
    }
  };
  let iv = null;
  if (ns === "oldmemo") {
    for (const k of children(header, x, "key")) {
      addKey(k, null);
    }
    const ivElement = onlyChild(header, x, "iv");
    iv = ivElement ? unb64(textOf(ivElement), "IV") : null;
  } else {
    for (const group of children(header, x, "keys")) {
      const jid = group.attributes.jid;
      if (typeof jid === "string" && jid && !jid.includes("/")) {
        for (const k of children(group, x, "key")) {
          addKey(k, jid.toLowerCase());
        }
      }
    }
  }
  const payloadElement = onlyChild(element, x, "payload");
  return {
    namespace: ns,
    sid,
    keys: parsed,
    iv,
    payload: payloadElement ? unb64(textOf(payloadElement), "payload") : null,
  };
}

/**
 * The key meant for our device, if the message has one.
 *
 * @param {Encrypted} message
 * @param {{ jid: string, deviceId: number }} us - our (bare or full) JID
 *   and device id; twomemo keys must also be listed under our bare JID.
 * @returns {EncryptedKey|null}
 */
export function findOurKey(message, { jid, deviceId }) {
  const slash = jid.indexOf("/");
  const bare = (slash < 0 ? jid : jid.slice(0, slash)).toLowerCase();
  return message.keys.find((k) => k.rid === deviceId && (message.namespace === "oldmemo" || k.jid === bare)) ?? null;
}

// --- helpers ---

function expectElement(element, ns, name) {
  if (!element || element.ns !== NS[ns] || element.name !== name) {
    throw new Error(`Expected a ${ns} <${name}> element.`);
  }
}

function parseDeviceId(value) {
  if (typeof value !== "string" || !/^[0-9]{1,10}$/.test(value)) {
    return null;
  }
  const id = Number(value);
  return id >= 1 && id <= MAX_DEVICE_ID ? id : null;
}

function parseKeyId(value) {
  if (typeof value !== "string" || !/^[0-9]{1,10}$/.test(value)) {
    return null;
  }
  const id = Number(value);
  return id >= 1 && id <= keys.MAX_KEY_ID ? id : null;
}

// XML Schema booleans; a missing attribute is false, anything else odd is null.
function parseBoolean(value) {
  if (value === undefined || value === "false" || value === "0") {
    return false;
  }
  return value === "true" || value === "1" ? true : null;
}

function assertNamespace(ns) {
  if (!keys.NAMESPACES.includes(ns)) {
    throw new Error(`Unknown OMEMO namespace "${ns}"; expected "oldmemo" or "twomemo".`);
  }
}

function assertDeviceId(id) {
  if (!Number.isInteger(id) || id < 1 || id > MAX_DEVICE_ID) {
    throw new Error(`Device id must be an integer from 1 to ${MAX_DEVICE_ID}; got ${id}.`);
  }
}

function b64(bytes) {
  let s = "";
  for (const b of bytes) {
    s += String.fromCharCode(b);
  }
  return btoa(s);
}

// Whitespace inside base64 text is ignored, as some clients wrap lines.
function unb64(text, what) {
  const clean = text.replace(/\s+/g, "");
  if (clean.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) {
    throw new Error(`The ${what} is not valid base64.`);
  }
  return Uint8Array.from(atob(clean), (c) => c.charCodeAt(0));
}
