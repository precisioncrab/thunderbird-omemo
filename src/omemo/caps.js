/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Entity capabilities (XEP-0115) for docs/TASKS.md 3.5. Servers push PEP
 * updates (a contact's new OMEMO device) only to clients that advertise
 * "<node>+notify" for them, which they learn from a caps hash in presence.
 * Thunderbird sends no caps hash, so the Experiment adds OMEMO's +notify
 * features to Thunderbird's disco#info features, puts a <c/> with the hash
 * below into our presence, and answers disco#info for "<CAPS_NODE>#<ver>".
 *
 * The hash is the XEP-0115 section 5.1 algorithm without data forms (our
 * disco#info reply has none), checked against the XEP's own example.
 */

import { sha1 } from "@noble/hashes/sha1";

export const NS_CAPS = "http://jabber.org/protocol/caps";

/** Where our caps say the software comes from. */
export const CAPS_NODE = "https://github.com/precisioncrab/thunderbird-omemo";

/** OMEMO's +notify features: device list changes in both namespaces. */
export const NOTIFY_FEATURES = Object.freeze([
  "eu.siacs.conversations.axolotl.devicelist+notify",
  "urn:xmpp:omemo:2:devices+notify",
]);

/**
 * @param {object} disco
 * @param {{ category: string, type: string, lang?: string, name?: string }[]} disco.identities
 * @param {string[]} disco.features
 * @returns {string} the base64 SHA-1 verification string ("ver").
 */
export function capsVer({ identities, features }) {
  // i;octet ordering: compare by UTF-8 bytes, which for strings is the same
  // as comparing code points.
  const byOctets = (a, b) => {
    const x = [...a].map((c) => c.codePointAt(0));
    const y = [...b].map((c) => c.codePointAt(0));
    for (let i = 0; i < Math.min(x.length, y.length); i++) {
      if (x[i] !== y[i]) {
        return x[i] - y[i];
      }
    }
    return x.length - y.length;
  };
  const ids = identities
    .map((i) => ({ key: `${i.category}/${i.type}/${i.lang ?? ""}`, full: `${i.category}/${i.type}/${i.lang ?? ""}/${i.name ?? ""}` }))
    .sort((a, b) => byOctets(a.key, b.key) || byOctets(a.full, b.full))
    .map((i) => `${i.full}<`);
  const feats = [...new Set(features)].sort(byOctets).map((f) => `${f}<`);
  const digest = sha1(new TextEncoder().encode(ids.join("") + feats.join("")));
  let s = "";
  for (const b of digest) {
    s += String.fromCharCode(b);
  }
  return btoa(s);
}
