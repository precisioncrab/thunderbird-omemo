/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Trust decisions (docs/PLAN.md milestone 5), "blind trust before
 * verification" as Conversations and Cheogram do it (the maintainer's choice,
 * 2026-09-25):
 *
 *   - A contact's identity keys are accepted automatically ("blind") until
 *     the user verifies one of them.
 *   - Once one is verified, any new key for that contact is "undecided":
 *     not encrypted to until the user trusts or verifies it.
 *   - A device that shows up with a different key than before is always
 *     reported ("key-changed"); the new key then follows the two rules above.
 *   - "distrusted" keys are never encrypted to.
 *
 * Trust belongs to identity keys (by fingerprint), as in Conversations; the
 * store also remembers which key each device last had, to spot changes.
 * This applies the same way to our own other devices (jid = our JID).
 */

import { TRUST_STATES } from "./store.js";

/** States we encrypt to. */
const USABLE = new Set(["blind", "trusted", "verified"]);

/** How each state reads in /omemo status. */
export const TRUST_DESCRIPTIONS = Object.freeze({
  blind: "trusted automatically, not verified",
  trusted: "approved by you, not verified",
  verified: "verified",
  undecided: "not trusted yet, so messages aren't encrypted to it",
  distrusted: "distrusted, so messages aren't encrypted to it",
});

/**
 * @typedef {object} TrustNotice
 * @property {"key-changed"|"new-undecided"} type
 * @property {string} jid
 * @property {number} deviceId
 * @property {string} fingerprint
 * @property {string} [previous] - key-changed: the old fingerprint.
 */

/**
 * Decides whether to use a device's key, recording what we learn: the
 * device's current key, and a trust state for a key seen for the first time.
 *
 * @param {import("./store.js").OmemoStore} store
 * @param {string} jid - the device's owner (bare JID).
 * @param {number} deviceId
 * @param {string} fingerprint - fingerprint.js's form.
 * @returns {{ use: boolean, state: string, notices: TrustNotice[] }}
 */
export function decideTrust(store, jid, deviceId, fingerprint) {
  const notices = [];
  const previous = store.deviceKey(jid, deviceId);
  if (previous !== fingerprint) {
    if (previous !== null) {
      notices.push({ type: "key-changed", jid, deviceId, fingerprint, previous });
    }
    store.setDeviceKey(jid, deviceId, fingerprint);
  }
  let state = store.trustOf(jid, fingerprint);
  if (state === null) {
    state = store.hasVerified(jid) ? "undecided" : "blind";
    store.setTrust(jid, fingerprint, state);
    if (state === "undecided") {
      notices.push({ type: "new-undecided", jid, deviceId, fingerprint });
    }
  }
  return { use: USABLE.has(state), state, notices };
}

/**
 * @param {TrustNotice} notice
 * @returns {string} a line for the conversation.
 */
export function noticeText(notice) {
  if (notice.type === "key-changed") {
    return `Warning: the security key of ${notice.jid}'s device ${notice.deviceId} has changed `
      + `(now ${notice.fingerprint}). If they didn't reinstall their app, someone may be listening in. `
      + `Compare fingerprints, then use /omemo verify ${notice.deviceId}.`;
  }
  return `${notice.jid} has a new device (${notice.deviceId}, ${notice.fingerprint}). `
    + `Messages aren't encrypted to it until you check it: /omemo verify ${notice.deviceId} or /omemo trust ${notice.deviceId}.`;
}

/** @returns {boolean} whether a state is one we encrypt to. */
export function isUsable(state) {
  return USABLE.has(state);
}

export { TRUST_STATES };
