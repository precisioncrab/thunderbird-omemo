/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Chat contact names from the address book: for each chat contact of each
 * connected XMPP account, the address book's name (src/contacts/cards.js),
 * written where the account's setting says:
 *   "local"   Thunderbird only: the contact's own name in Thunderbird's
 *             contact list (blist.sqlite), never sent anywhere
 *   "server"  also the server: the roster name, with Thunderbird's own roster
 *             update, so other apps on the account get it too
 *   "off"     nothing written; the preview still shows what would be named
 *
 * A name a contact already has is never replaced (a roster name, or a name
 * given in Thunderbird), except one this add-on wrote itself, which follows
 * the card when its name changes (`written` remembers those).
 *
 * Read from Thunderbird 158 (chat/modules/imContacts.sys.mjs,
 * chat/protocols/xmpp/xmpp-base.sys.mjs): a contact's display name is its
 * alias, else its preferred account buddy's: the roster name, else the
 * contact's own vCard name, else the address. Setting imIContact.alias also
 * sets serverAlias on every account buddy, and an XMPP account buddy's
 * serverAlias setter sends a roster set. So "local" sets the alias with
 * serverAlias shadowed on those buddies for the moment it runs.
 *
 * Works on raw Thunderbird objects: an account's `_buddies` map of account
 * buddies (`_rosterAlias`, `_rosterItem`, `buddy.contact`), so a test can
 * pass fakes shaped the same way.
 */

import { indexCards, nameFor } from "./cards.js";

export const MODES = ["off", "local", "server"];

/** The key `written` uses for one chat contact of one account. */
export const writtenKey = (accountJid, buddyJid) => `${accountJid} ${buddyJid}`;

/** The account buddy's name on the server's roster, or "". */
function rosterName(accountBuddy) {
  return accountBuddy._rosterAlias || accountBuddy._rosterItem?.attributes?.name || "";
}

function accountBuddiesOf(contact) {
  return (contact?.getBuddies?.() ?? []).flatMap((b) => b.getAccountBuddies?.() ?? []);
}

/**
 * Sets a contact's name in Thunderbird only. imIContact.alias would also
 * send it to the server as each account buddy's roster name, so their
 * serverAlias is shadowed with a no-op while it runs (it runs synchronously).
 */
export function setLocalName(contact, name) {
  const shadowed = [];
  for (const accountBuddy of accountBuddiesOf(contact)) {
    if (Object.hasOwn(accountBuddy, "serverAlias")) {
      continue;
    }
    Object.defineProperty(accountBuddy, "serverAlias", {
      configurable: true,
      get() {
        return Reflect.get(Object.getPrototypeOf(accountBuddy), "serverAlias", accountBuddy);
      },
      set() {},
    });
    shadowed.push(accountBuddy);
  }
  try {
    contact.alias = name;
  } finally {
    for (const accountBuddy of shadowed) {
      delete accountBuddy.serverAlias;
    }
  }
}

/**
 * What to do for one chat contact. Returns
 *   { status, name, current }
 * status: "set" (gets the name), "update" (our earlier name follows the
 * card), "named" (already has this name), "kept" (has a name of its own,
 * `current`), "ambiguous" (cards with different names, `names`),
 * "unmatched" (no card), "no-roster" (server mode, but the contact isn't on
 * the server's roster).
 */
function decide(accountBuddy, match, mode, ours) {
  if (!match.name) {
    return match.by ? { status: "ambiguous", names: match.names } : { status: "unmatched" };
  }
  const target = match.name;
  const alias = accountBuddy.buddy?.contact?.alias || "";
  const roster = rosterName(accountBuddy);
  const oursIs = (name, where) => Boolean(ours && ours.where === where && ours.name === name);
  if (mode === "server") {
    if (roster) {
      if (roster === target) {
        return { status: "named", name: target };
      }
      return oursIs(roster, "server") ? { status: "update", name: target, current: roster } : { status: "kept", current: roster };
    }
    if (alias && !oursIs(alias, "local")) {
      return { status: "kept", current: alias };
    }
    return accountBuddy._rosterItem ? { status: "set", name: target } : { status: "no-roster" };
  }
  // "local" (and the preview for "off").
  if (alias) {
    if (alias === target) {
      return { status: "named", name: target };
    }
    return oursIs(alias, "local") ? { status: "update", name: target, current: alias } : { status: "kept", current: alias };
  }
  const named = accountBuddiesOf(accountBuddy.buddy?.contact).map(rosterName).find(Boolean) || roster;
  return named ? { status: "kept", current: named } : { status: "set", name: target };
}

/**
 * Previews or applies names for every connected account's chat contacts.
 *
 * @param {object} options
 * @param {object[]} options.accounts - connected XMPP accounts (raw
 *   Thunderbird objects with `_buddies`)
 * @param {(account: object) => string} options.jidOf - an account's bare JID
 * @param {string[]} options.cards - the address book cards' vCard texts
 * @param {Object<string, string>} [options.modes] - account JID -> mode
 *   (missing means "off")
 * @param {Object<string, {name: string, where: string}>} [options.written] -
 *   names written earlier (writtenKey -> what and where); not changed
 * @param {boolean} [options.apply] - write names (false: preview only)
 * @param {(line: string) => void} [options.log]
 * @returns {{ cards: number, accounts: object[], written: object }} one
 *   entry per account: { jid, mode, contacts: [{ jid, status, name,
 *   current, names, by }] }, and `written` with this run's writes added
 */
export function chatNames({ accounts, jidOf, cards, modes = {}, written = {}, apply = false, log = () => {} }) {
  const index = indexCards(cards);
  const nowWritten = { ...written };
  const result = [];
  for (const account of accounts) {
    const accountJid = jidOf(account);
    const mode = MODES.includes(modes[accountJid]) ? modes[accountJid] : "off";
    const contacts = [];
    let wrote = 0;
    for (const accountBuddy of account._buddies?.values?.() ?? []) {
      const jid = String(accountBuddy.normalizedName ?? accountBuddy.userName ?? "").toLowerCase();
      if (!jid) {
        continue;
      }
      const key = writtenKey(accountJid, jid);
      const match = nameFor(index, jid);
      const entry = { jid, by: match.by, ...decide(accountBuddy, match, mode, written[key]) };
      if (apply && mode !== "off" && (entry.status === "set" || entry.status === "update")) {
        try {
          if (mode === "server") {
            accountBuddy.serverAlias = entry.name;
          } else {
            setLocalName(accountBuddy.buddy.contact, entry.name);
          }
          nowWritten[key] = { name: entry.name, where: mode };
          entry.done = true;
          wrote++;
        } catch (e) {
          entry.status = "error";
          entry.error = String(e?.message ?? e);
          log(`ERROR: couldn't name a chat contact of ${accountJid}: ${entry.error}`);
        }
      }
      contacts.push(entry);
    }
    if (wrote) {
      log(`chat contact names: ${wrote} written for ${accountJid} (${mode === "server" ? "Thunderbird and the server" : "Thunderbird only"})`);
    }
    result.push({ jid: accountJid, mode, contacts });
  }
  return { cards: index.cards, accounts: result, written: nowWritten };
}
