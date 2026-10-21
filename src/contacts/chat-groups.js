/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * A group per account in Thunderbird's chat contact list, so you can tell
 * which of your XMPP accounts a chat contact is on. In Thunderbird only:
 * your server's contact list and your other chat apps keep their own groups.
 *
 * Thunderbird's chat contact list shows contacts under tags (its groups). An
 * XMPP account buddy's tag setter also changes the roster on the server
 * (xmpp-base.sys.mjs: it rewrites the roster item's groups and sends a roster
 * set), so this moves account buddies the way Thunderbird's own roster
 * handling does instead: it sets `_tag` and tells the contacts service
 * (`accountBuddyMoved`), which updates Thunderbird's contact database and
 * the list, and nothing else.
 *
 * When an account connects, Thunderbird moves a contact that has groups on
 * the server back into one of them, so the background script runs this again
 * after each connect and whenever a contact lands in a group.
 *
 * Duck-typed against Thunderbird's account buddies (`_tag`, `_rosterItem`),
 * so a test can pass fakes. Group names are trimmed and cut to 64 characters.
 */

const MAX_NAME = 64;

/** The group name an account starts with: the part of its address before the @. */
export function defaultGroupName(jid) {
  const text = String(jid ?? "");
  return text.split("@")[0] || text;
}

/** A group name as it's used: trimmed, at most 64 characters, "" for none. */
export function groupName(name) {
  return String(name ?? "").trim().slice(0, MAX_NAME);
}

/** The group a contact goes back to: its first group on the server, else Thunderbird's default. */
function homeTag(accountBuddy, tags) {
  const group = (accountBuddy._rosterItem?.getChildren?.("group") ?? [])
    .map((g) => String(g.innerText ?? "").trim())
    .find(Boolean);
  return group ? tags.createTag(group) : tags.defaultTag;
}

/** Moves an account buddy to a tag in Thunderbird only. Returns whether it moved. */
function moveLocally(accountBuddy, tag, moved) {
  const old = accountBuddy._tag;
  if (!old || !tag || old.name === tag.name) {
    return false;
  }
  accountBuddy._tag = tag;
  moved(accountBuddy, old, tag);
  return true;
}

/**
 * Puts each connected account's chat contacts in that account's group, or
 * takes them out of the group this put them in before.
 *
 * - accounts: the connected XMPP accounts (`_buddies`, a Map of account buddies)
 * - jidOf(account): its bare JID
 * - groups: { <jid>: group name } for the accounts that have their own group
 * - applied: { <jid>: group name } as returned by the last run
 * - tags: Thunderbird's tags service (createTag, defaultTag)
 * - moved(accountBuddy, oldTag, newTag): Thunderbird's accountBuddyMoved
 *
 * Returns { accounts: [{ jid, group, contacts, moved }], applied }, where
 * applied keeps accounts that aren't connected as they were.
 */
export function chatGroups({ accounts, jidOf, groups = {}, applied = {}, tags, moved, log = () => {} }) {
  const result = { accounts: [], applied: { ...applied } };
  for (const account of accounts) {
    const jid = String(jidOf(account) ?? "").toLowerCase();
    const want = groupName(groups[jid]);
    const before = groupName(applied[jid]);
    const buddies = [...(account._buddies?.values?.() ?? [])];
    let count = 0;
    if (want) {
      const tag = tags.createTag(want);
      for (const accountBuddy of buddies) {
        count += moveLocally(accountBuddy, tag, moved) ? 1 : 0;
      }
      result.applied[jid] = want;
    } else {
      if (before) {
        for (const accountBuddy of buddies) {
          if (accountBuddy._tag?.name === before) {
            count += moveLocally(accountBuddy, homeTag(accountBuddy, tags), moved) ? 1 : 0;
          }
        }
      }
      delete result.applied[jid];
    }
    if (count) {
      log(`chat groups: moved ${count} of ${jid}'s chat contacts ${want ? `into "${want}"` : `out of "${before}"`}`);
    }
    result.accounts.push({ jid, group: want, contacts: buddies.length, moved: count });
  }
  return result;
}
