/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * A section per account in Thunderbird's chat contact list, so you can see
 * which of your accounts each chat contact is on. In Thunderbird only: your
 * server's contact list and your other chat apps don't change.
 *
 * Thunderbird 158's chat contact list (#contactlistbox in messenger.xhtml)
 * shows Conversations, Online contacts and Offline contacts, and never the
 * contacts' groups (tags): chat-messenger.js only ever adds contacts to
 * #onlinecontactsGroup and #offlinecontactsGroup. The list is flat: a group
 * is a header row (a chat-group-richlistitem) with its contacts as the rows
 * after it, sorted online first, then by name (the group's addContact).
 *
 * So each account gets a header row of the same kind, labelled with the
 * account's name, holding the contacts that have a buddy on that account,
 * online first. A contact on two accounts is in both sections (Thunderbird
 * keeps one contact per address, shared by all accounts). Online contacts
 * and Offline contacts are hidden by a style sheet while the sections show
 * (the listbox gets SECTIONS_ATTR; the Experiment loads the sheet), and come
 * back as they were when the sections are turned off.
 *
 * Duck-typed against Thunderbird's chat list elements and contacts
 * (imIContact.getBuddies, imIBuddy.getAccountBuddies, the group's addContact,
 * removeContact, updateContactPosition, contacts and contactsById), so a test
 * can pass fakes.
 */

import { defaultGroupName, groupName } from "./chat-groups.js";

/** On the listbox while the sections show. */
export const SECTIONS_ATTR = "omemo-sections";
/** On a section's header row: the account's id. */
export const SECTION_ATTR = "omemo-section";
/** On a contact row in a section: the account's id. */
export const ROW_ATTR = "omemo-section-row";

/** The style sheet that hides Online contacts and Offline contacts while the sections show. */
export const SECTIONS_CSS = `
#contactlistbox[${SECTIONS_ATTR}] > #onlinecontactsGroup,
#contactlistbox[${SECTIONS_ATTR}] > #offlinecontactsGroup,
#contactlistbox[${SECTIONS_ATTR}] > richlistitem[is="chat-contact-richlistitem"]:not([${ROW_ATTR}]) {
  display: none !important;
}
`;

/**
 * A section's name: the one chosen on the options page for an XMPP account
 * (names[jid]), else the part of its address before the @, else the
 * account's name as Thunderbird shows it.
 */
export function sectionLabel(account, names = {}) {
  const jid = String(account.jid ?? "").toLowerCase();
  return groupName(jid ? names[jid] : "") || (jid ? defaultGroupName(jid) : String(account.name ?? ""));
}

/** The ids of the accounts a chat contact is on. */
export function accountIdsOf(contact) {
  const ids = new Set();
  for (const buddy of contact.getBuddies?.() ?? []) {
    for (const accountBuddy of buddy.getAccountBuddies?.() ?? []) {
      const id = accountBuddy.account?.id;
      if (id !== undefined && id !== null) {
        ids.add(String(id));
      }
    }
  }
  return ids;
}

/** The contact's buddy on one account, or null. */
export function accountBuddyOn(contact, accountId) {
  for (const buddy of contact.getBuddies?.() ?? []) {
    for (const accountBuddy of buddy.getAccountBuddies?.() ?? []) {
      if (String(accountBuddy.account?.id) === String(accountId)) {
        return accountBuddy;
      }
    }
  }
  return null;
}

/**
 * The sections: one per account, in Thunderbird's account order, each with
 * the contacts on that account. accounts: [{ id, label }].
 */
export function planSections(accounts, contacts) {
  const sections = accounts.map((a) => ({ id: String(a.id), label: a.label, contacts: [] }));
  const byId = new Map(sections.map((s) => [s.id, s]));
  for (const contact of contacts) {
    for (const id of accountIdsOf(contact)) {
      byId.get(id)?.contacts.push(contact);
    }
  }
  return sections;
}

/** The section header rows in a listbox, in order. */
export function sectionGroups(listbox) {
  return [...listbox.children].filter((el) => el.hasAttribute?.(SECTION_ATTR));
}

function dropRow(group, key) {
  const row = group.contactsById[key];
  if (!row) {
    return;
  }
  group.removeContact({ id: key });
  // A contact that stopped being a dummy has a new id, so removeContact
  // deletes the new key; the old one goes here.
  delete group.contactsById[key];
}

/** Takes every section out of the listbox and shows Online and Offline contacts again. */
export function removeSections(listbox) {
  for (const group of sectionGroups(listbox)) {
    for (const key of Object.keys(group.contactsById ?? {})) {
      dropRow(group, key);
    }
    group.remove();
  }
  listbox.removeAttribute(SECTIONS_ATTR);
}

/**
 * Makes the listbox show `plan` (planSections): creates, renames and fills
 * the sections, adding and removing only the rows that changed. When the
 * accounts or their order changed, the sections are made again.
 *
 * - createGroup(): a new, empty chat-group-richlistitem (not yet in the list)
 * - onRow(row, accountId): called for each new contact row (the Experiment
 *   makes it open the chat from that account)
 *
 * Returns { sections, added, removed }.
 */
export function syncSections(listbox, plan, { createGroup, onRow = () => {} }) {
  let groups = sectionGroups(listbox);
  const same = groups.length === plan.length && groups.every((g, i) => g.getAttribute(SECTION_ATTR) === plan[i].id);
  if (!same) {
    removeSections(listbox);
    groups = [];
  }
  listbox.setAttribute(SECTIONS_ATTR, "true");
  let added = 0;
  let removed = 0;
  plan.forEach((section, i) => {
    let group = groups[i];
    if (!group) {
      group = createGroup();
      group.setAttribute(SECTION_ATTR, section.id);
      group.setAttribute("name", section.label);
      listbox.append(group);
    } else if ((group.displayName || group.getAttribute("name")) !== section.label) {
      // The group keeps its name in displayName (the name attribute also
      // carries the count while it's closed).
      group.displayName = section.label;
      group._updateGroupLabel?.();
    }
    const wanted = new Map(section.contacts.map((c) => [String(c.id), c]));
    for (const key of Object.keys(group.contactsById ?? {})) {
      if (!wanted.has(key)) {
        dropRow(group, key);
        removed++;
      }
    }
    for (const [key, contact] of wanted) {
      if (group.contactsById?.[key]) {
        continue;
      }
      const row = group.addContact(contact);
      if (row) {
        row.setAttribute(ROW_ATTR, section.id);
        onRow(row, section.id);
        added++;
      }
    }
  });
  return { sections: plan.length, added, removed };
}

/** Puts a contact back in order in each section it's in (after it signed on or off). */
export function repositionContact(listbox, contact) {
  for (const group of sectionGroups(listbox)) {
    if (group.contactsById?.[String(contact.id)]) {
      group.updateContactPosition(contact);
    }
  }
}
