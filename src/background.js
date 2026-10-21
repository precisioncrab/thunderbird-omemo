/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Ordinary (non-privileged) WebExtension background script. The OMEMO work
 * happens in the Experiment (src/experiment/, which loads src/core.js); this
 * script starts it, passes on the options page's setting, and shows the
 * Experiment's diagnostic lines in the add-on's console.
 */

// Debug only (task 4.0): the Experiment's diagnostic lines, so they show
// here as well as in Thunderbird's Error Console.
browser.omemoXmpp.onDiagnostic.addListener((line) => {
  console.log(`[omemo] ${line}`);
});

// /omemo qr and /omemo help: the options page, opened as a Thunderbird tab
// at its "Verify on phone" or "Instructions" tab.
browser.omemoXmpp.onShowPage.addListener(async (section) => {
  try {
    await browser.tabs.create({ url: browser.runtime.getURL(`src/options/options.html#${section}`) });
  } catch (e) {
    console.log(`[omemo] couldn't open the page in a tab (${e?.message ?? e}); opening the options instead.`);
    browser.runtime.openOptionsPage();
  }
});

// The encryption setting from the options page (src/options/). Sent before
// install() so the hooks start with it, and again whenever it changes.
const DEFAULT_SETTINGS = { mode: "manual" };

browser.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.settings) {
    browser.omemoXmpp.setSettings({ ...DEFAULT_SETTINGS, ...changes.settings.newValue });
  }
});

/*
 * Chat contact names from the address book (src/contacts/, run by the
 * Experiment's chatNames). Each account's choice is in storage as
 * chatNames: { accounts: { <jid>: "off"|"local"|"server" } }, and the names
 * written so far as chatNamesWritten (so a name we wrote can follow its
 * card). Runs when cards change, when an account connects, at startup, and
 * when the options page's Chat contacts tab asks (a preview, or a write
 * after the user changed a choice).
 */

/** Every address book card as vCard text. */
async function addressBookCards() {
  const cards = [];
  for (const book of await browser.addressBooks.list(true)) {
    for (const node of book.contacts ?? []) {
      const card = node.properties?.vCard || vCardFromProperties(node.properties ?? {});
      if (card) {
        cards.push(card);
      }
    }
  }
  return cards;
}

/** A minimal vCard from the older card properties, if a card has no vCard. */
function vCardFromProperties(p) {
  const escape = (s) => String(s).replace(/[\\,;]/g, "\\$&").replace(/\n/g, "\\n");
  const lines = [];
  const name = p.DisplayName || [p.FirstName, p.LastName].filter(Boolean).join(" ");
  if (name) {
    lines.push(`FN:${escape(name)}`);
  }
  for (const key of ["CellularNumber", "HomePhone", "WorkPhone"]) {
    if (p[key]) {
      lines.push(`TEL:${p[key]}`);
    }
  }
  for (const key of ["PrimaryEmail", "SecondEmail"]) {
    if (p[key]) {
      lines.push(`EMAIL:${p[key]}`);
    }
  }
  if (p._JabberId) {
    lines.push(`IMPP:xmpp:${p._JabberId}`);
  }
  return lines.length ? ["BEGIN:VCARD", "VERSION:4.0", ...lines, "END:VCARD"].join("\r\n") : "";
}

// One run at a time, so two writes never race over chatNamesWritten.
let chatNamesQueue = Promise.resolve();

/** Previews (apply false) or writes (apply true) chat contact names. */
function runChatNames(apply) {
  const run = chatNamesQueue.then(async () => {
    const { chatNames, chatNamesWritten } = await browser.storage.local.get(["chatNames", "chatNamesWritten"]);
    const modes = chatNames?.accounts ?? {};
    if (apply && !Object.values(modes).some((m) => m === "local" || m === "server")) {
      return null;
    }
    const result = await browser.omemoXmpp.chatNames({
      cards: await addressBookCards(),
      modes,
      written: chatNamesWritten ?? {},
      apply,
    });
    if (apply && result && JSON.stringify(result.written) !== JSON.stringify(chatNamesWritten ?? {})) {
      await browser.storage.local.set({ chatNamesWritten: result.written });
    }
    return result;
  });
  chatNamesQueue = run.catch(() => {});
  return run;
}

// Card changes and connects come in bursts (a CardDAV sync, a reconnect of
// every account), so writes wait for a quiet moment.
let chatNamesTimer = null;
function applyChatNamesSoon() {
  clearTimeout(chatNamesTimer);
  chatNamesTimer = setTimeout(() => {
    runChatNames(true).catch((e) => console.log(`[omemo] ERROR: naming chat contacts failed: ${e?.message ?? e}`));
  }, 3000);
}

for (const event of [browser.contacts.onCreated, browser.contacts.onUpdated, browser.contacts.onDeleted]) {
  event.addListener(applyChatNamesSoon);
}
browser.omemoXmpp.onAccountConnected.addListener(applyChatNamesSoon);

browser.runtime.onMessage.addListener((message) => {
  if (message?.command === "chatNames.preview") {
    return runChatNames(false);
  }
  // After the options page saved a choice: write at once, then show the result.
  if (message?.command === "chatNames.apply") {
    return runChatNames(true).then((result) => result ?? runChatNames(false));
  }
  return undefined;
});

/*
 * Contacts Cleanup, the free address book add-on on addons.thunderbird.net
 * (github.com/precisioncrab/contacts-cleanup), runs the same chat contact
 * names from its Chat contacts tab, since it can't reach Thunderbird's
 * chat itself. Only that add-on is answered. Protocol 1:
 *   { command: "hello" }                        -> { name, version, pro, protocol }
 *   { command: "chatNames.preview" }            -> what the Chat contacts tab shows
 *   { command: "chatNames.setMode", jid, mode } -> saves an account's choice, writes, the same
 *   { command: "openOptions", section }         -> opens this options page at a tab
 *   { command: "chatContacts.hello" }           -> { add: true, remove: true }
 *   { command: "chatContacts.add", account, contacts: [{ jid, name }] }
 *                                               -> { added: [jid], failed: [{ jid, error }] }
 *   { command: "chatContacts.remove", account, jids: [jid] }
 *                                               -> { removed: [jid], failed: [{ jid, error }] }
 * Adding sends a roster set with the name from the card, then a presence
 * subscription request: what Thunderbird's own Add Contact sends
 * (xmpp-base.sys.mjs addBuddy), plus the name. Removing sends a roster set
 * with subscription="remove" (RFC 6121 2.5). The server's roster push then
 * updates Thunderbird's chat list.
 */
const CONTACTS_CLEANUP_ID = "contacts-cleanup@precisioncrab";
const MAX_CHAT_CONTACTS = 500;
const ROSTER_TIMEOUT_MS = 10000;
const BARE_JID = /^[^@\s/<>"'&]+@[^@\s/<>"'&]+$/;
let rosterIds = 0;

const xmlAttribute = (value) => String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" })[c]);

/** A roster set with one item: { jid, name } to add or rename, { jid, remove: true } to remove. */
function rosterSetXml({ jid, name, remove }) {
  const attributes = [`jid="${xmlAttribute(jid)}"`];
  if (remove) {
    attributes.push('subscription="remove"');
  } else if (name) {
    attributes.push(`name="${xmlAttribute(name)}"`);
  }
  return `<iq xmlns="jabber:client" type="set" id="cc-roster-${Date.now().toString(36)}-${++rosterIds}"><query xmlns="jabber:iq:roster"><item ${attributes.join(" ")}/></query></iq>`;
}

const subscribeXml = (jid) => `<presence xmlns="jabber:client" to="${xmlAttribute(jid)}" type="subscribe"/>`;
const isErrorReply = (xml) => /^<iq\b[^>]*\btype=(["'])error\1/.test(String(xml ?? "").trim());

/** Puts each contact on the account's roster with its name, then asks for its presence. */
async function addChatContacts(account, contacts) {
  const added = [];
  const failed = [];
  for (const contact of contacts) {
    const jid = String(contact?.jid ?? "").trim().toLowerCase();
    const name = String(contact?.name ?? "").trim().slice(0, 200);
    if (!BARE_JID.test(jid)) {
      failed.push({ jid, error: "not a chat address" });
      continue;
    }
    try {
      if (isErrorReply(await browser.omemoXmpp.sendIq(account, rosterSetXml({ jid, name }), ROSTER_TIMEOUT_MS))) {
        throw new Error("the server refused it");
      }
      await browser.omemoXmpp.sendStanza(account, subscribeXml(jid));
      added.push(jid);
    } catch (e) {
      failed.push({ jid, error: e?.message ?? String(e) });
    }
  }
  return { added, failed };
}

/** Takes each address off the account's roster. */
async function removeChatContacts(account, jids) {
  const removed = [];
  const failed = [];
  for (const raw of jids) {
    const jid = String(raw ?? "").trim().toLowerCase();
    if (!BARE_JID.test(jid)) {
      failed.push({ jid, error: "not a chat address" });
      continue;
    }
    try {
      if (isErrorReply(await browser.omemoXmpp.sendIq(account, rosterSetXml({ jid, remove: true }), ROSTER_TIMEOUT_MS))) {
        throw new Error("the server refused it");
      }
      removed.push(jid);
    } catch (e) {
      failed.push({ jid, error: e?.message ?? String(e) });
    }
  }
  return { removed, failed };
}
const NAME_MODES = ["off", "local", "server"];
const OPTIONS_TABS = ["settings", "verify", "contacts", "instructions"];

async function saveNameMode(jid, mode) {
  const { chatNames } = await browser.storage.local.get("chatNames");
  await browser.storage.local.set({ chatNames: { ...chatNames, accounts: { ...chatNames?.accounts, [jid]: mode } } });
  return (await runChatNames(true)) ?? runChatNames(false);
}

browser.runtime.onMessageExternal.addListener((message, sender) => {
  if (sender?.id !== CONTACTS_CLEANUP_ID) {
    return undefined;
  }
  switch (message?.command) {
    case "hello": {
      const manifest = browser.runtime.getManifest();
      return Promise.resolve({ name: manifest.name, version: manifest.version, pro: OMEMO_PRO.isPro(manifest), protocol: 1 });
    }
    case "chatNames.preview":
      return runChatNames(false);
    case "chatNames.setMode":
      if (typeof message.jid !== "string" || !/^[^@\s/]+@[^@\s/]+$/.test(message.jid) || !NAME_MODES.includes(message.mode)) {
        return Promise.reject(new Error("chatNames.setMode needs an account address and a mode (off, local or server)."));
      }
      return saveNameMode(message.jid, message.mode);
    case "chatContacts.hello":
      return Promise.resolve({ add: true, remove: true });
    case "chatContacts.add":
      if (typeof message.account !== "string" || !Array.isArray(message.contacts) || message.contacts.length > MAX_CHAT_CONTACTS) {
        return Promise.reject(new Error(`chatContacts.add needs an account and a list of at most ${MAX_CHAT_CONTACTS} contacts.`));
      }
      return addChatContacts(message.account, message.contacts);
    case "chatContacts.remove":
      if (typeof message.account !== "string" || !Array.isArray(message.jids) || message.jids.length > MAX_CHAT_CONTACTS) {
        return Promise.reject(new Error(`chatContacts.remove needs an account and a list of at most ${MAX_CHAT_CONTACTS} addresses.`));
      }
      return removeChatContacts(message.account, message.jids);
    case "openOptions": {
      const section = OPTIONS_TABS.includes(message.section) ? message.section : "settings";
      return browser.tabs.create({ url: browser.runtime.getURL(`src/options/options.html#${section}`) })
        .catch(() => browser.runtime.openOptionsPage())
        .then(() => true);
    }
    default:
      return undefined;
  }
});

(async () => {
  const { settings } = await browser.storage.local.get("settings");
  await browser.omemoXmpp.setSettings({ ...DEFAULT_SETTINGS, ...settings });
  await browser.omemoXmpp.install();
  console.log("[omemo] install() finished; OMEMO starts on each XMPP account as it connects.");
  // Accounts that connected before this script was listening.
  applyChatNamesSoon();
  // The free add-on's /call says where calls are (src/pro.js). The Pro
  // build has a real /call.
  if (!OMEMO_PRO.isPro(browser.runtime.getManifest())) {
    await browser.omemoXmpp.addHintCommand({
      name: "call",
      help: `call: audio calls, part of ${OMEMO_PRO.name}.`,
      message: OMEMO_PRO.callHint(),
    });
  }
})();
