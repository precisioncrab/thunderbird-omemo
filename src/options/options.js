/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * The options page: the encryption mode (docs/TASKS.md 4.1), kept in
 * browser.storage.local as { settings: { mode } }. The background script
 * watches storage and passes changes on to the Experiment, so a change takes
 * effect at once.
 *
 * Also shows a QR code per connected account for verifying this
 * Thunderbird's device on a phone, and the /omemo instructions, each on its
 * own tab of the page. The page also opens as a Thunderbird tab of its own
 * (/omemo qr, /omemo help). Bundled with qrcode-generator (MIT) by
 * scripts/build.mjs into dist/options.js.
 *
 * In the free add-on, a card at the top points to OMEMO for Thunderbird + Calls
 * (src/pro.js, loaded before this script); the Pro build doesn't show it.
 */

import qrcode from "qrcode-generator";

const DEFAULT_MODE = "manual";
const saved = document.getElementById("saved");

async function load() {
  const { settings } = await browser.storage.local.get("settings");
  const mode = settings?.mode ?? DEFAULT_MODE;
  const input = document.querySelector(`input[name="mode"][value="${mode}"]`) ?? document.querySelector(`input[value="${DEFAULT_MODE}"]`);
  input.checked = true;
}

document.getElementById("modes").addEventListener("change", async (event) => {
  if (event.target.name !== "mode") {
    return;
  }
  const { settings } = await browser.storage.local.get("settings");
  await browser.storage.local.set({ settings: { ...settings, mode: event.target.value } });
  saved.textContent = "Saved.";
  setTimeout(() => {
    saved.textContent = "";
  }, 2000);
});

/** The QR codes: one per account this Thunderbird has an OMEMO device on. */
async function showDevices() {
  const container = document.getElementById("devices");
  const devices = await browser.omemoXmpp.getOwnDevices();
  container.replaceChildren();
  if (!devices.length) {
    const p = document.createElement("p");
    p.className = "detail";
    p.textContent = "No XMPP account is connected yet. Connect one, then reopen this page.";
    container.append(p);
    return;
  }
  for (const device of devices) {
    const qr = qrcode(0, "M");
    qr.addData(device.uri);
    qr.make();
    const svg = new DOMParser().parseFromString(qr.createSvgTag({ cellSize: 4, margin: 4, scalable: true }), "image/svg+xml").documentElement;

    const box = document.createElement("div");
    box.className = "device";
    const code = document.createElement("div");
    code.className = "qr";
    code.append(document.importNode(svg, true));
    const text = document.createElement("div");
    const name = document.createElement("div");
    name.className = "name";
    name.textContent = device.jid;
    const id = document.createElement("div");
    id.textContent = `This Thunderbird is device ${device.deviceId}. Fingerprint:`;
    const fingerprint = document.createElement("div");
    fingerprint.className = "fingerprint";
    fingerprint.textContent = device.fingerprint;
    text.append(name, id, fingerprint);
    box.append(code, text);
    container.append(box);
  }
}

/**
 * The page's tabs: Settings, Verify on phone, Instructions. The URL's hash
 * picks one (/omemo qr opens #verify, /omemo help #instructions).
 */
const tabs = [...document.querySelectorAll('[role="tab"]')];
function showTab(id) {
  const tab = tabs.find((t) => t.getAttribute("aria-controls") === id) ?? tabs[0];
  for (const t of tabs) {
    const selected = t === tab;
    t.setAttribute("aria-selected", String(selected));
    t.tabIndex = selected ? 0 : -1;
    document.getElementById(t.getAttribute("aria-controls")).hidden = !selected;
  }
}
for (const tab of tabs) {
  tab.addEventListener("click", () => {
    const id = tab.getAttribute("aria-controls");
    history.replaceState(null, "", `#${id}`);
    showTab(id);
  });
}
window.addEventListener("hashchange", () => showTab(location.hash.slice(1)));
showTab(location.hash.slice(1));

/**
 * The Chat contacts tab: names for chat contacts from the address book. The
 * background script does the work (it reads the address books and keeps
 * track of the names written); this page shows its preview and saves each
 * account's choice in storage as chatNames.accounts.
 */
const NAME_MODES = [
  ["off", "Off"],
  ["local", "In Thunderbird only"],
  ["server", "In Thunderbird and on the server"],
];

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

/** One line about an account's contacts, from the run's statuses. */
function namesSummary(account) {
  const count = (test) => account.contacts.filter(test).length;
  const parts = [];
  const pending = count((c) => (c.status === "set" || c.status === "update") && !c.done);
  const done = count((c) => c.done);
  if (done) {
    parts.push(`${plural(done, "contact just got its name", "contacts just got their names")}.`);
  }
  if (pending) {
    parts.push(account.mode === "off"
      ? `${plural(pending, "contact would get a name", "contacts would get names")}.`
      : `${plural(pending, "contact still needs its name", "contacts still need their names")}.`);
  }
  const named = count((c) => c.status === "named");
  if (named) {
    parts.push(`${plural(named, "already has", "already have")} the name from the address book.`);
  }
  const kept = count((c) => c.status === "kept");
  if (kept) {
    parts.push(`${plural(kept, "already has another name, which is", "already have other names, which are")} kept.`);
  }
  const ambiguous = count((c) => c.status === "ambiguous");
  if (ambiguous) {
    parts.push(`${plural(ambiguous, "is", "are")} on cards with different names.`);
  }
  const unmatched = count((c) => c.status === "unmatched");
  if (unmatched) {
    parts.push(`${plural(unmatched, "isn't", "aren't")} in the address book.`);
  }
  const noRoster = count((c) => c.status === "no-roster");
  if (noRoster) {
    parts.push(`${plural(noRoster, "isn't", "aren't")} on the server's contact list, so can't get a name there.`);
  }
  const failed = count((c) => c.status === "error");
  if (failed) {
    parts.push(`${failed} couldn't be named (see the add-on's console).`);
  }
  return parts.join(" ") || "No chat contacts on this account.";
}

/** What the list shows for one contact. */
function namesRow(contact, mode) {
  switch (contact.status) {
    case "set":
      return contact.done ? `Named ${contact.name}` : `${mode === "off" ? "Would get" : "Gets"} ${contact.name}`;
    case "update":
      return `${contact.done ? "Renamed" : "Would be renamed"} ${contact.name} (was ${contact.current}, from an older card)`;
    case "named":
      return contact.name;
    case "kept":
      return `Keeps ${contact.current}`;
    case "ambiguous":
      return `Cards with different names: ${contact.names.join(", ")}`;
    case "no-roster":
      return "Not on the server's contact list, so it can't get a name there";
    case "error":
      return `Couldn't be named: ${contact.error}`;
    default:
      return "Not in the address book";
  }
}

function renderChatNames(result) {
  const container = document.getElementById("chat-names");
  container.replaceChildren();
  const say = (text) => {
    const p = document.createElement("p");
    p.className = "detail";
    p.textContent = text;
    container.append(p);
  };
  if (!result) {
    say("Couldn't read the chat contacts; see the add-on's console.");
    return;
  }
  if (!result.accounts.length) {
    say("No XMPP account is connected yet. Connect one, then reopen this page.");
    return;
  }
  if (!result.cards) {
    say("No address book card with a name was found. Cards need a name and a phone number, chat address or email address.");
  }
  for (const account of result.accounts) {
    const box = document.createElement("div");
    box.className = "account";
    const name = document.createElement("div");
    name.className = "name";
    name.textContent = account.jid;

    const label = document.createElement("label");
    label.textContent = "Names:";
    const select = document.createElement("select");
    for (const [value, text] of NAME_MODES) {
      select.append(new Option(text, value, false, value === account.mode));
    }
    select.addEventListener("change", () => saveNameMode(account.jid, select.value));
    label.append(select);

    const summary = document.createElement("p");
    summary.className = "detail";
    summary.textContent = namesSummary(account);
    box.append(name, label, summary);

    if (account.contacts.length) {
      const details = document.createElement("details");
      const title = document.createElement("summary");
      title.textContent = `All ${plural(account.contacts.length, "chat contact", "chat contacts")}`;
      const table = document.createElement("table");
      table.className = "commands";
      const order = ["set", "update", "error", "ambiguous", "named", "kept", "no-roster", "unmatched"];
      const sorted = [...account.contacts].sort((a, b) => order.indexOf(a.status) - order.indexOf(b.status) || a.jid.localeCompare(b.jid));
      for (const contact of sorted) {
        const row = table.insertRow();
        const address = document.createElement("th");
        address.textContent = contact.jid;
        row.append(address);
        row.insertCell().textContent = namesRow(contact, account.mode);
      }
      details.append(title, table);
      box.append(details);
    }
    container.append(box);
  }
}

async function showChatNames(command = "chatNames.preview") {
  try {
    renderChatNames(await browser.runtime.sendMessage({ command }));
  } catch (e) {
    document.getElementById("chat-names").textContent = `Couldn't read the chat contacts: ${e?.message ?? e}`;
  }
}

async function saveNameMode(jid, mode) {
  const { chatNames } = await browser.storage.local.get("chatNames");
  await browser.storage.local.set({ chatNames: { ...chatNames, accounts: { ...chatNames?.accounts, [jid]: mode } } });
  await showChatNames("chatNames.apply");
}

/** Points a card's button at a web page, opened in the web browser rather than in Thunderbird. */
function linkOut(link, text, url) {
  link.textContent = text;
  link.href = url;
  link.addEventListener("click", (event) => {
    if (browser.windows?.openDefaultBrowser) {
      event.preventDefault();
      browser.windows.openDefaultBrowser(url);
    }
  });
}

/** The Pro card, in the free add-on only. */
function showPro() {
  const pro = globalThis.OMEMO_PRO;
  if (!pro || pro.isPro(browser.runtime.getManifest())) {
    return;
  }
  document.getElementById("pro-name").textContent = pro.name;
  document.getElementById("pro-text").textContent = `Audio calls with Cheogram, Conversations and other XMPP apps, in a call window in Thunderbird. Installs over this add-on and keeps your keys and verifications. ${pro.onSale ? `${pro.price}, one time.` : "Coming soon."}`;
  linkOut(document.getElementById("pro-link"), pro.onSale ? "Add calls" : "Learn more", pro.url);
  document.getElementById("pro").hidden = false;
}

/*
 * Contacts Cleanup, the free address book add-on: a card on the Chat contacts
 * tab, in the free add-on and Pro alike, until Contacts Cleanup has talked to
 * this add-on (the background script notes its hello). Not on
 * addons.thunderbird.net yet: once it's listed, point `url` at its page
 * there, set `listed`, and change the README's link to match.
 */
const CONTACTS_CLEANUP = {
  url: "https://github.com/precisioncrab/contacts-cleanup",
  listed: false,
};

async function showCleanup() {
  const { contactsCleanup } = await browser.storage.local.get("contactsCleanup");
  if (contactsCleanup?.seen) {
    return;
  }
  document.getElementById("cleanup-text").textContent = `A free address book add-on from the same maker. It finds duplicate cards, puts phone numbers in one format and adds chat addresses (XMPP and JMP.chat) to cards, so more chat contacts get their names here. It can also put people from your cards on your chat list. ${CONTACTS_CLEANUP.listed ? "Free on Thunderbird's add-on site." : "Coming soon to Thunderbird's add-on site."}`;
  linkOut(document.getElementById("cleanup-link"), CONTACTS_CLEANUP.listed ? "Get it free" : "Learn more", CONTACTS_CLEANUP.url);
  document.getElementById("cleanup").hidden = false;
}

showPro();
showCleanup().catch(() => {});
load();
showDevices().catch((e) => {
  document.getElementById("devices").textContent = `Couldn't list the devices: ${e?.message ?? e}`;
});
showChatNames();
