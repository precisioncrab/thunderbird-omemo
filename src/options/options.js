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

load();
showDevices().catch((e) => {
  document.getElementById("devices").textContent = `Couldn't list the devices: ${e?.message ?? e}`;
});
