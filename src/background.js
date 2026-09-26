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

(async () => {
  const { settings } = await browser.storage.local.get("settings");
  await browser.omemoXmpp.setSettings({ ...DEFAULT_SETTINGS, ...settings });
  await browser.omemoXmpp.install();
  console.log("[omemo] install() finished; OMEMO starts on each XMPP account as it connects.");
})();
