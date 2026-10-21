/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests for src/pro.js, the free add-on's pointer to OMEMO Pro for
 * Thunderbird (the options page's card and the /call answer), and that the
 * pages load it before the scripts that read it.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

function loadPro() {
  const context = vm.createContext({});
  vm.runInContext(read("src/pro.js"), context);
  return context.OMEMO_PRO;
}

test("the Pro build is the one with the calls Experiment", () => {
  const pro = loadPro();
  // Runs in both repos, so example manifests rather than this repo's own.
  assert.equal(pro.isPro({ experiment_apis: { omemoXmpp: {} } }), false);
  assert.equal(pro.isPro({ experiment_apis: { omemoXmpp: {}, omemoCalls: {} } }), true);
  assert.equal(pro.isPro(undefined), false);
});

test("/call names Pro, its price and its link", () => {
  const pro = loadPro();
  assert.equal(pro.callHint(), `Audio calls are part of OMEMO Pro for Thunderbird ($10, one time): ${pro.url}`);
  pro.onSale = false;
  assert.equal(pro.callHint(), `Audio calls are coming in OMEMO Pro for Thunderbird: ${pro.url}`);
});

test("Pro is on sale, and the link goes to its Gumroad listing, which the README links too", () => {
  const pro = loadPro();
  assert.equal(pro.onSale, true);
  assert.equal(pro.url, "https://precisioncrab.gumroad.com/l/omemo-pro");
  assert.ok(read("README.md").includes(pro.url), "the README doesn't link Pro's listing");
});

test("the background and options pages load src/pro.js before their own scripts", () => {
  const scripts = JSON.parse(read("manifest.json")).background.scripts;
  assert.ok(scripts.indexOf("src/pro.js") >= 0 && scripts.indexOf("src/pro.js") < scripts.indexOf("src/background.js"));
  const page = read("src/options/options.html");
  assert.ok(page.indexOf('src="../pro.js"') >= 0 && page.indexOf('src="../pro.js"') < page.indexOf('src="../../dist/options.js"'));
});
