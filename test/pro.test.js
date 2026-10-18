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
  assert.equal(pro.isPro(JSON.parse(read("manifest.json"))), false);
  assert.equal(pro.isPro({ experiment_apis: { omemoXmpp: {}, omemoCalls: {} } }), true);
  assert.equal(pro.isPro(undefined), false);
});

test("/call names Pro and its link, with the price once it's on sale", () => {
  const pro = loadPro();
  assert.equal(pro.callHint(), `Audio calls are coming in OMEMO Pro for Thunderbird: ${pro.url}`);
  pro.onSale = true;
  assert.equal(pro.callHint(), `Audio calls are part of OMEMO Pro for Thunderbird ($10, one time): ${pro.url}`);
});

test("the link before Pro is on sale goes to the README's Pro section", () => {
  const pro = loadPro();
  const anchor = new URL(pro.url).hash.slice(1);
  const headings = read("README.md").split(/\r?\n/).filter((l) => l.startsWith("## "))
    .map((l) => l.slice(3).trim().toLowerCase().replace(/[^\w\s-]/g, "").replace(/\s+/g, "-"));
  assert.ok(headings.includes(anchor), `no README heading for #${anchor}`);
});

test("the background and options pages load src/pro.js before their own scripts", () => {
  const scripts = JSON.parse(read("manifest.json")).background.scripts;
  assert.ok(scripts.indexOf("src/pro.js") >= 0 && scripts.indexOf("src/pro.js") < scripts.indexOf("src/background.js"));
  const page = read("src/options/options.html");
  assert.ok(page.indexOf('src="../pro.js"') >= 0 && page.indexOf('src="../pro.js"') < page.indexOf('src="../../dist/options.js"'));
});
