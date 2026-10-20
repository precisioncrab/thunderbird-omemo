/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests for automatic updates: scripts/updates.mjs (the update manifest
 * Thunderbird reads) and the update addresses in manifest.json and
 * package.json. Runs in both the free and the Pro repo; the free and Pro
 * builds share an add-on id, so the Pro build must never update from the
 * free add-on's address (that would replace Pro with the free version).
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { updateLink, updateManifest } from "../scripts/updates.mjs";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const manifest = JSON.parse(read("manifest.json"));
const updates = JSON.parse(read("package.json")).updates;
const isPro = Boolean(manifest.experiment_apis?.omemoCalls);

const FREE_UPDATE_URL = "https://raw.githubusercontent.com/precisioncrab/thunderbird-omemo/main/updates.json";
const FREE_LINK = "https://github.com/precisioncrab/thunderbird-omemo/releases/download/v{version}/thunderbird-omemo-{version}.xpi";

test("the update manifest has the shape Thunderbird reads", () => {
  const sha256 = "ab".repeat(32);
  const json = updateManifest({
    id: "thunderbird-omemo@precisioncrab",
    version: "0.1.5",
    link: "https://example.com/thunderbird-omemo-0.1.5.xpi",
    sha256,
    minVersion: "128.0",
  });
  assert.deepEqual(json, {
    addons: {
      "thunderbird-omemo@precisioncrab": {
        updates: [
          {
            version: "0.1.5",
            update_link: "https://example.com/thunderbird-omemo-0.1.5.xpi",
            update_hash: `sha256:${sha256}`,
            applications: { gecko: { strict_min_version: "128.0" } },
          },
        ],
      },
    },
  });
  assert.throws(() => updateManifest({ id: "a", version: "1", link: "https://x/", sha256: "abc", minVersion: "128.0" }));
});

test("download links are filled in per version and must be https", () => {
  assert.equal(updateLink(FREE_LINK, "0.1.5"),
    "https://github.com/precisioncrab/thunderbird-omemo/releases/download/v0.1.5/thunderbird-omemo-0.1.5.xpi");
  assert.throws(() => updateLink("http://example.com/{version}.xpi", "0.1.5"), /https/);
});

test("this build checks an https address for updates", () => {
  const url = manifest.browser_specific_settings.gecko.update_url;
  assert.ok(url?.startsWith("https://") && url.endsWith("/updates.json"), `update_url is ${url}`);
  assert.ok(updates?.link?.includes("{version}") && updates.link.startsWith("https://"));
  assert.ok(updates.out?.endsWith("updates.json"));
});

test("the free build updates from GitHub and the Pro build never does", () => {
  const url = manifest.browser_specific_settings.gecko.update_url;
  if (isPro) {
    assert.ok(!url.includes("github"), `Pro would update from ${url}`);
    assert.ok(!updates.link.includes("github"), `Pro updates would download ${updates.link}`);
  } else {
    assert.equal(url, FREE_UPDATE_URL);
    assert.equal(updates.link, FREE_LINK);
    assert.equal(updates.out, "updates.json");
  }
});
