/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Writes the update manifest Thunderbird reads to update the add-on by
 * itself. manifest.json's browser_specific_settings.gecko.update_url points
 * at it; Thunderbird fetches it about once a day and installs any newer
 * version it lists. Format (read by Thunderbird's AddonUpdateChecker):
 *
 *   { "addons": { "<id>": { "updates": [ { "version", "update_link",
 *     "update_hash", "applications": { "gecko": { "strict_min_version" } } } ] } } }
 *
 * Where the .xpi is downloaded from and where the manifest is written come
 * from package.json's "updates" ({ "link": "...{version}...", "out": "..." }),
 * so the Pro build can publish elsewhere than the free one.
 *
 * Run after npm run package, with: npm run updates
 */

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

/** The .xpi's download address for a version, from a "...{version}..." template. */
export function updateLink(template, version) {
  const link = template.replaceAll("{version}", version);
  if (!link.startsWith("https://")) {
    throw new Error(`Update link ${link} isn't https; Thunderbird would refuse it.`);
  }
  return link;
}

/** The update manifest listing one version of the add-on. */
export function updateManifest({ id, version, link, sha256, minVersion }) {
  if (!/^[0-9a-f]{64}$/.test(sha256)) {
    throw new Error("sha256 must be 64 lowercase hex digits.");
  }
  return {
    addons: {
      [id]: {
        updates: [
          {
            version,
            update_link: link,
            update_hash: `sha256:${sha256}`,
            applications: { gecko: { strict_min_version: minVersion } },
          },
        ],
      },
    },
  };
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");
  const manifest = JSON.parse(readFileSync(join(root, "manifest.json"), "utf8"));
  const config = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).updates;
  const gecko = manifest.browser_specific_settings.gecko;
  const xpi = join(root, "dist", `thunderbird-omemo-${manifest.version}.xpi`);
  const sha256 = createHash("sha256").update(readFileSync(xpi)).digest("hex");
  const json = updateManifest({
    id: gecko.id,
    version: manifest.version,
    link: updateLink(config.link, manifest.version),
    sha256,
    minVersion: gecko.strict_min_version,
  });
  const out = join(root, config.out);
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, `${JSON.stringify(json, null, 2)}\n`);
  console.log(`Wrote ${out}: version ${manifest.version}, ${json.addons[gecko.id].updates[0].update_link}`);
  console.log(`Thunderbird reads it from ${gecko.update_url}`);
}
