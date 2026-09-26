/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Builds dist/thunderbird-omemo-<version>.xpi: a zip with manifest.json at the root,
 * the files the manifest references, the bundled crypto core (rebuilt
 * first, see scripts/build.mjs) and LICENSE. Install it with Add-ons and
 * Themes > gear > Install Add-on From File.
 *
 * No dependencies: the zip is written by hand with Node's zlib (deflate and
 * crc32, Node 22+). Entries use forward slashes and a fixed timestamp, so
 * the same sources always give the same bytes.
 *
 * Run with: npm run package
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { deflateRawSync, crc32 } from "node:zlib";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildCore, buildOptions, CORE_BUNDLE, OPTIONS_BUNDLE } from "./build.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(readFileSync(join(root, "manifest.json"), "utf8"));

await buildCore();
await buildOptions();
const files = new Set(["manifest.json", "LICENSE", CORE_BUNDLE, OPTIONS_BUNDLE]);
for (const script of manifest.background?.scripts ?? []) {
  files.add(script);
}
for (const api of Object.values(manifest.experiment_apis ?? {})) {
  files.add(api.schema);
  if (api.parent) {
    files.add(api.parent.script);
  }
  if (api.child) {
    files.add(api.child.script);
  }
}
// The options page (its script is the bundle above).
if (manifest.options_ui?.page) {
  files.add(manifest.options_ui.page);
}
for (const file of files) {
  if (!existsSync(join(root, file))) {
    throw new Error(`manifest.json references ${file}, which doesn't exist.`);
  }
}

const archive = zip([...files].sort().map((name) => ({ name, data: readFileSync(join(root, name)) })));
// Named by version, so the newest build is obvious and a file Thunderbird
// still holds open (on Windows it can keep the one it installed from) is
// never in the way of the next version.
let out = join(root, "dist", `thunderbird-omemo-${manifest.version}.xpi`);
mkdirSync(dirname(out), { recursive: true });
try {
  writeFileSync(out, archive);
} catch (e) {
  // Same version rebuilt while Thunderbird holds the file: add the local time.
  const now = new Date();
  const time = [now.getHours(), now.getMinutes(), now.getSeconds()].map((n) => String(n).padStart(2, "0")).join("");
  const fallback = join(root, "dist", `thunderbird-omemo-${manifest.version}-${time}.xpi`);
  writeFileSync(fallback, archive);
  console.log(`${out} is in use (${e.code}), probably by Thunderbird; wrote a copy instead.`);
  out = fallback;
}
console.log(`Wrote ${out} (${files.size} files, version ${manifest.version}):`);
for (const file of [...files].sort()) {
  console.log(`  ${file}`);
}

/** A zip archive of the given entries, deflated, with a fixed timestamp. */
function zip(entries) {
  const DOS_TIME = 0;
  const DOS_DATE = (0 << 9) | (1 << 5) | 1; // 1980-01-01, the earliest zip date
  const UTF8_NAMES = 0x0800;
  const locals = [];
  const centrals = [];
  let offset = 0;

  for (const { name, data } of entries) {
    const nameBytes = Buffer.from(name, "utf8");
    const compressed = deflateRawSync(data, { level: 9 });
    const crc = crc32(data);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed: 2.0 (deflate)
    local.writeUInt16LE(UTF8_NAMES, 6);
    local.writeUInt16LE(8, 8); // deflate
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28); // extra field length
    locals.push(local, nameBytes, compressed);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4); // version made by
    central.writeUInt16LE(20, 6); // version needed
    central.writeUInt16LE(UTF8_NAMES, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt16LE(DOS_TIME, 12);
    central.writeUInt16LE(DOS_DATE, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    // extra length, comment length, disk number, internal and external
    // attributes are all zero.
    central.writeUInt32LE(offset, 42);
    centrals.push(central, nameBytes);

    offset += local.length + nameBytes.length + compressed.length;
  }

  const centralSize = centrals.reduce((sum, b) => sum + b.length, 0);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, ...centrals, end]);
}
