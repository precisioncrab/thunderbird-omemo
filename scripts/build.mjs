/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Bundles src/core.js (the crypto core and OMEMO layer, @noble inlined) into one
 * ES module, dist/omemo-core.mjs, because Gecko can't resolve bare
 * "@noble/..." imports (docs/TASKS.md 3.1). The Experiment loads it with
 * ChromeUtils.importESModule. noble's MIT license comments are kept.
 *
 * Run with: npm run build (npm run package runs it too).
 */

import { build } from "esbuild";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
export const CORE_BUNDLE = "dist/omemo-core.mjs";

/**
 * @param {object} [options]
 * @param {boolean} [options.write] - false returns the code instead of
 *   writing it (for tests).
 * @returns {Promise<{ code: string, imports: object[] }|undefined>} when
 *   write is false: the bundle's code, and the imports esbuild left in it
 *   (there should be none).
 */
export async function buildCore({ write = true } = {}) {
  const result = await build({
    absWorkingDir: root,
    entryPoints: ["src/core.js"],
    bundle: true,
    format: "esm",
    platform: "neutral",
    target: "firefox128",
    outfile: CORE_BUNDLE,
    legalComments: "eof",
    write,
    metafile: true,
    // Stamped so the Experiment can tell a stale cached core from this one.
    define: { __OMEMO_VERSION__: JSON.stringify(JSON.parse(readFileSync(join(root, "manifest.json"), "utf8")).version) },
    logLevel: write ? "info" : "silent",
  });
  if (write) {
    return undefined;
  }
  const [output] = Object.values(result.metafile.outputs);
  return { code: result.outputFiles[0].text, imports: output.imports };
}

export const OPTIONS_BUNDLE = "dist/options.js";

/** Bundles the options page's script with its QR code library. */
export async function buildOptions() {
  await build({
    absWorkingDir: root,
    entryPoints: ["src/options/options.js"],
    bundle: true,
    format: "iife",
    platform: "browser",
    target: "firefox128",
    outfile: OPTIONS_BUNDLE,
    legalComments: "eof",
    logLevel: "info",
  });
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  await buildCore();
  await buildOptions();
}
