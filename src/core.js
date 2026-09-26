/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Everything the Experiment loads, bundled by scripts/build.mjs into
 * dist/omemo-core.mjs: the crypto core, plus the OMEMO layer on top of it
 * (key store and persistence, XML and OMEMO's formats, the message layer,
 * PEP, caps, the account lifecycle, and the bridge that hooks it all into
 * Thunderbird; docs/TASKS.md milestones 3 and 4).
 */

export * from "./crypto/index.js";

/* global __OMEMO_VERSION__ */
/**
 * The add-on version this bundle was built for (scripts/build.mjs fills it
 * in), which the Experiment checks so a stale cached core can't run with a
 * newer add-on. "source" when running unbundled, as in tests.
 */
export const CORE_VERSION = typeof __OMEMO_VERSION__ === "string" ? __OMEMO_VERSION__ : "source";

export * as store from "./omemo/store.js";
export * as persist from "./omemo/persist.js";
export * as xml from "./omemo/xml.js";
export * as formats from "./omemo/formats.js";
export * as messages from "./omemo/messages.js";
export * as pep from "./omemo/pep.js";
export * as caps from "./omemo/caps.js";
export * as account from "./omemo/account.js";
export * as xmlnode from "./omemo/xmlnode.js";
export * as bridge from "./omemo/bridge.js";
export * as fingerprint from "./omemo/fingerprint.js";
