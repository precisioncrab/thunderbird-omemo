/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * OMEMO Pro for Thunderbird, the paid version with audio calls, as this
 * free add-on mentions it: the Pro card on the options page and the answer
 * to /call. The one place to change when Pro goes on sale. The Pro build is
 * this same code plus the calls Experiment, and shows none of it.
 *
 * A classic script (no exports): the background page and the options page
 * load it before their own scripts and read the OMEMO_PRO global.
 */

// eslint-disable-next-line no-unused-vars
var OMEMO_PRO = {
  name: "OMEMO Pro for Thunderbird",
  price: "$10",
  // Until Pro is on sale, its section in the README.
  url: "https://github.com/precisioncrab/thunderbird-omemo#omemo-pro-for-thunderbird",
  onSale: false,

  /** Whether this add-on is the Pro build: it carries the calls Experiment. */
  isPro(manifest) {
    return Boolean(manifest?.experiment_apis?.omemoCalls);
  },

  /** What the free add-on's /call shows in the chat. */
  callHint() {
    return this.onSale
      ? `Audio calls are part of ${this.name} (${this.price}, one time): ${this.url}`
      : `Audio calls are coming in ${this.name}: ${this.url}`;
  },
};
