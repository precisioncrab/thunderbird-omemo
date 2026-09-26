/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * The XEP-0420 (Stanza Content Encryption) envelope that twomemo encrypts
 * instead of the bare body, docs/TASKS.md 2.8. XEP-0384's profile: <rpad>
 * is required, <from> recommended, <time> optional, and <to> only for group
 * chats (out of scope for v1). We send
 *
 *   <envelope xmlns="urn:xmpp:sce:1">
 *     <content><body xmlns="jabber:client">...</body></content>
 *     <rpad>0-200 random characters</rpad>
 *     <from jid="our bare JID"/>
 *   </envelope>
 *
 * and on receive reject an envelope whose <from> names someone other than
 * the stanza's sender, which stops a server from replaying one contact's
 * message as another's. A missing <from> is accepted, since it's only
 * recommended.
 *
 * The XML parsing and escaping come from src/omemo/xml.js.
 */

import { randomBytes } from "./random.js";
import { INVALID_XML_CHAR, escapeAttribute, escapeText, onlyChild, parseXml, textOf } from "../omemo/xml.js";

// Re-exported for existing callers; the parser lives in src/omemo/xml.js.
export { parseXml, MAX_DEPTH } from "../omemo/xml.js";

export const SCE_NS = "urn:xmpp:sce:1";
const CLIENT_NS = "jabber:client";

const RPAD_MAX = 200;
const RPAD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * @param {object} fields
 * @param {string} fields.body - the chat text.
 * @param {string} fields.from - our bare JID.
 * @param {object} [options]
 * @param {(n: number) => Uint8Array} [options.random] - one byte for the
 *   padding length, then one byte per padding character.
 * @returns {Uint8Array} the UTF-8 envelope, for payload.encrypt.
 * @throws if the body holds characters XML can't carry, or `from` isn't a
 *   bare JID.
 */
export function buildEnvelope({ body, from }, { random = randomBytes } = {}) {
  if (typeof body !== "string" || INVALID_XML_CHAR.test(body)) {
    throw new Error("The body must be a string of characters XML allows.");
  }
  if (typeof from !== "string" || !from || from.includes("/") || INVALID_XML_CHAR.test(from)) {
    throw new Error("`from` must be a bare JID.");
  }
  const length = random(1)[0] % (RPAD_MAX + 1);
  const rpad = Array.from(length ? random(length) : [], (b) => RPAD_ALPHABET[b & 63]).join("");
  const xml =
    `<envelope xmlns="${SCE_NS}">` +
    `<content><body xmlns="${CLIENT_NS}">${escapeText(body)}</body></content>` +
    `<rpad>${rpad}</rpad>` +
    `<from jid="${escapeAttribute(from)}"/>` +
    `</envelope>`;
  return new TextEncoder().encode(xml);
}

/**
 * @param {Uint8Array} bytes - payload.decrypt's output.
 * @param {object} options
 * @param {string} options.sender - the stanza's sender (bare or full JID).
 * @returns {{ body: string|null, from: string|null, time: string|null }}
 *   body is null when <content> has no <body> (e.g. only other extensions).
 * @throws on malformed XML, a missing <envelope> or <content>, or a <from>
 *   that doesn't match the sender.
 */
export function parseEnvelope(bytes, { sender }) {
  if (typeof sender !== "string" || !sender) {
    throw new Error("parseEnvelope needs the stanza's sender.");
  }
  const root = parseXml(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  if (root.ns !== SCE_NS || root.name !== "envelope") {
    throw new Error("Not an XEP-0420 envelope.");
  }
  const content = onlyChild(root, SCE_NS, "content");
  if (!content) {
    throw new Error("The envelope has no <content>.");
  }
  const bodyElement = onlyChild(content, CLIENT_NS, "body");
  const fromElement = onlyChild(root, SCE_NS, "from");
  const timeElement = onlyChild(root, SCE_NS, "time");

  let from = null;
  if (fromElement) {
    from = fromElement.attributes.jid;
    if (typeof from !== "string" || bareJid(from) !== bareJid(sender)) {
      throw new Error("The envelope's <from> does not match the sender.");
    }
  }
  return {
    body: bodyElement ? textOf(bodyElement) : null,
    from,
    time: timeElement?.attributes.stamp ?? null,
  };
}

// Local and domain parts compare case-insensitively (RFC 7622); the
// resource is dropped.
function bareJid(jid) {
  const slash = jid.indexOf("/");
  return (slash < 0 ? jid : jid.slice(0, slash)).toLowerCase();
}
