/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Converting between xml.js elements and Thunderbird's XMLNode objects
 * (comm-central chat/protocols/xmpp/xmpp-xml.sys.mjs), and a PEP transport
 * on account.sendStanza.
 *
 * Thunderbird quirks this handles:
 *   - XMLNode.getXML() writes attribute values as they are, unescaped, so
 *     values are escaped here before they go in. (Text nodes are escaped by
 *     Thunderbird itself.)
 *   - Attributes with an empty value are dropped by XMLNode.
 *   - Every node with a namespace writes its own xmlns, so a child in its
 *     parent's namespace is given none.
 *   - Parsed nodes carry xmlns:prefix declarations as attributes; they're
 *     left out when converting back.
 */

import { escapeAttribute } from "./xml.js";

const NS_CLIENT = "jabber:client";

/**
 * @param {object} element - an xml.js element.
 * @param {object} Stanza - Thunderbird's Stanza builder.
 * @param {string|null} [parentNs] - the enclosing namespace; top-level
 *   stanzas sit in jabber:client, which Thunderbird leaves implicit.
 * @returns {object} an XMLNode.
 */
export function toXmlNode(element, Stanza, parentNs = NS_CLIENT) {
  const attributes = {};
  for (const [name, value] of Object.entries(element.attributes)) {
    attributes[name] = escapeAttribute(value);
  }
  const children = element.children.map((c) => (typeof c === "string" ? c : toXmlNode(c, Stanza, element.ns)));
  return Stanza.node(element.name, element.ns === parentNs ? null : element.ns, attributes, children);
}

/**
 * @param {object} node - an XMLNode (or a text node).
 * @param {string|null} [parentNs] - for nodes built with no namespace of
 *   their own, which inherit their parent's.
 * @returns {object|string} an xml.js element, or text.
 */
export function fromXmlNode(node, parentNs = NS_CLIENT) {
  if (node.type === "text") {
    return node.text;
  }
  const ns = node.uri || parentNs;
  const attributes = {};
  for (const [name, value] of Object.entries(node.attributes ?? {})) {
    if (name !== "xmlns" && !name.startsWith("xmlns:")) {
      attributes[name] = value;
    }
  }
  return { name: node.localName, ns, attributes, children: node.children.map((c) => fromXmlNode(c, ns)) };
}

/**
 * A pep.js transport on a Thunderbird XMPP account.
 *
 * @param {object} account - the XMPP account (has sendStanza).
 * @param {object} options
 * @param {object} options.Stanza
 * @param {typeof setTimeout} options.setTimer
 * @param {typeof clearTimeout} options.clearTimer
 * @param {number} [options.timeoutMs] - give up on a reply after this long.
 * @returns {(iq: object) => Promise<object>}
 */
export function createSendIq(account, { Stanza, setTimer, clearTimer, timeoutMs = 30000 }) {
  return (iq) => new Promise((resolve, reject) => {
    let done = false;
    const timer = setTimer(() => {
      if (!done) {
        done = true;
        reject(new Error(`No reply to a PEP request within ${timeoutMs / 1000} s.`));
      }
    }, timeoutMs);
    try {
      account.sendStanza(toXmlNode(iq, Stanza), (reply) => {
        if (!done) {
          done = true;
          clearTimer(timer);
          resolve(fromXmlNode(reply));
        }
        return true;
      });
    } catch (e) {
      done = true;
      clearTimer(timer);
      reject(e);
    }
  });
}
