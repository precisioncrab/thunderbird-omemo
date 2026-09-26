/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * PEP (XEP-0163, on XEP-0060 pubsub) for OMEMO's device lists and bundles,
 * docs/TASKS.md 3.4 and 3.6. It builds and reads xml.js element trees and
 * talks through an injected `sendIq(iq) => Promise<reply>`, so it runs in
 * Node against a fake server; the Experiment supplies a sendIq built on
 * Thunderbird's account.sendStanza.
 *
 * publish() asks for the node settings OMEMO needs through publish-options
 * (open access; for twomemo bundles, max_items=max so every device's item
 * is kept). A server that already has the node configured differently
 * answers precondition-not-met; then we reconfigure the node and publish
 * again, as XEP-0060 section 7.1.5 describes.
 */

import { el, children, onlyChild } from "./xml.js";

export const NS_PUBSUB = "http://jabber.org/protocol/pubsub";
export const NS_PUBSUB_OWNER = "http://jabber.org/protocol/pubsub#owner";
export const NS_PUBSUB_EVENT = "http://jabber.org/protocol/pubsub#event";
export const NS_PUBSUB_ERRORS = "http://jabber.org/protocol/pubsub#errors";
const NS_DATA = "jabber:x:data";
const NS_STANZAS = "urn:ietf:params:xml:ns:xmpp-stanzas";
const NS_CLIENT = "jabber:client";

/** A pubsub request the server answered with an error. */
export class PepError extends Error {
  /**
   * @param {{ type: string|null, condition: string|null, pubsubCondition: string|null, text: string|null }} details
   */
  constructor(details) {
    super(`PEP request failed: ${details.condition ?? "unknown error"}${details.pubsubCondition ? ` (${details.pubsubCondition})` : ""}${details.text ? `: ${details.text}` : ""}`);
    this.name = "PepError";
    Object.assign(this, details);
  }
}

// --- stanzas ---

/** A data form of type submit (XEP-0004), with FORM_TYPE first. */
function submitForm(formType, fields) {
  return el("x", NS_DATA, { type: "submit" }, [
    el("field", NS_DATA, { var: "FORM_TYPE", type: "hidden" }, [el("value", NS_DATA, {}, [formType])]),
    ...Object.entries(fields).map(([name, value]) => el("field", NS_DATA, { var: name }, [el("value", NS_DATA, {}, [String(value)])])),
  ]);
}

/**
 * @param {string} node
 * @param {string} itemId
 * @param {object} payload - an xml.js element.
 * @param {Record<string, string>} [options] - publish-options, e.g.
 *   { "pubsub#access_model": "open" }.
 * @returns {object} the <iq type="set"> to send to our own account.
 */
export function publishIq(node, itemId, payload, options = {}) {
  const parts = [el("publish", NS_PUBSUB, { node }, [el("item", NS_PUBSUB, { id: itemId }, [payload])])];
  if (Object.keys(options).length) {
    parts.push(el("publish-options", NS_PUBSUB, {}, [submitForm(`${NS_PUBSUB}#publish-options`, options)]));
  }
  return el("iq", NS_CLIENT, { type: "set" }, [el("pubsub", NS_PUBSUB, {}, parts)]);
}

/** @returns {object} an <iq type="set"> reconfiguring one of our nodes. */
export function configureIq(node, options) {
  return el("iq", NS_CLIENT, { type: "set" }, [
    el("pubsub", NS_PUBSUB_OWNER, {}, [el("configure", NS_PUBSUB_OWNER, { node }, [submitForm(`${NS_PUBSUB}#node_config`, options)])]),
  ]);
}

/**
 * @param {string|null} jid - whose node to read; null for our own.
 * @param {string} node
 * @param {string} [itemId] - one item, or all of them if left out.
 * @returns {object} an <iq type="get">.
 */
export function itemsIq(jid, node, itemId) {
  const items = el("items", NS_PUBSUB, { node }, itemId === undefined ? [] : [el("item", NS_PUBSUB, { id: itemId })]);
  return el("iq", NS_CLIENT, jid ? { type: "get", to: jid } : { type: "get" }, [el("pubsub", NS_PUBSUB, {}, [items])]);
}

// --- replies ---

/**
 * @param {object} reply - an <iq> reply.
 * @returns {{ type: string|null, condition: string|null, pubsubCondition: string|null, text: string|null }|null}
 *   null when it isn't an error.
 */
export function parseError(reply) {
  if (reply?.attributes?.type !== "error") {
    return null;
  }
  const error = reply.children.find((c) => typeof c !== "string" && c.name === "error");
  const elements = error ? error.children.filter((c) => typeof c !== "string") : [];
  const condition = elements.find((c) => c.ns === NS_STANZAS && c.name !== "text");
  const pubsub = elements.find((c) => c.ns === NS_PUBSUB_ERRORS);
  const text = elements.find((c) => c.ns === NS_STANZAS && c.name === "text");
  return {
    type: error?.attributes.type ?? null,
    condition: condition?.name ?? null,
    pubsubCondition: pubsub?.name ?? null,
    text: text ? text.children.filter((c) => typeof c === "string").join("") : null,
  };
}

/**
 * The items in an items reply or a pubsub#event notification.
 *
 * @param {object} items - the <items> element.
 * @returns {{ id: string|null, payload: object|null }[]}
 */
export function parseItems(items) {
  return children(items, items.ns, "item").map((item) => ({
    id: item.attributes.id ?? null,
    payload: item.children.find((c) => typeof c !== "string") ?? null,
  }));
}

/**
 * A PEP notification (docs/TASKS.md 3.6): a <message> carrying a
 * pubsub#event with items.
 *
 * @param {object} message - the <message> element.
 * @returns {{ from: string|null, node: string, items: { id: string|null, payload: object|null }[] }|null}
 *   null if the message isn't a pubsub event with items.
 */
export function parseEvent(message) {
  const event = message.children.find((c) => typeof c !== "string" && c.ns === NS_PUBSUB_EVENT && c.name === "event");
  const items = event ? onlyChild(event, NS_PUBSUB_EVENT, "items") : null;
  if (!items || typeof items.attributes.node !== "string") {
    return null;
  }
  return { from: message.attributes.from ?? null, node: items.attributes.node, items: parseItems(items) };
}

// --- requests ---

/**
 * @param {(iq: object) => Promise<object>} sendIq - sends an <iq> element
 *   and resolves with the reply element (result or error).
 */
export function createPep(sendIq) {
  async function request(iq) {
    const reply = await sendIq(iq);
    const error = parseError(reply);
    if (error) {
      throw new PepError(error);
    }
    return reply;
  }

  return {
    /**
     * Publishes one item to one of our nodes, reconfiguring the node once
     * if its settings conflict with `options`.
     */
    async publish(node, itemId, payload, options = {}) {
      try {
        await request(publishIq(node, itemId, payload, options));
      } catch (e) {
        if (!(e instanceof PepError) || e.pubsubCondition !== "precondition-not-met" || !Object.keys(options).length) {
          throw e;
        }
        await request(configureIq(node, options));
        await request(publishIq(node, itemId, payload, options));
      }
    },

    /**
     * Reads items from someone's node (ours if jid is null).
     *
     * @returns {Promise<{ id: string|null, payload: object|null }[]>} an
     *   empty list if the node or item doesn't exist.
     */
    async fetchItems(jid, node, itemId) {
      let reply;
      try {
        reply = await request(itemsIq(jid, node, itemId));
      } catch (e) {
        if (e instanceof PepError && e.condition === "item-not-found") {
          return [];
        }
        throw e;
      }
      const pubsub = reply.children.find((c) => typeof c !== "string" && c.ns === NS_PUBSUB && c.name === "pubsub");
      const items = pubsub ? onlyChild(pubsub, NS_PUBSUB, "items") : null;
      return items ? parseItems(items) : [];
    },
  };
}
