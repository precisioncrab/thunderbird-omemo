/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * An in-memory pubsub service for tests: enough of XEP-0060/XEP-0163 for
 * OMEMO. Each account's nodes live under its bare JID. Publish-options
 * that conflict with an existing node's configuration fail with
 * precondition-not-met, as real servers do; a configure request fixes it.
 * Every request and reply goes through xml.js serialize/parse, so the
 * stanzas are exercised as text.
 */

import { el, parseXml, serialize, children, onlyChild } from "../src/omemo/xml.js";
import { NS_PUBSUB, NS_PUBSUB_OWNER, NS_PUBSUB_ERRORS, NS_PUBSUB_EVENT } from "../src/omemo/pep.js";

const NS_STANZAS = "urn:ietf:params:xml:ns:xmpp-stanzas";
const NS_DATA = "jabber:x:data";
const NS_CLIENT = "jabber:client";

export function createFakePepServer() {
  const accounts = new Map(); // bare jid -> Map(node -> { config, items: Map(id -> payload xml) })
  const log = [];
  const subscribers = new Map(); // bare jid -> (message element) => void, for notifications

  const nodesOf = (jid) => {
    if (!accounts.has(jid)) {
      accounts.set(jid, new Map());
    }
    return accounts.get(jid);
  };
  const formValues = (form) => {
    const out = {};
    for (const field of form ? children(form, NS_DATA, "field") : []) {
      if (field.attributes.var !== "FORM_TYPE") {
        const value = onlyChild(field, NS_DATA, "value");
        out[field.attributes.var] = value ? value.children.join("") : "";
      }
    }
    return out;
  };
  const error = (condition, pubsubCondition) => el("iq", NS_CLIENT, { type: "error" }, [
    el("error", NS_CLIENT, { type: "cancel" }, [
      el(condition, NS_STANZAS),
      ...(pubsubCondition ? [el(pubsubCondition, NS_PUBSUB_ERRORS)] : []),
    ]),
  ]);
  const result = (content = []) => el("iq", NS_CLIENT, { type: "result" }, content);

  function handle(from, iq) {
    const type = iq.attributes.type;
    const owner = onlyChild(iq, NS_PUBSUB_OWNER, "pubsub");
    const pubsub = onlyChild(iq, NS_PUBSUB, "pubsub");
    if (type === "set" && owner) {
      const configure = onlyChild(owner, NS_PUBSUB_OWNER, "configure");
      const node = nodesOf(from).get(configure.attributes.node);
      if (!node) {
        return error("item-not-found");
      }
      Object.assign(node.config, formValues(onlyChild(configure, NS_DATA, "x")));
      return result();
    }
    if (type === "set" && pubsub) {
      const publish = onlyChild(pubsub, NS_PUBSUB, "publish");
      const options = formValues(onlyChild(onlyChild(pubsub, NS_PUBSUB, "publish-options") ?? { children: [] }, NS_DATA, "x"));
      const nodes = nodesOf(from);
      const name = publish.attributes.node;
      let node = nodes.get(name);
      if (!node) {
        node = { config: { "pubsub#access_model": "presence", "pubsub#max_items": "1", ...options }, items: new Map() };
        nodes.set(name, node);
      } else if (Object.entries(options).some(([k, v]) => node.config[k] !== v)) {
        return error("conflict", "precondition-not-met");
      }
      const item = onlyChild(publish, NS_PUBSUB, "item");
      node.items.delete(item.attributes.id);
      node.items.set(item.attributes.id, serialize(item.children.find((c) => typeof c !== "string")));
      const max = node.config["pubsub#max_items"] === "max" ? Infinity : Number(node.config["pubsub#max_items"]);
      while (node.items.size > max) {
        node.items.delete(node.items.keys().next().value);
      }
      // Notify everyone who listens to this account (a stand-in for +notify).
      for (const [jid, deliver] of subscribers) {
        deliver(el("message", NS_CLIENT, { from, to: jid, type: "headline" }, [
          el("event", NS_PUBSUB_EVENT, {}, [el("items", NS_PUBSUB_EVENT, { node: name }, [
            el("item", NS_PUBSUB_EVENT, { id: item.attributes.id }, [parseXml(node.items.get(item.attributes.id))]),
          ])]),
        ]));
      }
      return result();
    }
    if (type === "get" && pubsub) {
      const target = iq.attributes.to ? iq.attributes.to.split("/")[0].toLowerCase() : from;
      const items = onlyChild(pubsub, NS_PUBSUB, "items");
      const node = nodesOf(target).get(items.attributes.node);
      if (!node) {
        return error("item-not-found");
      }
      if (target !== from && node.config["pubsub#access_model"] !== "open") {
        return error("forbidden");
      }
      const wanted = children(items, NS_PUBSUB, "item").map((i) => i.attributes.id);
      const picked = [...node.items].filter(([id]) => !wanted.length || wanted.includes(id));
      if (wanted.length && !picked.length) {
        return error("item-not-found");
      }
      return result([el("pubsub", NS_PUBSUB, {}, [el("items", NS_PUBSUB, { node: items.attributes.node },
        picked.map(([id, xml]) => el("item", NS_PUBSUB, { id }, [parseXml(xml)])))])]);
    }
    return error("feature-not-implemented");
  }

  return {
    accounts,
    log,
    /** A sendIq for one account, round-tripping everything through text. */
    connect(jid) {
      const bare = jid.toLowerCase();
      return async (iq) => {
        const text = serialize(iq);
        log.push({ from: bare, iq: text });
        const reply = handle(bare, parseXml(text));
        return parseXml(serialize(reply));
      };
    },
    /** Delivers notifications for every publish to `deliver`. */
    subscribe(jid, deliver) {
      subscribers.set(jid.toLowerCase(), deliver);
    },
    /** Sets a node's configuration directly (e.g. as another client left it). */
    configure(jid, node, config) {
      const nodes = nodesOf(jid.toLowerCase());
      if (!nodes.has(node)) {
        nodes.set(node, { config: {}, items: new Map() });
      }
      Object.assign(nodes.get(node).config, config);
    },
    /** Puts an item on a node directly, bypassing publish-options. */
    put(jid, node, id, payload, config = { "pubsub#access_model": "open", "pubsub#max_items": "max" }) {
      const nodes = nodesOf(jid.toLowerCase());
      if (!nodes.has(node)) {
        nodes.set(node, { config, items: new Map() });
      }
      nodes.get(node).items.set(id, serialize(payload));
    },
  };
}
