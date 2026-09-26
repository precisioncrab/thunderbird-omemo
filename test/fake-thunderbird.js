/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * A stand-in for the parts of Thunderbird's XMPP code the bridge touches,
 * written from comm-central's chat/protocols/xmpp/xmpp-xml.sys.mjs and
 * xmpp-base.sys.mjs behavior (not copied):
 *   - XMLNode drops attributes with empty values and writes attribute
 *     values unescaped in getXML(); text nodes are escaped.
 *   - Every node with a namespace writes its own xmlns.
 *   - Parsed nodes carry resolved namespaces, and sendStanza's callback gets
 *     the reply with the same id.
 * An account's sendStanza turns each stanza into text with getXML(), parses
 * it strictly (so escaping mistakes fail), hands pubsub iqs to the fake
 * pubsub server, and delivers <message> stanzas to the addressed fake
 * account (asynchronously, with a from attribute, like a server).
 */

import { parseXml, serialize } from "../src/omemo/xml.js";

class TextNode {
  constructor(text) {
    this.text = text;
  }
  get type() {
    return "text";
  }
  getXML() {
    return this.text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
}

export class XMLNode {
  constructor(uri, localName, attrs = {}) {
    this.uri = uri;
    this.localName = localName;
    this.qName = localName;
    this.attributes = {};
    this.children = [];
    for (const name in attrs) {
      if (attrs[name]) {
        this.attributes[name] = attrs[name];
      }
    }
  }
  get type() {
    return "node";
  }
  addChild(node) {
    this.children.push(node);
  }
  addText(text) {
    const last = this.children.at(-1);
    if (last instanceof TextNode) {
      last.text += text;
    } else {
      this.children.push(new TextNode(text));
    }
  }
  getElement(query) {
    if (!query.length) {
      return this;
    }
    for (const child of this.children) {
      if (child.type !== "text" && child.localName === query[0]) {
        const found = child.getElement(query.slice(1));
        if (found) {
          return found;
        }
      }
    }
    return null;
  }
  getChildren(name) {
    return this.children.filter((c) => c.type !== "text" && c.localName === name);
  }
  getXML() {
    const xmlns = this.uri ? ` xmlns="${this.uri}"` : "";
    let attrs = "";
    for (const name in this.attributes) {
      attrs += ` ${name}="${this.attributes[name]}"`; // unescaped, like Thunderbird
    }
    const inner = this.children.map((c) => c.getXML()).join("");
    return `<${this.qName}${xmlns}${attrs}${inner ? `>${inner}</${this.qName}` : "/"}>`;
  }
}

export const Stanza = {
  node(name, ns, attrs, data) {
    const node = new XMLNode(ns, name, attrs ?? {});
    for (const child of data === undefined || data === null ? [] : Array.isArray(data) ? data : [data]) {
      node[typeof child === "string" ? "addText" : "addChild"](child);
    }
    return node;
  },
  iq(type, id, to, data) {
    const attrs = { type };
    if (id) {
      attrs.id = id;
    }
    if (to) {
      attrs.to = to;
    }
    return this.node("iq", null, attrs, data);
  },
  presence(attrs, data) {
    return this.node("presence", null, attrs, data);
  },
};

/** An XMLNode tree as the parser would build it from text: resolved namespaces. */
export function parseToXmlNode(text) {
  const build = (el) => {
    const node = new XMLNode(el.ns, el.name, el.attributes);
    for (const c of el.children) {
      if (typeof c === "string") {
        node.addText(c);
      } else {
        node.addChild(build(c));
      }
    }
    return node;
  };
  return build(parseXml(text));
}

/**
 * Fake xmpp-base prototypes and accounts wired to a fake pubsub server.
 *
 * @param {ReturnType<import("./fake-pep.js").createFakePepServer>} server
 */
export function createFakeThunderbird(server) {
  const calls = [];
  const network = new Map(); // bare jid -> account
  const bareOf = (jid) => String(jid).split("/")[0].toLowerCase();
  // Like jsProtoHelper's GenericConversationPrototype, which XMPP
  // conversations inherit writeMessage and notifyObservers from.
  const GenericConversationPrototype = {
    writeMessage(who, text, flags) {
      this.shown.push({ who, text, flags });
    },
    notifyObservers(subject, topic) {
      this.notifications.push(topic);
    },
  };
  const XMPPConversationPrototype = Object.create(GenericConversationPrototype);
  XMPPConversationPrototype.dispatchMessage = function (msg) {
    calls.push(["dispatchMessage", this.to, msg]);
  };
  /** What Thunderbird's own onMessageStanza would show: the first <body>'s text. */
  const bodyOf = (stanza) => {
    try {
      const b = stanza.getElement(["body"]);
      return b ? b.children.map((c) => c.text ?? "").join("") : null;
    } catch {
      return null; // a deliberately broken test stanza
    }
  };
  const XMPPAccountPrototype = {
    onConnection() {
      calls.push(["onConnection", this.name]);
    },
    _disconnect() {
      calls.push(["_disconnect", this.name]);
    },
    onIQStanza(stanza) {
      calls.push(["onIQStanza", stanza.getXML()]);
    },
    onMessageStanza(stanza) {
      calls.push(["onMessageStanza", stanza.getXML()]);
      // Like Thunderbird: a carbon is unwrapped; a sent one (our own message
      // from another device) is shown as outgoing in the conversation with
      // its addressee, through _displaySentMsg's synchronous writeMessage.
      let message = stanza;
      let isSent = false;
      let carbon = null;
      try {
        carbon = stanza.getElement(["sent"]) ?? stanza.getElement(["received"]);
      } catch {
        // a deliberately broken test stanza
      }
      if (carbon?.uri === "urn:xmpp:carbons:2") {
        isSent = carbon.localName === "sent";
        message = carbon.getElement(["forwarded", "message"]) ?? stanza;
      }
      const body = bodyOf(message);
      this.received.push({ from: stanza.attributes.from, body, xml: stanza.getXML() });
      // A message with a body goes to its conversation.
      const convJid = isSent ? message.attributes.to : message.attributes.from;
      const conversation = body !== null && this._conv.get(bareOf(convJid ?? ""));
      if (conversation && isSent) {
        conversation.writeMessage(this._connection._jid.jid, body, { outgoing: true, _alias: "Me" });
      } else if (conversation) {
        conversation.writeMessage(message.attributes.from, body, { incoming: true });
      }
    },
    sendStanza(stanza, callback) {
      const xml = stanza.getXML();
      parseXml(xml); // must be well-formed, as a server would insist
      this.sent.push(xml);
      if (stanza.qName === "iq" && /jabber\.org\/protocol\/pubsub/.test(xml)) {
        server.connect(this.name)(parseXml(xml)).then((reply) => {
          callback?.(parseToXmlNode(serialize(reply)));
        });
      }
      if (stanza.qName === "message") {
        const tree = parseXml(xml);
        tree.attributes.from = `${this.name}/Thunderbird`;
        const to = network.get(bareOf(tree.attributes.to));
        if (to) {
          const text = serialize(tree);
          setImmediate(() => to.onMessageStanza(parseToXmlNode(text)));
        }
      }
      return stanza.attributes.id ?? "id";
    },
  };
  const SupportedFeatures = ["http://jabber.org/protocol/disco#info", "http://jabber.org/protocol/muc"];

  function makeAccount(jid) {
    const [node, domain] = jid.split("@");
    const account = Object.create(XMPPAccountPrototype);
    Object.assign(account, {
      name: jid,
      _jid: { node, domain, resource: "Thunderbird" },
      _connection: { _jid: { jid: `${jid}/Thunderbird` } },
      sent: [],
      received: [],
      _conv: new Map(),
    });
    network.set(bareOf(jid), account);
    return account;
  }

  let nextConversationId = 1;
  /** A 1:1 conversation of `account` with `to`, recording what it displays. */
  function makeConversation(account, to) {
    const conversation = Object.create(XMPPConversationPrototype);
    Object.assign(conversation, {
      _account: account,
      account: { alias: "", statusInfo: { displayName: "Me" } },
      to,
      name: bareOf(to),
      id: nextConversationId++,
      shown: [],
      notifications: [],
    });
    account._conv.set(bareOf(to), conversation);
    return conversation;
  }

  return {
    calls,
    xmppBase: { XMPPConversationPrototype, XMPPAccountPrototype },
    Stanza,
    SupportedFeatures,
    makeAccount,
    makeConversation,
  };
}
