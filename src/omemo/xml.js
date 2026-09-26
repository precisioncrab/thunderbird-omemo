/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * A small XML toolkit for the stanza content OMEMO handles: the XEP-0420
 * envelope, device lists, bundles and <encrypted> elements.
 *
 * DOMParser exists neither in Node nor in the Experiment's module scope, so
 * this carries its own parser for the XML subset stanzas allow: elements,
 * attributes, namespaces, text, CDATA and the predefined and numeric
 * entities. Comments, processing instructions and DTDs are refused, as
 * XMPP forbids them (RFC 6120 section 11.1), and so is nesting deeper than
 * MAX_DEPTH. Elements are plain objects ({ name, ns, attributes, children },
 * children being elements or strings); el() builds them and serialize()
 * writes them out. The Experiment converts between these and Thunderbird's
 * own XMLNode objects.
 */

const XML_NS = "http://www.w3.org/XML/1998/namespace";

export const MAX_DEPTH = 32;

// Characters XML 1.0 allows; everything else can't appear even escaped.
export const INVALID_XML_CHAR = /[^\t\n\r\u0020-\uD7FF\uE000-\uFFFD\u{10000}-\u{10FFFF}]/u;

// --- building ---

/**
 * @param {string} name - local name.
 * @param {string|null} ns
 * @param {Record<string, string|number>} [attributes] - written in this order.
 * @param {(XmlElement|string)[]} [children]
 * @returns {XmlElement}
 */
export function el(name, ns, attributes = {}, children = []) {
  const attrs = {};
  for (const [k, v] of Object.entries(attributes)) {
    if (v !== undefined && v !== null) {
      attrs[k] = String(v);
    }
  }
  return { name, ns, attributes: attrs, children };
}

/**
 * Writes an element as XML text. A namespace is declared (xmlns) wherever
 * it differs from the parent's; childless elements self-close.
 *
 * @param {XmlElement} element
 * @param {string|null} [parentNs]
 * @returns {string}
 */
export function serialize(element, parentNs = null) {
  let out = `<${element.name}`;
  if (element.ns !== parentNs) {
    out += ` xmlns="${escapeAttribute(element.ns ?? "")}"`;
  }
  for (const [k, v] of Object.entries(element.attributes)) {
    out += ` ${k}="${escapeAttribute(v)}"`;
  }
  if (!element.children.length) {
    return `${out}/>`;
  }
  out += ">";
  for (const child of element.children) {
    if (typeof child === "string") {
      if (INVALID_XML_CHAR.test(child)) {
        throw new Error("Text contains a character XML doesn't allow.");
      }
      out += escapeText(child);
    } else {
      out += serialize(child, element.ns);
    }
  }
  return `${out}</${element.name}>`;
}

// --- serializing ---

export function escapeText(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\r/g, "&#xD;");
}

export function escapeAttribute(s) {
  return escapeText(s).replace(/"/g, "&quot;").replace(/\t/g, "&#x9;").replace(/\n/g, "&#xA;");
}

// --- parsing ---

/**
 * @typedef {object} XmlElement
 * @property {string} name - local name.
 * @property {string|null} ns - resolved namespace.
 * @property {Record<string, string>} attributes - by name as written,
 *   without namespace declarations.
 * @property {(XmlElement|string)[]} children
 */

/**
 * Parses one XML document (the subset described in the file header).
 *
 * @param {string} text
 * @returns {XmlElement} the root element.
 * @throws on anything outside the subset or not well-formed.
 */
export function parseXml(text) {
  if (INVALID_XML_CHAR.test(text)) {
    throw new Error("XML contains a character XML doesn't allow.");
  }
  const p = { s: text.replace(/\r\n?/g, "\n"), i: 0 };
  // An XML declaration is allowed at the very start, nothing else like it.
  const decl = /^<\?xml\s[^?]*\?>/.exec(p.s);
  if (decl) {
    p.i = decl[0].length;
  }
  skipSpace(p);
  if (p.s[p.i] !== "<") {
    throw new Error("XML must start with an element.");
  }
  refuseMarkupDeclarations(p);
  const root = parseElement(p, Object.assign(Object.create(null), { "": null, xml: XML_NS }), 0);
  skipSpace(p);
  if (p.i !== p.s.length) {
    throw new Error("Unexpected content after the root element.");
  }
  return root;
}

function parseElement(p, scope, depth) {
  if (depth >= MAX_DEPTH) {
    throw new Error(`XML nests deeper than ${MAX_DEPTH} elements.`);
  }
  p.i++; // "<"
  const rawName = readName(p);
  const raw = [];
  let selfClosing = false;
  for (;;) {
    const hadSpace = skipSpace(p);
    if (p.s.startsWith("/>", p.i)) {
      p.i += 2;
      selfClosing = true;
      break;
    }
    if (p.s[p.i] === ">") {
      p.i++;
      break;
    }
    if (!hadSpace) {
      throw new Error(`Malformed start tag <${rawName}>.`);
    }
    const name = readName(p);
    skipSpace(p);
    expect(p, "=");
    skipSpace(p);
    const quote = p.s[p.i];
    if (quote !== '"' && quote !== "'") {
      throw new Error(`Attribute ${name} needs a quoted value.`);
    }
    const end = p.s.indexOf(quote, p.i + 1);
    if (end < 0) {
      throw new Error("Unterminated attribute value.");
    }
    const value = p.s.slice(p.i + 1, end);
    if (value.includes("<")) {
      throw new Error(`Attribute ${name} contains "<".`);
    }
    p.i = end + 1;
    if (raw.some(([n]) => n === name)) {
      throw new Error(`Attribute ${name} appears twice.`);
    }
    raw.push([name, decodeEntities(value.replace(/[\t\n]/g, " "))]);
  }

  const inner = Object.assign(Object.create(null), scope);
  const attributes = {};
  for (const [name, value] of raw) {
    if (name === "xmlns") {
      inner[""] = value || null;
    } else if (name.startsWith("xmlns:")) {
      const prefix = name.slice(6);
      if (!value || prefix === "xml" || prefix === "xmlns") {
        throw new Error(`Invalid namespace declaration ${name}.`);
      }
      inner[prefix] = value;
    } else {
      attributes[name] = value;
    }
  }
  const [prefix, local] = splitName(rawName);
  if (prefix !== "" && !(prefix in inner)) {
    throw new Error(`Undeclared namespace prefix "${prefix}".`);
  }
  const element = { name: local, ns: inner[prefix] ?? null, attributes, children: [] };
  if (selfClosing) {
    return element;
  }

  for (;;) {
    if (p.i >= p.s.length) {
      throw new Error(`Unclosed element <${rawName}>.`);
    }
    if (p.s.startsWith("</", p.i)) {
      p.i += 2;
      const closing = readName(p);
      skipSpace(p);
      expect(p, ">");
      if (closing !== rawName) {
        throw new Error(`</${closing}> doesn't close <${rawName}>.`);
      }
      return element;
    }
    if (p.s.startsWith("<![CDATA[", p.i)) {
      const end = p.s.indexOf("]]>", p.i + 9);
      if (end < 0) {
        throw new Error("Unterminated CDATA section.");
      }
      element.children.push(p.s.slice(p.i + 9, end));
      p.i = end + 3;
      continue;
    }
    if (p.s[p.i] === "<") {
      refuseMarkupDeclarations(p);
      element.children.push(parseElement(p, inner, depth + 1));
      continue;
    }
    const end = p.s.indexOf("<", p.i);
    const chunk = p.s.slice(p.i, end < 0 ? p.s.length : end);
    if (chunk.includes("]]>")) {
      throw new Error('Text contains "]]>".');
    }
    element.children.push(decodeEntities(chunk));
    p.i += chunk.length;
  }
}

function refuseMarkupDeclarations(p) {
  const next = p.s[p.i + 1];
  if (next === "!" || next === "?") {
    throw new Error("XML comments, processing instructions and DTDs are not allowed in stanzas.");
  }
}

const NAME = /[A-Za-z_\u00C0-\uFFFF][\w.\-:\u00B7-\uFFFF]*/y;

function readName(p) {
  NAME.lastIndex = p.i;
  const m = NAME.exec(p.s);
  if (!m) {
    throw new Error(`Expected an XML name at offset ${p.i}.`);
  }
  p.i += m[0].length;
  return m[0];
}

function splitName(rawName) {
  const parts = rawName.split(":");
  if (parts.length === 1) {
    return ["", rawName];
  }
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new Error(`Invalid qualified name "${rawName}".`);
  }
  return parts;
}

function skipSpace(p) {
  const start = p.i;
  while (p.i < p.s.length && " \t\n".includes(p.s[p.i])) {
    p.i++;
  }
  return p.i > start;
}

function expect(p, ch) {
  if (p.s[p.i] !== ch) {
    throw new Error(`Expected "${ch}" at offset ${p.i}.`);
  }
  p.i++;
}

const PREDEFINED = { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'" };

function decodeEntities(s) {
  let out = "";
  let i = 0;
  for (;;) {
    const amp = s.indexOf("&", i);
    if (amp < 0) {
      return out + s.slice(i);
    }
    const semi = s.indexOf(";", amp);
    if (semi < 0) {
      throw new Error("Unterminated entity reference.");
    }
    out += s.slice(i, amp) + decodeEntity(s.slice(amp + 1, semi));
    i = semi + 1;
  }
}

function decodeEntity(name) {
  if (Object.hasOwn(PREDEFINED, name)) {
    return PREDEFINED[name];
  }
  const m = /^#(?:x([0-9A-Fa-f]{1,6})|([0-9]{1,7}))$/.exec(name);
  if (!m) {
    throw new Error(`Unknown entity &${name};.`);
  }
  const code = m[1] ? parseInt(m[1], 16) : parseInt(m[2], 10);
  const ch = code <= 0x10ffff ? String.fromCodePoint(code) : "";
  if (!ch || INVALID_XML_CHAR.test(ch)) {
    throw new Error(`Character reference &${name}; is not an allowed XML character.`);
  }
  return ch;
}

// --- helpers ---

/** The child elements with this namespace and name. */
export function children(element, ns, name) {
  return element.children.filter((c) => typeof c !== "string" && c.ns === ns && c.name === name);
}

/**
 * The single child with this namespace and name, or null.
 * @throws if there is more than one.
 */

export function onlyChild(element, ns, name) {
  const matches = children(element, ns, name);
  if (matches.length > 1) {
    throw new Error(`More than one <${name}> in <${element.name}>.`);
  }
  return matches[0] ?? null;
}

/** The element's direct text, joined. */
export function textOf(element) {
  return element.children.filter((c) => typeof c === "string").join("");
}
