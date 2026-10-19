/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Names for chat contacts from the address book: reading address book
 * cards (their vCards, as Thunderbird's contacts API gives them) and
 * matching chat addresses against them.
 *
 * A chat address whose user part is a phone number (Cheogram's
 * +15551234567@cheogram.com, Quicksy's) matches the cards' phone numbers,
 * written in any format; a number without a country code counts as +1 when
 * it has 10 digits. Any other address matches the cards' xmpp: chat
 * addresses (IMPP), and failing that their email addresses. When the
 * matching cards give different names, there is no name: never a guess.
 */

/** Unfolds a vCard and splits it into { name, params, value } lines. */
export function parseVCard(text) {
  const lines = String(text ?? "").replace(/\r\n?/g, "\n").replace(/\n[ \t]/g, "").split("\n");
  const props = [];
  for (const line of lines) {
    const colon = findUnquoted(line, ":");
    if (colon < 0) {
      continue;
    }
    const [head, ...paramParts] = splitUnquoted(line.slice(0, colon), ";");
    const name = head.replace(/^.*\./, "").toUpperCase();
    const params = {};
    for (const part of paramParts) {
      const eq = part.indexOf("=");
      const key = (eq < 0 ? "TYPE" : part.slice(0, eq)).toUpperCase();
      params[key] = (eq < 0 ? part : part.slice(eq + 1)).replace(/^"|"$/g, "");
    }
    props.push({ name, params, value: line.slice(colon + 1) });
  }
  return props;
}

function findUnquoted(text, char) {
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '"') {
      quoted = !quoted;
    } else if (text[i] === char && !quoted) {
      return i;
    }
  }
  return -1;
}

function splitUnquoted(text, char) {
  const parts = [];
  let rest = text;
  for (let i = findUnquoted(rest, char); i >= 0; i = findUnquoted(rest, char)) {
    parts.push(rest.slice(0, i));
    rest = rest.slice(i + 1);
  }
  parts.push(rest);
  return parts;
}

/** A vCard text value's escapes undone. */
function unescapeText(value) {
  return value.replace(/\\([\\,;nN])/g, (_, c) => (c === "n" || c === "N" ? "\n" : c));
}

/** Splits a structured value (N) at its unescaped semicolons. */
function splitStructured(value) {
  return value.split(/(?<!\\);/).map(unescapeText);
}

const tidy = (s) => s.replace(/\s+/g, " ").trim();

/**
 * What a card offers for matching: its name (FN, else the name parts,
 * else the organization), phone numbers in +E.164, and lowercase xmpp: and
 * email addresses.
 */
export function readCard(vCard) {
  const props = parseVCard(vCard);
  const first = (name) => props.find((p) => p.name === name);
  let name = tidy(unescapeText(first("FN")?.value ?? ""));
  if (!name && first("N")) {
    const [family = "", given = "", additional = "", prefix = "", suffix = ""] = splitStructured(first("N").value);
    name = tidy([prefix, given, additional, family, suffix].join(" "));
  }
  if (!name && first("ORG")) {
    name = tidy(splitStructured(first("ORG").value)[0] ?? "");
  }
  const phones = props.filter((p) => p.name === "TEL").map((p) => phoneNumber(p.value)).filter(Boolean);
  const xmpp = props.filter((p) => p.name === "IMPP" || p.name === "X-JABBER")
    .map((p) => chatAddress(unescapeText(p.value))).filter(Boolean);
  const emails = props.filter((p) => p.name === "EMAIL").map((p) => bareAddress(unescapeText(p.value))).filter(Boolean);
  return { name, phones: [...new Set(phones)], xmpp: [...new Set(xmpp)], emails: [...new Set(emails)] };
}

/**
 * A phone number as +E.164, or null when it can't be told. Takes any
 * format: "tel:" links, spaces, dashes, dots, brackets, an extension at the
 * end. "00" starts an international number; 10 digits, or 11 starting with
 * 1, are North American (+1). Other numbers without a country code can't
 * be placed, so they don't match.
 */
export function phoneNumber(value) {
  let text = String(value ?? "").trim().replace(/^tel:/i, "");
  // An extension: ";ext=12", "x12", "ext. 12", ",12" (a pause, then digits).
  text = text.replace(/(;|,|\s*(?:ext\.?|x)\s*\d).*$/i, "");
  if (/[a-z]/i.test(text)) {
    return null;
  }
  const plus = text.startsWith("+");
  let digits = text.replace(/\D/g, "");
  if (!plus && digits.startsWith("00")) {
    digits = digits.slice(2);
  } else if (!plus) {
    if (digits.length === 10 && /^[2-9]/.test(digits)) {
      digits = `1${digits}`;
    } else if (!(digits.length === 11 && digits.startsWith("1"))) {
      return null;
    }
  }
  return digits.length >= 7 && digits.length <= 15 ? `+${digits}` : null;
}

/** The phone number a chat address stands for (its user part), or null. */
export function phoneOfChatAddress(jid) {
  const node = String(jid ?? "").split("@")[0];
  return String(jid).includes("@") && /^\+\d{7,15}$/.test(node) ? node : null;
}

/** "xmpp:alice@example.org?message" -> "alice@example.org"; else null. */
function chatAddress(value) {
  const match = /^xmpp:(?:\/\/[^/]*\/)?([^?#]+)/i.exec(value.trim());
  return match ? bareAddress(decodeURIComponentSafe(match[1])) : null;
}

function decodeURIComponentSafe(text) {
  try {
    return decodeURIComponent(text);
  } catch {
    return text;
  }
}

/** A lowercase bare address, or null when it isn't one. */
function bareAddress(value) {
  const address = value.trim().replace(/^mailto:/i, "").split("/")[0].toLowerCase();
  return /^[^@\s]+@[^@\s]+$/.test(address) ? address : null;
}

/** Names that are only a number or an address are no names. */
const isRealName = (name) => /\p{L}/u.test(name) && !/^[^@\s]+@[^@\s]+$/.test(name);

/**
 * An index of the cards (vCard texts) by phone number, xmpp: address and
 * email address, each to the names found under it.
 */
export function indexCards(vCards) {
  const index = { phones: new Map(), xmpp: new Map(), emails: new Map(), cards: 0 };
  const add = (map, key, name) => {
    if (!map.has(key)) {
      map.set(key, []);
    }
    map.get(key).push(name);
  };
  for (const vCard of vCards) {
    const card = readCard(vCard);
    if (!isRealName(card.name)) {
      continue;
    }
    index.cards++;
    for (const phone of card.phones) {
      add(index.phones, phone, card.name);
    }
    for (const address of card.xmpp) {
      add(index.xmpp, address, card.name);
    }
    for (const address of card.emails) {
      add(index.emails, address, card.name);
    }
  }
  return index;
}

/** One name from a list, or null when the list gives different ones. */
function oneName(names) {
  const distinct = new Map();
  for (const name of names) {
    distinct.set(name.toLocaleLowerCase(), distinct.get(name.toLocaleLowerCase()) ?? name);
  }
  return distinct.size === 1 ? [...distinct.values()][0] : null;
}

/**
 * The address book's name for a chat address:
 *   { name, by: "phone"|"xmpp"|"email" }   one name found
 *   { name: null, by, names }              cards with different names
 *   { name: null, by: null }               no card
 */
export function nameFor(index, jid) {
  const address = String(jid ?? "").toLowerCase();
  const phone = phoneOfChatAddress(address);
  const tiers = phone ? [["phone", index.phones, phone]] : [["xmpp", index.xmpp, address], ["email", index.emails, address]];
  for (const [by, map, key] of tiers) {
    const names = map.get(key);
    if (names?.length) {
      const name = oneName(names);
      return name ? { name, by } : { name: null, by, names: [...new Set(names)] };
    }
  }
  return { name: null, by: null };
}
