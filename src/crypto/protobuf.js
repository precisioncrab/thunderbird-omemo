/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Minimal protobuf codec for OMEMO's message structures (docs/TASKS.md 2.5),
 * with no dependency. It handles only what OMEMO uses: uint32 varints,
 * bytes, and nested messages.
 *
 * Encoding writes fields in field-number order and always writes required
 * fields, even when zero (proto2 semantics). That matches the reference
 * implementations byte for byte (test/protobuf.test.js).
 *
 * Decoding is strict, since these bytes come from the network: it throws on
 * truncated input, field number 0, missing required fields, a known field
 * sent with the wrong wire type or more than once, and uint32 values that
 * don't fit. Unknown fields are skipped, as protobuf requires.
 *
 * This file only knows the field layouts. The framing around them (oldmemo's
 * 0x33 version byte and appended MAC, which bytes the MAC covers) belongs to
 * the ratchet's per-namespace profile (docs/TASKS.md 2.7).
 */

/**
 * @typedef {object} Field
 * @property {string} name - property name in JS objects.
 * @property {number} number - protobuf field number.
 * @property {"uint32"|"bytes"|Schema} type - a Schema means a nested message.
 * @property {boolean} [required]
 *
 * @typedef {object} Schema
 * @property {string} name
 * @property {Field[]} fields - in field-number order.
 */

const WIRE_VARINT = 0;
const WIRE_FIXED64 = 1;
const WIRE_LENGTH_DELIMITED = 2;
const WIRE_FIXED32 = 5;

const MAX_UINT32 = 0xffffffff;

function schema(name, fields) {
  return Object.freeze({
    name,
    fields: Object.freeze([...fields].sort((a, b) => a.number - b.number).map(Object.freeze)),
  });
}

/**
 * twomemo (`urn:xmpp:omemo:2`) message structures, from XEP-0384's schema.
 */
const twomemoMessage = schema("OMEMOMessage", [
  { name: "n", number: 1, type: "uint32", required: true },
  { name: "pn", number: 2, type: "uint32", required: true },
  { name: "dhPub", number: 3, type: "bytes", required: true },
  { name: "ciphertext", number: 4, type: "bytes" },
]);
const twomemoAuthenticatedMessage = schema("OMEMOAuthenticatedMessage", [
  { name: "mac", number: 1, type: "bytes", required: true },
  { name: "message", number: 2, type: "bytes", required: true },
]);
export const twomemo = Object.freeze({
  OMEMOMessage: twomemoMessage,
  OMEMOAuthenticatedMessage: twomemoAuthenticatedMessage,
  OMEMOKeyExchange: schema("OMEMOKeyExchange", [
    { name: "preKeyId", number: 1, type: "uint32", required: true },
    { name: "signedPreKeyId", number: 2, type: "uint32", required: true },
    { name: "identityKey", number: 3, type: "bytes", required: true },
    { name: "ephemeralKey", number: 4, type: "bytes", required: true },
    { name: "message", number: 5, type: twomemoAuthenticatedMessage, required: true },
  ]),
});

/**
 * oldmemo (`eu.siacs.conversations.axolotl`) message structures: libsignal's
 * SignalMessage (WhisperMessage) and PreKeySignalMessage
 * (PreKeyWhisperMessage). Field names follow the twomemo ones so the ratchet
 * code can treat both alike; libsignal's names are in the comments. Public
 * keys in these messages carry the 0x05 type byte (keys.encodePublicKey).
 */
export const oldmemo = Object.freeze({
  OMEMOMessage: schema("OMEMOMessage", [
    { name: "dhPub", number: 1, type: "bytes", required: true }, // ratchetKey
    { name: "n", number: 2, type: "uint32", required: true }, // counter
    { name: "pn", number: 3, type: "uint32", required: true }, // previousCounter
    { name: "ciphertext", number: 4, type: "bytes" },
  ]),
  OMEMOKeyExchange: schema("OMEMOKeyExchange", [
    { name: "preKeyId", number: 1, type: "uint32", required: true },
    { name: "ephemeralKey", number: 2, type: "bytes", required: true }, // baseKey
    { name: "identityKey", number: 3, type: "bytes", required: true },
    // The framed ratchet message: 0x33 || OMEMOMessage || 8-byte MAC.
    { name: "message", number: 4, type: "bytes", required: true },
    // libsignal clients send their registration id; OMEMO doesn't use it.
    { name: "registrationId", number: 5, type: "uint32" },
    { name: "signedPreKeyId", number: 6, type: "uint32", required: true },
  ]),
});

/**
 * @param {Schema} schema
 * @param {object} value - properties named after the schema's fields;
 *   optional fields may be undefined or null.
 * @returns {Uint8Array}
 * @throws if a required field is missing or a value has the wrong type.
 */
export function encode(schema, value) {
  const out = [];
  for (const field of schema.fields) {
    const v = value[field.name];
    if (v === undefined || v === null) {
      if (field.required) {
        throw new Error(`${schema.name}.${field.name} is required.`);
      }
      continue;
    }
    if (field.type === "uint32") {
      if (!Number.isInteger(v) || v < 0 || v > MAX_UINT32) {
        throw new Error(`${schema.name}.${field.name} must be a uint32; got ${v}.`);
      }
      writeVarint(out, (field.number << 3) | WIRE_VARINT);
      writeVarint(out, v);
      continue;
    }
    let bytes;
    if (field.type === "bytes") {
      if (!(v instanceof Uint8Array)) {
        throw new Error(`${schema.name}.${field.name} must be a Uint8Array.`);
      }
      bytes = v;
    } else {
      bytes = encode(field.type, v);
    }
    writeVarint(out, (field.number << 3) | WIRE_LENGTH_DELIMITED);
    writeVarint(out, bytes.length);
    for (const b of bytes) {
      out.push(b);
    }
  }
  return Uint8Array.from(out);
}

/**
 * @param {Schema} schema
 * @param {Uint8Array} bytes
 * @returns {object} one property per field present; absent optional fields
 *   are left out. Byte fields are fresh copies.
 * @throws on malformed input, see the file header.
 */
export function decode(schema, bytes) {
  const byNumber = new Map(schema.fields.map((f) => [f.number, f]));
  const result = {};
  const reader = { bytes, pos: 0 };

  while (reader.pos < bytes.length) {
    const tag = readVarint(reader);
    const number = Math.floor(tag / 8);
    const wireType = tag % 8;
    if (number === 0) {
      throw new Error("Invalid protobuf field number 0.");
    }
    const field = byNumber.get(number);

    if (!field) {
      skipField(reader, wireType);
      continue;
    }
    if (field.name in result) {
      throw new Error(`${schema.name}.${field.name} appears more than once.`);
    }
    const expected = field.type === "uint32" ? WIRE_VARINT : WIRE_LENGTH_DELIMITED;
    if (wireType !== expected) {
      throw new Error(`${schema.name}.${field.name} has wire type ${wireType}; expected ${expected}.`);
    }

    if (field.type === "uint32") {
      const v = readVarint(reader);
      if (v > MAX_UINT32) {
        throw new Error(`${schema.name}.${field.name} does not fit in a uint32.`);
      }
      result[field.name] = v;
    } else {
      const chunk = readLengthDelimited(reader);
      result[field.name] = field.type === "bytes" ? chunk.slice() : decode(field.type, chunk);
    }
  }

  for (const field of schema.fields) {
    if (field.required && !(field.name in result)) {
      throw new Error(`${schema.name}.${field.name} is required but missing.`);
    }
  }
  return result;
}

// --- internals ---

function writeVarint(out, value) {
  let v = value >>> 0;
  while (v >= 0x80) {
    out.push((v & 0x7f) | 0x80);
    v >>>= 7;
  }
  out.push(v);
}

/**
 * Reads an unsigned varint of up to 10 bytes (64 bits). Values above 2^53
 * lose precision, which is fine: callers only compare them against the
 * uint32 range or discard them.
 */
function readVarint(reader) {
  let value = 0;
  for (let i = 0; i < 10; i++) {
    if (reader.pos >= reader.bytes.length) {
      throw new Error("Truncated protobuf varint.");
    }
    const b = reader.bytes[reader.pos++];
    value += (b & 0x7f) * 2 ** (7 * i);
    if ((b & 0x80) === 0) {
      return value;
    }
  }
  throw new Error("Protobuf varint longer than 10 bytes.");
}

function readLengthDelimited(reader) {
  const length = readVarint(reader);
  if (length > reader.bytes.length - reader.pos) {
    throw new Error("Truncated protobuf length-delimited field.");
  }
  const chunk = reader.bytes.subarray(reader.pos, reader.pos + length);
  reader.pos += length;
  return chunk;
}

function skipField(reader, wireType) {
  switch (wireType) {
    case WIRE_VARINT:
      readVarint(reader);
      return;
    case WIRE_FIXED64:
      skipBytes(reader, 8);
      return;
    case WIRE_LENGTH_DELIMITED:
      readLengthDelimited(reader);
      return;
    case WIRE_FIXED32:
      skipBytes(reader, 4);
      return;
    default:
      // 3 and 4 are the long-deprecated groups; 6 and 7 are invalid.
      throw new Error(`Unsupported protobuf wire type ${wireType}.`);
  }
}

function skipBytes(reader, n) {
  if (n > reader.bytes.length - reader.pos) {
    throw new Error("Truncated protobuf fixed-width field.");
  }
  reader.pos += n;
}
