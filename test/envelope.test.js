/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests for src/crypto/envelope.js (the XEP-0420 envelope twomemo
 * encrypts) and its XML parser, plus one end-to-end twomemo message:
 * envelope, payload and ratchet together.
 */

import test from "node:test";
import assert from "node:assert/strict";
import * as envelope from "../src/crypto/envelope.js";
import * as payload from "../src/crypto/payload.js";
import * as dr from "../src/crypto/double-ratchet.js";
import * as keys from "../src/crypto/keys.js";
import * as x3dh from "../src/crypto/x3dh.js";

const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);

// --- building ---

test("builds the envelope XEP-0384 describes, with padding from the given randomness", () => {
  const draws = [Uint8Array.of(3), Uint8Array.of(0, 1, 63 + 64)];
  const random = (n) => {
    const next = draws.shift();
    assert.equal(next.length, n);
    return next;
  };
  const xml = dec(envelope.buildEnvelope({ body: "Hello World!", from: "romeo@montague.lit" }, { random }));
  assert.equal(xml,
    '<envelope xmlns="urn:xmpp:sce:1"><content><body xmlns="jabber:client">Hello World!</body></content>' +
    '<rpad>AB_</rpad><from jid="romeo@montague.lit"/></envelope>');
  assert.equal(draws.length, 0);
});

test("padding length varies from 0 to 200 characters", () => {
  const zero = dec(envelope.buildEnvelope({ body: "x", from: "a@b" }, { random: () => Uint8Array.of(201) }));
  assert.match(zero, /<rpad><\/rpad>/);
  const lengths = new Set();
  for (let i = 0; i < 50; i++) {
    const xml = dec(envelope.buildEnvelope({ body: "x", from: "a@b" }));
    const rpad = /<rpad>([^<]*)<\/rpad>/.exec(xml)[1];
    assert.ok(rpad.length <= 200);
    assert.match(rpad, /^[A-Za-z0-9_-]*$/);
    lengths.add(rpad.length);
  }
  assert.ok(lengths.size > 10, "lengths should vary");
});

test("the body round-trips exactly: markup characters, quotes, line breaks, non-ASCII", () => {
  for (const body of ["<b>not bold</b> & \"quoted\" 'single' ]]> >", "line 1\r\nline 2\rline 3\n\ttab", "Grüße 👋 𝄞", "", "   "]) {
    const bytes = envelope.buildEnvelope({ body, from: "alice@example.org" });
    assert.deepEqual(envelope.parseEnvelope(bytes, { sender: "alice@example.org/phone" }), {
      body,
      from: "alice@example.org",
      time: null,
    });
  }
});

test("refuses bodies XML can't carry and non-bare from JIDs", () => {
  for (const body of ["nul \u0000", "bell \u0007", "lone surrogate \uD800", "\uFFFE", 42]) {
    assert.throws(() => envelope.buildEnvelope({ body, from: "a@b" }), /characters XML allows/);
  }
  for (const from of ["a@b/res", "", undefined]) {
    assert.throws(() => envelope.buildEnvelope({ body: "x", from }), /bare JID/);
  }
});

// --- parsing envelopes from other clients ---

test("parses the spec's example with whitespace, and extra affixes", () => {
  const xml = `<envelope xmlns='urn:xmpp:sce:1'>
  <content>
    <body xmlns='jabber:client'>
     Hello World!
    </body>
  </content>
  <rpad>...</rpad>
  <time stamp='2004-01-25T05:05:00.000+00:00'/>
  <from jid='romeo@montague.lit'/>
</envelope>`;
  assert.deepEqual(envelope.parseEnvelope(enc(xml), { sender: "Romeo@Montague.lit/orchard" }), {
    body: "\n     Hello World!\n    ",
    from: "romeo@montague.lit",
    time: "2004-01-25T05:05:00.000+00:00",
  });
});

test("parses prefixes, CDATA, entities and an XML declaration", () => {
  const xml =
    "<?xml version='1.0' encoding='UTF-8'?>" +
    '<s:envelope xmlns:s="urn:xmpp:sce:1" xmlns:c="jabber:client"><s:content>' +
    "<c:body>a &lt;&amp;&gt; &#x1F44B;&#33;<![CDATA[<raw> & ]]></c:body>" +
    '<unknown xmlns="urn:example:ext"><deep/></unknown>' +
    "</s:content><s:from jid='alice@example.org'/></s:envelope>";
  assert.equal(envelope.parseEnvelope(enc(xml), { sender: "alice@example.org" }).body, "a <&> 👋!<raw> & ");
});

test("a missing <from> is accepted (it's only recommended); a missing <body> gives null", () => {
  const xml = '<envelope xmlns="urn:xmpp:sce:1"><content><x xmlns="urn:example"/></content><rpad/></envelope>';
  assert.deepEqual(envelope.parseEnvelope(enc(xml), { sender: "a@b" }), { body: null, from: null, time: null });
});

test("rejects a <from> that names someone other than the sender", () => {
  const bytes = envelope.buildEnvelope({ body: "hi", from: "mallory@evil.example" });
  assert.throws(() => envelope.parseEnvelope(bytes, { sender: "alice@example.org" }), /does not match the sender/);
  const noJid = '<envelope xmlns="urn:xmpp:sce:1"><content/><from/></envelope>';
  assert.throws(() => envelope.parseEnvelope(enc(noJid), { sender: "a@b" }), /does not match/);
  assert.throws(() => envelope.parseEnvelope(bytes, {}), /needs the stanza's sender/);
});

test("rejects things that aren't an envelope", () => {
  const cases = {
    "wrong namespace": '<envelope xmlns="urn:xmpp:sce:0"><content/></envelope>',
    "no namespace": "<envelope><content/></envelope>",
    "wrong root": '<content xmlns="urn:xmpp:sce:1"/>',
    "no content": '<envelope xmlns="urn:xmpp:sce:1"><rpad/></envelope>',
    "two contents": '<envelope xmlns="urn:xmpp:sce:1"><content/><content/></envelope>',
    "two froms": '<envelope xmlns="urn:xmpp:sce:1"><content/><from jid="a@b"/><from jid="a@b"/></envelope>',
    "body in the wrong namespace only": '<envelope xmlns="urn:xmpp:sce:1"><content><body>x</body></content></envelope>',
  };
  for (const [what, xml] of Object.entries(cases)) {
    if (what === "body in the wrong namespace only") {
      // Inherits urn:xmpp:sce:1, so it isn't a jabber:client body.
      assert.equal(envelope.parseEnvelope(enc(xml), { sender: "a@b" }).body, null, what);
      continue;
    }
    assert.throws(() => envelope.parseEnvelope(enc(xml), { sender: "a@b" }), undefined, what);
  }
  assert.throws(() => envelope.parseEnvelope(Uint8Array.of(0xc3, 0x28), { sender: "a@b" }), undefined, "invalid UTF-8");
});

// --- the XML parser ---

test("the parser refuses what XMPP forbids and what isn't well-formed", () => {
  const bad = {
    comment: "<a><!-- hi --></a>",
    "processing instruction": "<a><?pi x?></a>",
    doctype: '<!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>',
    "custom entity": "<a>&x;</a>",
    "prototype entity": "<a>&constructor;</a>",
    "unterminated entity": "<a>&amp</a>",
    "bad char ref": "<a>&#0;</a>",
    "char ref out of range": "<a>&#x110000;</a>",
    "mismatched tags": "<a><b></a></b>",
    unclosed: "<a><b></b>",
    "trailing element": "<a/><b/>",
    "trailing text": "<a/>x",
    "leading text": "x<a/>",
    "duplicate attribute": '<a x="1" x="2"/>',
    "unquoted attribute": "<a x=1/>",
    "< in attribute": '<a x="<"/>',
    "no space between attributes": '<a x="1"y="2"/>',
    "undeclared prefix": "<p:a/>",
    "prototype prefix": "<constructor:a/>",
    "double colon": '<a:b:c xmlns:a="x"/>',
    "empty prefix binding": '<a xmlns:p=""/>',
    "raw control char": "<a>\u0001</a>",
    "]]> in text": "<a>]]></a>",
    "unterminated CDATA": "<a><![CDATA[x</a>",
    "unterminated attribute": '<a x="1/>',
    "space before the name": "< a/>",
    "attribute without =": '<a x"1"/>',
    "closing tag without >": "<a></a",
    empty: "",
  };
  for (const [what, xml] of Object.entries(bad)) {
    assert.throws(() => envelope.parseXml(xml), undefined, what);
  }
});

test("the parser resolves namespaces and keeps attributes", () => {
  const root = envelope.parseXml('<r xmlns="d" xmlns:p="pns" a="1" xml:lang="en"><p:c b=\'&quot;2&quot;\'/><c xmlns=""/>t</r>');
  assert.equal(root.ns, "d");
  assert.deepEqual(root.attributes, { a: "1", "xml:lang": "en" });
  const [c1, c2, t] = root.children;
  assert.deepEqual([c1.name, c1.ns, c1.attributes.b], ["c", "pns", '"2"']);
  assert.deepEqual([c2.name, c2.ns], ["c", null]);
  assert.equal(t, "t");
});

test("the parser caps nesting depth", () => {
  const ok = "<a>".repeat(envelope.MAX_DEPTH) + "</a>".repeat(envelope.MAX_DEPTH);
  assert.equal(envelope.parseXml(ok).name, "a");
  const deep = "<a>".repeat(envelope.MAX_DEPTH + 1) + "</a>".repeat(envelope.MAX_DEPTH + 1);
  assert.throws(() => envelope.parseXml(deep), /deeper than/);
  assert.throws(() => envelope.parseXml("<a>".repeat(100000)), /deeper than/);
});

// --- end to end ---

test("twomemo end to end: envelope, payload and ratchet, and a spoofed sender is caught", () => {
  const ns = "twomemo";
  const party = () => {
    const identity = keys.generateIdentityKeyPair();
    return { identity, signedPreKey: keys.generateSignedPreKey(identity.privateKey, 1, ns), preKey: keys.generatePreKeys(1, 1)[0] };
  };
  const alice = party();
  const bob = party();
  const hs = x3dh.initiateHandshake(ns, alice.identity, {
    identityKey: keys.decodeIdentityKey(ns, keys.encodeIdentityKey(ns, bob.identity.publicKey)),
    signedPreKey: bob.signedPreKey,
    preKey: bob.preKey,
  });
  const aliceSession = dr.initSender(ns, hs, bob.signedPreKey.publicKey);

  // Alice sends.
  const sealed = payload.encrypt(ns, envelope.buildEnvelope({ body: "Meet at 6?", from: "alice@example.org" }));
  const keyElement = x3dh.encodeKeyExchange(ns, {
    preKeyId: hs.preKeyId,
    signedPreKeyId: hs.signedPreKeyId,
    identityKey: alice.identity.publicKey,
    ephemeralKey: hs.ephemeralPublicKey,
    message: dr.encrypt(aliceSession, sealed.keyMaterial),
  });

  // Bob receives.
  const kex = x3dh.decodeKeyExchange(ns, keyElement);
  const bobHs = x3dh.respondToHandshake(
    ns,
    { identity: bob.identity, signedPreKey: bob.signedPreKey, preKey: bob.preKey },
    { identityKey: kex.identityKey, ephemeralKey: kex.ephemeralKey }
  );
  const bobSession = dr.initReceiver(ns, bobHs, bob.signedPreKey);
  const keyMaterial = dr.decrypt(bobSession, kex.message);
  const plain = payload.decrypt(ns, { keyMaterial, ciphertext: sealed.ciphertext });
  assert.equal(envelope.parseEnvelope(plain, { sender: "alice@example.org/laptop" }).body, "Meet at 6?");
  assert.throws(() => envelope.parseEnvelope(plain, { sender: "carol@example.org" }), /does not match/);
});
