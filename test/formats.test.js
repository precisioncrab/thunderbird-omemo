/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests for src/omemo/formats.js and the XML builder in src/omemo/xml.js.
 * twomemo: Bob's published bundle and all 9 messages' <encrypted> XML from
 * python-twomemo parse to the right values and rebuild byte for byte.
 * oldmemo: round trips and hand-written XML in the XEP-0384 v0.3 format.
 */

import test from "node:test";
import assert from "node:assert/strict";
import * as f from "../src/omemo/formats.js";
import { parseXml, serialize, el } from "../src/omemo/xml.js";
import { createStore } from "../src/omemo/store.js";
import * as keys from "../src/crypto/keys.js";
import { load, h, hex, b64 } from "./helpers.js";

const v = load("twomemo");
const xml = (text) => parseXml(text);

// --- twomemo, against the reference ---

test("twomemo: Bob's published bundle parses to his keys and rebuilds byte for byte", () => {
  const bundle = f.parseBundle("twomemo", xml(v.bob.bundle_xml));
  assert.equal(hex(bundle.identityKey.ed25519), v.bob.identity.ed25519_pub);
  assert.equal(hex(bundle.identityKey.curve25519), v.bob.identity.curve25519_pub);
  assert.equal(bundle.signedPreKey.id, v.bob.signed_pre_key.id);
  assert.equal(hex(bundle.signedPreKey.publicKey), v.bob.signed_pre_key.pub);
  assert.equal(hex(bundle.signedPreKey.signature), v.bob.signed_pre_key.signature);
  assert.deepEqual(bundle.preKeys.map((k) => [k.id, hex(k.publicKey)]), v.bob.pre_keys.map((k) => [k.id, k.pub]));
  assert.equal(serialize(f.buildBundle("twomemo", bundle)), v.bob.bundle_xml);
});

test("twomemo: every message's <encrypted> parses to the reference values and rebuilds byte for byte", () => {
  const device = { alice: v.alice.device_id, bob: v.bob.device_id };
  const jid = { alice: v.alice.jid, bob: v.bob.jid };
  for (const m of v.messages) {
    const to = m.from === "alice" ? "bob" : "alice";
    const parsed = f.parseEncrypted(xml(m.xml));
    assert.equal(parsed.namespace, "twomemo");
    assert.equal(parsed.sid, device[m.from]);
    assert.equal(parsed.keys.length, 1);
    const [key] = parsed.keys;
    assert.deepEqual([key.jid, key.rid, key.kex], [jid[to], device[to], m.key_exchange], `message ${m.index}`);
    if (!m.key_exchange) {
      assert.equal(hex(key.data), m.ratchet_message);
    }
    assert.equal(parsed.iv, null);
    assert.equal(parsed.payload === null ? "" : hex(parsed.payload), m.empty ? "" : m.payload_ciphertext);
    assert.equal(f.findOurKey(parsed, { jid: `${jid[to]}/tb`, deviceId: device[to] }), key);
    assert.equal(f.findOurKey(parsed, { jid: jid[m.from], deviceId: device[to] }), null, "twomemo keys are per JID");
    assert.equal(serialize(f.buildEncrypted("twomemo", parsed)), m.xml, `message ${m.index} rebuilds`);
  }
});

// --- oldmemo ---

test("oldmemo: a bundle round-trips, with 0x05-prefixed keys", () => {
  const store = createStore();
  const published = store.bundle("oldmemo");
  const element = f.buildBundle("oldmemo", published);
  const text = serialize(element);
  assert.match(text, /^<bundle xmlns="eu\.siacs\.conversations\.axolotl"><signedPreKeyPublic signedPreKeyId="1">B[Q-Za-f]/, "0x05 type byte");
  const back = f.parseBundle("oldmemo", xml(text));
  assert.deepEqual(back.identityKey.curve25519, published.identityKey.curve25519);
  assert.equal(back.identityKey.ed25519, null, "oldmemo identity keys carry no sign bit");
  assert.deepEqual(back.signedPreKey, published.signedPreKey);
  assert.deepEqual(back.preKeys, published.preKeys);
});

test("oldmemo: parses a hand-written bundle with whitespace and wrapped base64", () => {
  const store = createStore();
  const { identityKey, signedPreKey, preKeys } = store.bundle("oldmemo");
  const wrap = (bytes) => Buffer.from(bytes).toString("base64").replace(/(.{20})/g, "$1\n      ");
  const text = `<bundle xmlns='eu.siacs.conversations.axolotl'>
    <signedPreKeyPublic signedPreKeyId='1'>${wrap(keys.encodePublicKey("oldmemo", signedPreKey.publicKey))}</signedPreKeyPublic>
    <signedPreKeySignature>${wrap(signedPreKey.signature)}</signedPreKeySignature>
    <identityKey>${wrap(keys.encodeIdentityKey("oldmemo", identityKey))}</identityKey>
    <prekeys>
      <preKeyPublic preKeyId='7'>${wrap(keys.encodePublicKey("oldmemo", preKeys[6].publicKey))}</preKeyPublic>
      <preKeyPublic preKeyId='x'>AAAA</preKeyPublic>
      <preKeyPublic preKeyId='8'>not base64!</preKeyPublic>
      <preKeyPublic preKeyId='9'>${Buffer.from(preKeys[8].publicKey).toString("base64")}</preKeyPublic>
    </prekeys>
  </bundle>`;
  const bundle = f.parseBundle("oldmemo", xml(text));
  assert.deepEqual(bundle.preKeys, [{ id: 7, publicKey: preKeys[6].publicKey }], "bad pre keys, including one missing its 0x05 byte, are skipped");
});

test("oldmemo: <encrypted> round-trips with prekey flags and an IV, and parses prekey='1'", () => {
  const message = {
    sid: 27183,
    keys: [
      { jid: null, rid: 31415, kex: false, data: h("33aabb") },
      { jid: null, rid: 12321, kex: true, data: h("33ccdd") },
    ],
    iv: h("000102030405060708090a0b"),
    payload: h("deadbeef"),
  };
  const text = serialize(f.buildEncrypted("oldmemo", message));
  assert.equal(text,
    '<encrypted xmlns="eu.siacs.conversations.axolotl"><header sid="27183">' +
    '<key rid="31415">M6q7</key><key rid="12321" prekey="true">M8zd</key><iv>AAECAwQFBgcICQoL</iv></header>' +
    "<payload>3q2+7w==</payload></encrypted>");
  assert.deepEqual(f.parseEncrypted(xml(text)), { namespace: "oldmemo", ...message });

  const other = f.parseEncrypted(xml(
    "<encrypted xmlns='eu.siacs.conversations.axolotl'><header sid='5'><key prekey='1' rid='9'>M8zd</key></header></encrypted>"));
  assert.deepEqual(other.keys, [{ jid: null, rid: 9, kex: true, data: h("33ccdd") }]);
  assert.equal(other.payload, null, "an empty OMEMO message");
  assert.equal(other.iv, null);
  assert.equal(f.findOurKey(other, { jid: "anyone@example.org", deviceId: 9 }), other.keys[0], "oldmemo keys aren't grouped by JID");
});

// --- device lists ---

test("device lists round-trip in both namespaces; twomemo keeps labels", () => {
  const devices = [{ id: 12345, label: "Gajim" }, { id: 4223, label: null }];
  assert.equal(serialize(f.buildDeviceList("twomemo", devices)),
    '<devices xmlns="urn:xmpp:omemo:2"><device id="12345" label="Gajim"/><device id="4223"/></devices>');
  assert.equal(serialize(f.buildDeviceList("oldmemo", devices)),
    '<list xmlns="eu.siacs.conversations.axolotl"><device id="12345"/><device id="4223"/></list>');
  for (const ns of keys.NAMESPACES) {
    const back = f.parseDeviceList(ns, xml(serialize(f.buildDeviceList(ns, devices))));
    assert.deepEqual(back, ns === "twomemo" ? devices : devices.map((d) => ({ ...d, label: null })));
  }
});

test("a contact's device list: bad entries skipped, duplicates dropped, wrong element refused", () => {
  const list = f.parseDeviceList("oldmemo", xml(`<list xmlns='eu.siacs.conversations.axolotl'>
      <device id='1'/><device id='0'/><device id='2147483648'/><device id='abc'/><device/><device id='1'/>
      <device id='2147483647'/><other id='5'/></list>`));
  assert.deepEqual(list.map((d) => d.id), [1, 2147483647]);
  assert.throws(() => f.parseDeviceList("twomemo", xml('<list xmlns="eu.siacs.conversations.axolotl"/>')), /twomemo <devices>/);
  assert.throws(() => f.parseDeviceList("oldmemo", xml('<list xmlns="urn:xmpp:omemo:2"/>')), /oldmemo <list>/);
  assert.throws(() => f.buildDeviceList("twomemo", [{ id: 0 }]), /Device id/);
});

// --- bundles that must be rejected ---

test("bundles without a valid signed prekey are rejected", () => {
  const good = v.bob.bundle_xml;
  const other = createStore().bundle("twomemo");
  const cases = {
    "no signed prekey": good.replace(/<spk id="1">[^<]*<\/spk>/, ""),
    "no signature": good.replace(/<spks>[^<]*<\/spks>/, ""),
    "no identity key": good.replace(/<ik>[^<]*<\/ik>/, ""),
    "bad signed prekey id": good.replace('<spk id="1">', '<spk id="zero">'),
    "swapped signed prekey": good.replace(/<spk id="1">[^<]*</, `<spk id="1">${Buffer.from(other.signedPreKey.publicKey).toString("base64")}<`),
    "other identity key": good.replace(/<ik>[^<]*</, `<ik>${Buffer.from(other.identityKey.ed25519).toString("base64")}<`),
    "short signature": good.replace(/<spks>[^<]*</, "<spks>AAAA<"),
    "wrong namespace": good.replace('xmlns="urn:xmpp:omemo:2"', 'xmlns="urn:xmpp:omemo:1"'),
  };
  for (const [what, text] of Object.entries(cases)) {
    assert.notEqual(text, good, `${what}: the edit applied`);
    assert.throws(() => f.parseBundle("twomemo", xml(text)), undefined, what);
  }
  const noPreKeys = f.parseBundle("twomemo", xml(good.replace(/<prekeys>.*<\/prekeys>/, "")));
  assert.deepEqual(noPreKeys.preKeys, [], "a bundle without pre keys still parses");
});

// --- <encrypted> edge cases ---

test("<encrypted>: malformed parts are refused or skipped", () => {
  const two = (header, rest = "") => xml(`<encrypted xmlns="urn:xmpp:omemo:2">${header}${rest}</encrypted>`);
  assert.throws(() => f.parseEncrypted(xml('<encrypted xmlns="urn:xmpp:omemo:1"/>')), /Not an OMEMO/);
  assert.throws(() => f.parseEncrypted(xml('<payload xmlns="urn:xmpp:omemo:2"/>')), /Not an OMEMO/);
  assert.throws(() => f.parseEncrypted(two("")), /no <header>/);
  assert.throws(() => f.parseEncrypted(two('<header sid="0"/>')), /valid sid/);
  assert.throws(() => f.parseEncrypted(two('<header sid="1"/>', "<payload>!!</payload>")), /payload is not valid base64/);

  const parsed = f.parseEncrypted(two(`<header sid="1">
      <keys jid="Bob@Example.org"><key rid="2">AAAA</key><key rid="x">AAAA</key><key rid="3" kex="maybe">AAAA</key><key rid="4">%%%%</key></keys>
      <keys jid="bob@example.org/res"><key rid="5">AAAA</key></keys>
      <keys><key rid="6">AAAA</key></keys>
      <key rid="7">AAAA</key>
    </header>`));
  assert.deepEqual(parsed.keys, [{ jid: "bob@example.org", rid: 2, kex: false, data: new Uint8Array(3) }]);
  assert.equal(f.findOurKey(parsed, { jid: "BOB@example.org/tb", deviceId: 2 }), parsed.keys[0]);
});

test("<encrypted> builders refuse what the namespace can't carry", () => {
  assert.throws(() => f.buildEncrypted("oldmemo", { sid: 1, keys: [], payload: h("00") }), /needs an IV/);
  assert.throws(() => f.buildEncrypted("twomemo", { sid: 1, keys: [{ rid: 2, kex: false, data: h("00") }] }), /bare JID/);
  assert.throws(() => f.buildEncrypted("twomemo", { sid: 1, keys: [{ jid: "a@b/c", rid: 2, kex: false, data: h("00") }] }), /bare JID/);
  assert.throws(() => f.buildEncrypted("twomemo", { sid: 0, keys: [] }), /Device id/);
  // Keys for several JIDs group under one <keys> each, in first-seen order.
  const text = serialize(f.buildEncrypted("twomemo", {
    sid: 1,
    keys: [
      { jid: "b@x", rid: 2, kex: false, data: h("01") },
      { jid: "a@x", rid: 3, kex: true, data: h("02") },
      { jid: "b@x", rid: 4, kex: false, data: h("03") },
    ],
  }));
  assert.equal(text, '<encrypted xmlns="urn:xmpp:omemo:2"><header sid="1">' +
    '<keys jid="b@x"><key rid="2">AQ==</key><key rid="4">Aw==</key></keys>' +
    '<keys jid="a@x"><key rid="3" kex="true">Ag==</key></keys></header></encrypted>');
});

// --- PEP locations and the XML builder ---

test("PEP nodes and item ids per namespace", () => {
  assert.deepEqual(f.deviceListLocation("oldmemo"), { node: "eu.siacs.conversations.axolotl.devicelist", itemId: "current" });
  assert.deepEqual(f.deviceListLocation("twomemo"), { node: "urn:xmpp:omemo:2:devices", itemId: "current" });
  assert.deepEqual(f.bundleLocation("oldmemo", 42), { node: "eu.siacs.conversations.axolotl.bundles:42", itemId: "current" });
  assert.deepEqual(f.bundleLocation("twomemo", 42), { node: "urn:xmpp:omemo:2:bundles", itemId: "42" });
  assert.throws(() => f.bundleLocation("twomemo", 0), /Device id/);
  assert.equal(f.namespaceOf({ ns: "urn:xmpp:omemo:2" }), "twomemo");
  assert.equal(f.namespaceOf(null), null);
});

test("serialize declares namespaces only where they change, escapes, and round-trips through the parser", () => {
  const tree = el("a", "urn:x", { q: 'say "hi" & <bye>' }, [
    el("b", "urn:x", {}, ["1 < 2 & 3 > 2\r\n"]),
    el("c", "urn:y", { skip: null, n: 5 }),
    el("d", null),
  ]);
  const text = serialize(tree);
  assert.equal(text, '<a xmlns="urn:x" q="say &quot;hi&quot; &amp; &lt;bye&gt;"><b>1 &lt; 2 &amp; 3 &gt; 2&#xD;\n</b>' +
    '<c xmlns="urn:y" n="5"/><d xmlns=""/></a>');
  assert.deepEqual(parseXml(text), tree);
  assert.throws(() => serialize(el("a", null, {}, ["bad " + String.fromCharCode(1)])), /character XML doesn't allow/);
});
