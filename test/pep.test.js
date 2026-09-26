/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests for src/omemo/pep.js: the stanzas it builds (checked as text),
 * error and notification parsing, and publish/fetch against the fake
 * pubsub server in test/fake-pep.js.
 */

import test from "node:test";
import assert from "node:assert/strict";
import * as pep from "../src/omemo/pep.js";
import { el, parseXml, serialize } from "../src/omemo/xml.js";
import { createFakePepServer } from "./fake-pep.js";

const payload = el("list", "eu.siacs.conversations.axolotl", {}, [el("device", "eu.siacs.conversations.axolotl", { id: 1 })]);

test("publish, configure and items stanzas, as text", () => {
  assert.equal(serialize(pep.publishIq("n", "current", payload, { "pubsub#access_model": "open" })),
    '<iq xmlns="jabber:client" type="set"><pubsub xmlns="http://jabber.org/protocol/pubsub"><publish node="n"><item id="current">' +
    '<list xmlns="eu.siacs.conversations.axolotl"><device id="1"/></list></item></publish><publish-options>' +
    '<x xmlns="jabber:x:data" type="submit"><field var="FORM_TYPE" type="hidden"><value>http://jabber.org/protocol/pubsub#publish-options</value></field>' +
    '<field var="pubsub#access_model"><value>open</value></field></x></publish-options></pubsub></iq>');
  assert.doesNotMatch(serialize(pep.publishIq("n", "1", payload)), /publish-options/, "no options, no form");
  assert.match(serialize(pep.configureIq("n", { "pubsub#max_items": "max" })),
    /<pubsub xmlns="http:\/\/jabber\.org\/protocol\/pubsub#owner"><configure node="n"><x xmlns="jabber:x:data" type="submit">.*#node_config.*<field var="pubsub#max_items"><value>max<\/value>/);
  assert.equal(serialize(pep.itemsIq("bob@example.org", "urn:xmpp:omemo:2:bundles", "42")),
    '<iq xmlns="jabber:client" type="get" to="bob@example.org"><pubsub xmlns="http://jabber.org/protocol/pubsub">' +
    '<items node="urn:xmpp:omemo:2:bundles"><item id="42"/></items></pubsub></iq>');
  assert.equal(serialize(pep.itemsIq(null, "n")),
    '<iq xmlns="jabber:client" type="get"><pubsub xmlns="http://jabber.org/protocol/pubsub"><items node="n"/></pubsub></iq>');
});

test("parses a server's error reply, including pubsub-specific conditions", () => {
  const reply = parseXml(`<iq type='error' id='x'><error type='cancel'>
      <conflict xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>
      <precondition-not-met xmlns='http://jabber.org/protocol/pubsub#errors'/>
      <text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'>Node config mismatch</text>
    </error></iq>`);
  assert.deepEqual(pep.parseError(reply), { type: "cancel", condition: "conflict", pubsubCondition: "precondition-not-met", text: "Node config mismatch" });
  assert.equal(pep.parseError(parseXml("<iq type='result'/>")), null);
  assert.deepEqual(pep.parseError(parseXml("<iq type='error'/>")), { type: null, condition: null, pubsubCondition: null, text: null });
});

test("parses a PEP notification, and ignores other messages", () => {
  const message = parseXml(`<message from='bob@example.org' to='alice@example.org/tb' type='headline'>
      <event xmlns='http://jabber.org/protocol/pubsub#event'>
        <items node='urn:xmpp:omemo:2:devices'>
          <item id='current'><devices xmlns='urn:xmpp:omemo:2'><device id='7'/></devices></item>
        </items>
      </event>
    </message>`);
  const event = pep.parseEvent(message);
  assert.equal(event.from, "bob@example.org");
  assert.equal(event.node, "urn:xmpp:omemo:2:devices");
  assert.equal(event.items.length, 1);
  assert.equal(event.items[0].id, "current");
  assert.equal(serialize(event.items[0].payload), '<devices xmlns="urn:xmpp:omemo:2"><device id="7"/></devices>');
  assert.equal(pep.parseEvent(parseXml("<message><body>hi</body></message>")), null);
  assert.equal(pep.parseEvent(parseXml("<message><event xmlns='http://jabber.org/protocol/pubsub#event'><purge node='x'/></event></message>")), null);
});

test("publish then fetch, our own node and a contact's", async () => {
  const server = createFakePepServer();
  const alice = pep.createPep(server.connect("alice@example.org"));
  const bob = pep.createPep(server.connect("bob@example.org"));
  await alice.publish("n", "current", payload, { "pubsub#access_model": "open" });
  const own = await alice.fetchItems(null, "n");
  assert.equal(own.length, 1);
  assert.equal(own[0].id, "current");
  assert.equal(serialize(own[0].payload), serialize(payload));
  const theirs = await bob.fetchItems("Alice@Example.org/tb", "n", "current");
  assert.equal(serialize(theirs[0].payload), serialize(payload));
});

test("a missing node or item reads as empty; other errors throw PepError", async () => {
  const server = createFakePepServer();
  const alice = pep.createPep(server.connect("alice@example.org"));
  assert.deepEqual(await alice.fetchItems("bob@example.org", "nothing-here"), []);
  await alice.publish("n", "a", payload);
  assert.deepEqual(await alice.fetchItems(null, "n", "b"), []);
  // Default access model is presence, so a stranger is refused.
  const bob = pep.createPep(server.connect("bob@example.org"));
  await assert.rejects(bob.fetchItems("alice@example.org", "n"), (e) => e instanceof pep.PepError && e.condition === "forbidden");
});

test("publish-options that conflict with the node's settings: reconfigure once, then publish", async () => {
  const server = createFakePepServer();
  server.configure("alice@example.org", "urn:xmpp:omemo:2:bundles", { "pubsub#access_model": "presence", "pubsub#max_items": "1" });
  const alice = pep.createPep(server.connect("alice@example.org"));
  const options = { "pubsub#access_model": "open", "pubsub#max_items": "max" };
  await alice.publish("urn:xmpp:omemo:2:bundles", "1", payload, options);
  const node = server.accounts.get("alice@example.org").get("urn:xmpp:omemo:2:bundles");
  assert.deepEqual(node.config, options);
  assert.equal(node.items.size, 1);
  assert.deepEqual(server.log.map((l) => /<(publish|configure) /.exec(l.iq)[1]), ["publish", "configure", "publish"]);
  // Without options there's nothing to reconcile: the conflict can't happen.
  await alice.publish("urn:xmpp:omemo:2:bundles", "2", payload);
  assert.equal(node.items.size, 2, "max_items=max keeps every device's item");
});

test("an error during the retry propagates", async () => {
  const sendIq = async (iq) => parseXml(serialize(el("iq", null, { type: "error" }, [el("error", null, { type: "cancel" }, [
    el(serialize(iq).includes("<configure") ? "not-authorized" : "conflict", "urn:ietf:params:xml:ns:xmpp-stanzas"),
    ...(serialize(iq).includes("<configure") ? [] : [el("precondition-not-met", pep.NS_PUBSUB_ERRORS)]),
  ])])));
  await assert.rejects(pep.createPep(sendIq).publish("n", "1", payload, { "pubsub#access_model": "open" }),
    (e) => e instanceof pep.PepError && e.condition === "not-authorized" && /not-authorized/.test(e.message));
});
