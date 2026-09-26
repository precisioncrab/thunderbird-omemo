/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * A quick check that the crypto core works in whatever environment loaded
 * it (docs/TASKS.md 3.1). The Experiment runs it once after importing the
 * bundle, since Thunderbird's privileged module scope differs from Node:
 * one known-answer XEdDSA signature (from test/vectors/xeddsa.json), then a
 * full session in each namespace using the environment's own randomness
 * (globalThis.crypto.getRandomValues, which noble relies on).
 */

import * as xeddsa from "./xeddsa.js";
import * as keys from "./keys.js";
import * as x3dh from "./x3dh.js";
import * as doubleRatchet from "./double-ratchet.js";
import * as payload from "./payload.js";
import * as envelope from "./envelope.js";

const KNOWN_SIGNATURE = {
  priv: "208b464f3c3d5d92680106f8bab7fb6a6e2952dc5d14d783c41b5b6a9ab31948",
  nonce:
    "6a9b1e223eb4d8ca24ed914d87a28e5c477e5b4ed7f705bc0e8f594c234fad6a" +
    "2933f1257712beef4f68af5e43f8988a61612613a56ddb7dfe48987bcf3bafca",
  signature:
    "eb91c596aad0573cffa8617b1b781f2c1631c2a7a00237a6830a045e1cafea6e" +
    "b66e94299eaa90267584c78a32f47f282a05526418c6574c815c20d71d385d03",
};

/**
 * @returns {string} a one-line summary on success.
 * @throws with a message naming the step that failed.
 */
export function selfTest() {
  const environment = [
    `crypto.getRandomValues: ${typeof globalThis.crypto?.getRandomValues}`,
    `TextEncoder: ${typeof globalThis.TextEncoder}`,
    `btoa: ${typeof globalThis.btoa}`,
    `BigInt: ${typeof globalThis.BigInt}`,
  ].join(", ");

  step("XEdDSA known answer", environment, () => {
    const signature = xeddsa.sign(fromHex(KNOWN_SIGNATURE.priv), new Uint8Array(0), fromHex(KNOWN_SIGNATURE.nonce));
    if (toHex(signature) !== KNOWN_SIGNATURE.signature) {
      throw new Error("signature differs from the reference");
    }
  });

  for (const ns of keys.NAMESPACES) {
    step(`${ns} session`, environment, () => roundTrip(ns));
  }
  return `crypto self-test passed (XEdDSA known answer, oldmemo and twomemo sessions); ${environment}`;
}

function roundTrip(ns) {
  const party = () => {
    const identity = keys.generateIdentityKeyPair();
    return {
      identity,
      signedPreKey: keys.generateSignedPreKey(identity.privateKey, 1, ns),
      preKey: keys.generatePreKeys(1, 1)[0],
    };
  };
  const alice = party();
  const bob = party();

  const handshake = x3dh.initiateHandshake(ns, alice.identity, {
    identityKey: keys.decodeIdentityKey(ns, keys.encodeIdentityKey(ns, bob.identity.publicKey)),
    signedPreKey: bob.signedPreKey,
    preKey: bob.preKey,
  });
  const aliceSession = doubleRatchet.initSender(ns, handshake, bob.signedPreKey.publicKey);

  const body = "self-test \u{1F510}";
  const plain = ns === "twomemo" ? envelope.buildEnvelope({ body, from: "alice@example.org" }) : new TextEncoder().encode(body);
  const sealed = payload.encrypt(ns, plain);
  const kex = x3dh.decodeKeyExchange(ns, x3dh.encodeKeyExchange(ns, {
    preKeyId: handshake.preKeyId,
    signedPreKeyId: handshake.signedPreKeyId,
    identityKey: alice.identity.publicKey,
    ephemeralKey: handshake.ephemeralPublicKey,
    message: doubleRatchet.encrypt(aliceSession, sealed.keyMaterial),
  }));

  const bobHandshake = x3dh.respondToHandshake(
    ns,
    { identity: bob.identity, signedPreKey: bob.signedPreKey, preKey: bob.preKey },
    { identityKey: kex.identityKey, ephemeralKey: kex.ephemeralKey }
  );
  const bobSession = doubleRatchet.deserializeState(
    JSON.parse(JSON.stringify(doubleRatchet.serializeState(doubleRatchet.initReceiver(ns, bobHandshake, bob.signedPreKey))))
  );
  const opened = payload.decrypt(ns, { ...sealed, keyMaterial: doubleRatchet.decrypt(bobSession, kex.message) });
  const received = ns === "twomemo"
    ? envelope.parseEnvelope(opened, { sender: "alice@example.org" }).body
    : new TextDecoder().decode(opened);
  if (received !== body) {
    throw new Error("the decrypted text differs");
  }
  // And a reply, which makes Alice's side ratchet.
  const reply = doubleRatchet.decrypt(aliceSession, doubleRatchet.encrypt(bobSession, payload.emptyKeyMaterial(ns)));
  if (reply.length !== (ns === "twomemo" ? 32 : 16)) {
    throw new Error("the reply's key material has the wrong size");
  }
}

function step(name, environment, fn) {
  try {
    fn();
  } catch (e) {
    throw new Error(`crypto self-test failed at "${name}": ${e?.message ?? e} (${environment})`);
  }
}

function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}

function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
