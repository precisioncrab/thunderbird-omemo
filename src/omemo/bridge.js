/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * The hooks into Thunderbird's XMPP code, and each account's OMEMO
 * lifecycle (docs/TASKS.md 3.5-3.9 wiring). Everything from Thunderbird is
 * passed in, so tests run this against fake prototypes that behave like
 * comm-central's; the Experiment only loads the modules and calls
 * installBridge.
 *
 * Patched, on the shared prototypes (so every account and connection gets
 * them):
 *   XMPPConversationPrototype.dispatchMessage  encrypt 1:1 messages (milestone 4)
 *   XMPPAccountPrototype.onConnection          start OMEMO for the account
 *   XMPPAccountPrototype._disconnect           save the key store
 *   XMPPAccountPrototype.sendStanza            add our caps hash to presence
 *   XMPPAccountPrototype.onIQStanza            answer disco#info for our caps node
 *   XMPPAccountPrototype.onMessageStanza       decrypt; OMEMO device list pushes
 * plus OMEMO's +notify features in Thunderbird's SupportedFeatures, which
 * its disco#info reply lists. A hook's own failure is logged and never
 * stops Thunderbird's original code from running.
 *
 * Which conversations are encrypted (docs/TASKS.md 4.1) follows the user's
 * mode, set on the add-on's options page:
 *   "manual"     only chats the user switched on (the default)
 *   "available"  every contact who publishes OMEMO devices
 *   "always"     every contact; a contact without OMEMO can't be messaged
 *                until the user switches that chat off
 * and a per-contact choice ("on"/"off", kept in the key store) that
 * overrides the mode: Thunderbird's encryption button switches a chat on,
 * and the /omemo command switches it on, off or back to the mode. Incoming
 * OMEMO is decrypted in every mode. `encryptionAllowlist` (tests, and the
 * first test builds) forces encryption between two listed accounts; with no
 * mode set, only that list applies. In an encrypted conversation a message
 * that can't be encrypted is not sent at all, never sent in plaintext. The
 * same goes when it can't be told whether a chat is encrypted: a message
 * sent while the account's OMEMO is starting waits for it, and in mode
 * "available" a failed device lookup blocks the message (retryable) rather
 * than counting as "no OMEMO".
 *
 * Thunderbird's chat UI shows a conversation's encryptionState (the lock
 * button and "Encryption Status"), which the bridge provides for XMPP 1:1
 * conversations, and a padlock on messages flagged isEncrypted: our local
 * echo, and whatever Thunderbird writes while handling a message we
 * decrypted.
 */

import { capsVer, CAPS_NODE, NOTIFY_FEATURES, NS_CAPS } from "./caps.js";
import { createOmemoAccount } from "./account.js";
import { NS_PUBSUB_EVENT, parseEvent } from "./pep.js";
import { NS, buildEncrypted, parseEncrypted, namespaceOf, findOurKey } from "./formats.js";
import { createSendIq, fromXmlNode, toXmlNode } from "./xmlnode.js";
import { encryptMessage, decryptMessage, OmemoError } from "./messages.js";
import { formatFingerprint, fingerprintOfWireKey, verificationUri } from "./fingerprint.js";
import { decideTrust, noticeText, TRUST_DESCRIPTIONS } from "./trust.js";

const NS_DISCO_INFO = "http://jabber.org/protocol/disco#info";
const DEVICE_LIST_NODES = new Set([`${NS.oldmemo}.devicelist`, `${NS.twomemo}:devices`]);
const NS_CARBONS = "urn:xmpp:carbons:2";
const NS_HINTS = "urn:xmpp:hints";
const NS_EME = "urn:xmpp:eme:0";

/** How often each account's upkeep runs while connected (signed prekey rotation). */
const MAINTAIN_EVERY_MS = 6 * 60 * 60 * 1000;

/**
 * A device that hasn't sent a message for this long (or, if it never has,
 * has been listed this long) is left out when encrypting, unless that would
 * leave none of its owner's devices (milestone 6). Old app installs stay on
 * device lists forever otherwise.
 */
export const STALE_AFTER_MS = 90 * 24 * 60 * 60 * 1000;

/** The <body> other clients show when they can't decrypt. */
export const FALLBACK_BODY = "This message is OMEMO encrypted, and your client can't decrypt it.";

/** What the user sees when a message for them couldn't be decrypted (docs/TASKS.md 4.9). */
const DECRYPT_NOTICES = {
  "not-for-this-device": "[OMEMO] This message wasn't encrypted for this device.",
  "no-session": "[OMEMO] This message couldn't be decrypted: there's no session with the sender's device yet.",
  "unknown-signed-prekey": "[OMEMO] This message couldn't be decrypted: it uses keys this device no longer has.",
  "unknown-pre-key": "[OMEMO] This message couldn't be decrypted: it uses a one-time key that's already used.",
  "decryption-failed": "[OMEMO] This message couldn't be decrypted (damaged, repeated or out of sync).",
  "bad-payload": "[OMEMO] This message's text couldn't be decrypted.",
  "sender-mismatch": "[OMEMO] This message claims to be from someone else and was not shown.",
};

/**
 * @param {object} tb - what Thunderbird provides.
 * @param {object} tb.xmppBase - xmpp-base.sys.mjs's exports.
 * @param {object} tb.Stanza - from xmpp-xml.sys.mjs.
 * @param {string[]} tb.SupportedFeatures - from xmpp-xml.sys.mjs (mutated).
 * @param {typeof setTimeout} tb.setTimer
 * @param {typeof clearTimeout} tb.clearTimer
 * @param {string} tb.appName - for our disco identity ("Thunderbird").
 * @param {(jid: string) => import("./persist.js").FileAccess} tb.fileAccessFor
 * @param {() => object[]} [tb.connectedAccounts] - XMPP accounts already
 *   connected when we install.
 * @param {(line: string) => void} tb.log
 * @param {(conversationId: number, text: string) => void} [tb.onOutgoing]
 * @param {(from: string, payload: { namespace: string, xml: string }) => void} [tb.onIncomingEncrypted]
 * @param {string[]} [tb.encryptionAllowlist] - bare JIDs; conversations
 *   between two of them are encrypted. Empty (the default): none are.
 * @param {"manual"|"available"|"always"} [tb.mode] - see above; change it
 *   later with updateSettings.
 * @param {boolean} [tb.optIn] - older name for mode "manual".
 * @param {(section: "verify"|"instructions") => void} [tb.onShowPage] -
 *   opens the add-on's page at its QR codes (/omemo qr) or instructions
 *   (/omemo help).
 * @param {() => number} [tb.now] - the clock, for "last message" times in
 *   /omemo status (tests).
 * @param {{ NOT_SUPPORTED: number, AVAILABLE: number, ENABLED: number, TRUSTED: number }} [tb.encryptionStates]
 *   - Ci.prplIConversation's ENCRYPTION_* values; without them the
 *   conversation encryption API isn't provided.
 * @returns {{ accounts: Map<object, object>, runCommand: (conversation: object, args: string) => boolean,
 *   updateSettings: (settings: { mode: string|null }) => void, saveAll: () => Promise<void>,
 *   uninstall: () => Promise<void> }}
 */
export function installBridge(tb) {
  const { xmppBase, Stanza, SupportedFeatures, setTimer, clearTimer, appName, fileAccessFor, log } = tb;
  const conv = xmppBase.XMPPConversationPrototype;
  const acct = xmppBase.XMPPAccountPrototype;
  const targets = [
    [conv, "dispatchMessage"],
    [acct, "onConnection"],
    [acct, "_disconnect"],
    [acct, "sendStanza"],
    [acct, "onIQStanza"],
    [acct, "onMessageStanza"],
  ];
  const missing = targets.filter(([proto, name]) => typeof proto?.[name] !== "function").map(([, name]) => name);
  if (missing.length) {
    throw new Error(`Can't hook Thunderbird's XMPP code: missing ${missing.join(", ")}.`);
  }

  const originals = new Map(targets.map(([proto, name]) => [name, proto[name]]));
  const allowlist = new Set((tb.encryptionAllowlist ?? []).map((j) => j.toLowerCase()));
  const MODES = ["manual", "available", "always"];
  let mode = tb.mode ?? (tb.optIn ? "manual" : null);
  if (mode !== null && !MODES.includes(mode)) {
    throw new Error(`Unknown encryption mode "${mode}".`);
  }
  // Contacts found to have no OMEMO devices, so an SMS contact isn't looked
  // up on every message: "<our jid> <their jid>" -> time to look again.
  const noDevicesUntil = new Map();
  const NO_DEVICES_RECHECK_MS = 10 * 60 * 1000;
  const states = tb.encryptionStates ?? null;
  const now = tb.now ?? Date.now;

  // Members we add to XMPPConversationPrototype itself (it inherits them
  // from Thunderbird's generic conversation), restored on uninstall.
  const ownPatches = [];
  function patchOwn(obj, name, descriptor) {
    ownPatches.push({ obj, name, previous: Object.getOwnPropertyDescriptor(obj, name) });
    Object.defineProperty(obj, name, descriptor.get
      ? { configurable: true, get: descriptor.get }
      : { configurable: true, writable: true, value: descriptor.value });
  }
  const addedFeatures = NOTIFY_FEATURES.filter((f) => !SupportedFeatures.includes(f));
  SupportedFeatures.push(...addedFeatures);

  /** @type {Map<object, ReturnType<typeof createOmemoAccount>>} */
  const accounts = new Map();
  // Settles when each account's start() has finished or failed.
  const started = new Map();
  // Saves still running for accounts that disconnected; uninstall and
  // saveAll wait for them.
  const pendingSaves = new Set();
  // Each account's upkeep timer (signed prekey rotation), while connected.
  const maintenanceTimers = new Map();

  function scheduleMaintenance(account, omemo) {
    const timer = setTimer(() => {
      if (accounts.get(account) !== omemo) {
        return;
      }
      omemo.maintain()
        .catch((e) => log(`ERROR: OMEMO upkeep for ${bareJidOf(account)} failed: ${e?.message ?? e}`))
        .finally(() => {
          if (accounts.get(account) === omemo) {
            scheduleMaintenance(account, omemo);
          }
        });
    }, MAINTAIN_EVERY_MS);
    timer?.unref?.(); // Node (tests): don't keep the process alive
    maintenanceTimers.set(account, timer);
  }

  const safely = (what, fn) => {
    try {
      return fn();
    } catch (e) {
      log(`ERROR: ${what} failed: ${e?.message ?? e}`);
      return undefined;
    }
  };
  const bareJidOf = (account) => {
    const jid = account._jid;
    return (jid?.node ? `${jid.node}@${jid.domain}` : jid?.domain ?? "").toLowerCase();
  };
  const identity = () => ({ category: "client", type: "pc", name: appName });
  // Accounts start one after another, with a pause between, so first-connect
  // key generation (hundreds of keys per account, synchronous) doesn't
  // freeze Thunderbird for all accounts at once.
  let startQueue = Promise.resolve();
  const pause = () => new Promise((resolve) => setTimer(resolve, 50));
  const ver = () => capsVer({ identities: [identity()], features: [...SupportedFeatures] });

  function startAccount(account) {
    const jid = bareJidOf(account);
    if (!jid || accounts.has(account)) {
      return;
    }
    const omemo = createOmemoAccount({
      jid,
      sendIq: createSendIq(account, { Stanza, setTimer, clearTimer }),
      fileAccess: fileAccessFor(jid),
      log,
      saverOptions: { setTimer, clearTimer },
    });
    accounts.set(account, omemo);
    startQueue = startQueue
      .then(pause)
      .then(() => (accounts.get(account) === omemo ? omemo.start() : undefined))
      .then(() => {
        if (accounts.get(account) === omemo) {
          scheduleMaintenance(account, omemo);
        }
        notifyConversations(account);
      })
      .catch((e) => {
        log(`ERROR: starting OMEMO for ${jid} failed: ${e?.message ?? e}`);
      });
    started.set(account, startQueue);
  }

  function stopAccount(account) {
    const omemo = accounts.get(account);
    if (!omemo) {
      return Promise.resolve();
    }
    accounts.delete(account);
    started.delete(account);
    if (maintenanceTimers.has(account)) {
      clearTimer(maintenanceTimers.get(account));
      maintenanceTimers.delete(account);
    }
    const saving = omemo.stop()
      .catch((e) => log(`ERROR: saving OMEMO keys for ${bareJidOf(account)} failed: ${e?.message ?? e}`))
      .finally(() => pendingSaves.delete(saving));
    pendingSaves.add(saving);
    return saving;
  }

  /**
   * Writes every account's pending key store changes now, and waits for the
   * saves of accounts that just disconnected (Thunderbird's shutdown).
   */
  async function saveAll() {
    const saves = [...accounts].map(([account, omemo]) =>
      omemo.stop().catch((e) => log(`ERROR: saving OMEMO keys for ${bareJidOf(account)} failed: ${e?.message ?? e}`)));
    await Promise.all([...saves, ...pendingSaves]);
  }

  const bare = (jid) => {
    const s = String(jid ?? "");
    const slash = s.indexOf("/");
    return (slash < 0 ? s : s.slice(0, slash)).toLowerCase();
  };

  /**
   * Whether this account's conversation with peerJid is encrypted (4.1).
   *
   * @returns {"yes"|"no"|"if-devices"|"not-ready"} "if-devices": mode
   *   "available" and no choice for this contact, so it depends on whether
   *   they have OMEMO. "not-ready": the key store, which holds the
   *   per-contact choice, isn't loaded yet.
   */
  function wantsEncryption(account, peerJid) {
    const ourJid = bareJidOf(account);
    if (ourJid === peerJid) {
      return "no";
    }
    if (allowlist.has(ourJid) && allowlist.has(peerJid)) {
      return "yes";
    }
    if (mode === null) {
      return "no";
    }
    const store = accounts.get(account)?.store;
    if (!store) {
      return "not-ready";
    }
    const choice = store.encryptionChoice(peerJid);
    if (choice === "on") {
      return "yes";
    }
    if (choice === "off" || mode === "manual") {
      return "no";
    }
    return mode === "always" ? "yes" : "if-devices";
  }

  /** Whether to decrypt what this account receives in a conversation with peerJid. */
  function decrypts(account, peerJid) {
    const ourJid = bareJidOf(account);
    return mode !== null || (ourJid !== peerJid && allowlist.has(ourJid) && allowlist.has(peerJid));
  }

  /** Whether we already know this contact publishes OMEMO devices. */
  function knownToHaveDevices(account, peerJid) {
    const store = accounts.get(account)?.store;
    return Boolean(store && (store.devices("twomemo", peerJid).length || store.devices("oldmemo", peerJid).length));
  }

  /**
   * Whether the contact has OMEMO devices, fetching their lists if we don't
   * know. A contact whose lists both came back empty is remembered for a
   * while; a failed lookup is not remembered.
   *
   * @returns {Promise<{ found: boolean|null, error: string|null }>} found:
   *   null if it couldn't be told (OMEMO not ready, or a lookup failed).
   */
  async function lookUpDevices(account, peerJid) {
    if (knownToHaveDevices(account, peerJid)) {
      return { found: true, error: null };
    }
    const key = `${bareJidOf(account)} ${peerJid}`;
    if ((noDevicesUntil.get(key) ?? 0) > Date.now()) {
      return { found: false, error: null };
    }
    const omemo = accounts.get(account);
    if (!omemo?.store) {
      return { found: null, error: "OMEMO isn't ready for this account yet" };
    }
    let found;
    try {
      const lists = await Promise.all([omemo.getDevices("twomemo", peerJid), omemo.getDevices("oldmemo", peerJid)]);
      found = lists.some((l) => l.length);
    } catch (e) {
      log(`looking up ${peerJid}'s OMEMO devices failed: ${e?.message ?? e}`);
      return { found: null, error: String(e?.message ?? e) };
    }
    if (found) {
      noDevicesUntil.delete(key);
    } else {
      noDevicesUntil.set(key, Date.now() + NO_DEVICES_RECHECK_MS);
    }
    return { found, error: null };
  }

  /** Tells Thunderbird's UI to redraw a conversation's encryption state. */
  function notifyConversation(conversation) {
    safely("updating the encryption button", () => conversation.notifyObservers?.(conversation, "update-conv-encryption"));
  }

  function notifyConversations(account, peerJid = null) {
    for (const conversation of account._conv?.values?.() ?? []) {
      if (peerJid === null || bare(conversation.to) === peerJid) {
        notifyConversation(conversation);
      }
    }
  }

  /** Whether every device the contact lists has a verified key (the lock's "verified"). */
  function allVerified(account, peerJid) {
    const store = accounts.get(account).store;
    const ids = new Set([...store.devices("twomemo", peerJid), ...store.devices("oldmemo", peerJid)].map((d) => d.id));
    return ids.size > 0 && [...ids].every((id) => {
      const fp = store.deviceKey(peerJid, id);
      return fp !== null && store.trustOf(peerJid, fp) === "verified";
    });
  }

  /** The conversation's state for Thunderbird's encryption button. */
  function encryptionStateOf(conversation) {
    const account = conversation._account;
    if (!accounts.get(account)?.store) {
      return states.NOT_SUPPORTED;
    }
    const peerJid = bare(conversation.to);
    const wants = wantsEncryption(account, peerJid);
    const encrypted = states.ENABLED;
    if (wants === "yes") {
      return allVerified(account, peerJid) ? states.TRUSTED : encrypted;
    }
    if (knownToHaveDevices(account, peerJid)) {
      if (wants === "if-devices") {
        return allVerified(account, peerJid) ? states.TRUSTED : encrypted;
      }
      return mode === null ? states.NOT_SUPPORTED : states.AVAILABLE;
    }
    if (mode !== null && !conversation._omemoLookedUp) {
      // Look the contact's devices up once; redraw if they have some.
      conversation._omemoLookedUp = true;
      lookUpDevices(account, peerJid).then(({ found }) => {
        if (found === null) {
          conversation._omemoLookedUp = false; // try again next time
        } else if (found) {
          notifyConversation(conversation);
        }
      });
    }
    return states.NOT_SUPPORTED;
  }

  /** When we last heard from a device, or (never) since it was first listed. */
  function lastSignOf(store, jid, deviceId) {
    const last = store.lastMessageFrom(jid, deviceId);
    if (last !== null) {
      return last;
    }
    const listed = ["twomemo", "oldmemo"].flatMap((ns) => store.devices(ns, jid)).filter((d) => d.id === deviceId);
    return listed.length ? Math.min(...listed.map((d) => d.firstSeen)) : now();
  }

  /**
   * Which of these devices of one JID to leave out as stale: silent past
   * STALE_AFTER_MS, unless that's all of them.
   *
   * @returns {Set<number>}
   */
  function staleAmong(store, jid, deviceIds) {
    const stale = new Set(deviceIds.filter((id) => now() - lastSignOf(store, jid, id) > STALE_AFTER_MS));
    return stale.size < new Set(deviceIds).size ? stale : new Set();
  }

  /**
   * The devices to encrypt for, grouped by the namespace each gets: twomemo
   * if it's on that JID's twomemo device list, otherwise oldmemo (4.2, per
   * device). Conversations-based clients such as Cheogram only speak
   * oldmemo, while our Thunderbird devices are on both lists, so one message
   * can need both. Bundles are attached where there's no session yet.
   */
  async function recipientsByNamespace(omemo, ourJid, peerJid) {
    const store = omemo.store;
    const ids = {};
    for (const ns of ["twomemo", "oldmemo"]) {
      ids[ns] = {
        [peerJid]: (await omemo.getDevices(ns, peerJid)).map((d) => d.id),
        [ourJid]: store.devices(ns, ourJid).map((d) => d.id).filter((id) => id !== store.deviceId),
      };
    }
    const byNs = { twomemo: [], oldmemo: [] };
    for (const jid of [peerJid, ourJid]) {
      for (const id of ids.twomemo[jid]) {
        byNs.twomemo.push({ jid, deviceId: id });
      }
      for (const id of ids.oldmemo[jid].filter((i) => !ids.twomemo[jid].includes(i))) {
        byNs.oldmemo.push({ jid, deviceId: id });
      }
    }
    for (const [ns, targets] of Object.entries(byNs)) {
      for (const t of targets) {
        if (!store.session(ns, t.jid, t.deviceId)) {
          try {
            t.bundle = (await omemo.getBundle(ns, t.jid, t.deviceId)) ?? undefined;
          } catch (e) {
            log(`${ns}: no usable bundle for ${t.jid} device ${t.deviceId}: ${e?.message ?? e}`);
          }
        }
      }
    }
    // Trust (milestone 5): leave out devices we don't encrypt to, and collect
    // what the user should hear about (new devices, changed keys).
    const notices = [];
    const heldBack = [];
    for (const [ns, targets] of Object.entries(byNs)) {
      byNs[ns] = targets.filter((t) => {
        const session = store.session(ns, t.jid, t.deviceId);
        const fingerprint = session
          ? fingerprintOfWireKey(ns, session.peerIdentityKey)
          : t.bundle ? formatFingerprint(t.bundle.identityKey.curve25519) : null;
        if (fingerprint === null) {
          return true; // no key to judge; encryptMessage reports it as unreachable
        }
        const decision = decideTrust(store, t.jid, t.deviceId, fingerprint);
        notices.push(...decision.notices);
        if (!decision.use) {
          heldBack.push(t);
        }
        return decision.use;
      });
    }
    // Milestone 6: leave out devices that have been silent for months.
    for (const jid of [peerJid, ourJid]) {
      const all = [...byNs.twomemo, ...byNs.oldmemo].filter((t) => t.jid === jid).map((t) => t.deviceId);
      const stale = staleAmong(store, jid, all);
      for (const id of stale) {
        log(`not encrypting to ${jid} device ${id}: no messages from it for over ${STALE_AFTER_MS / 86400000} days`);
      }
      for (const ns of ["twomemo", "oldmemo"]) {
        byNs[ns] = byNs[ns].filter((t) => t.jid !== jid || !stale.has(t.deviceId));
      }
    }
    return { byNs, notices, heldBack };
  }

  /**
   * Sends a message stanza with one <encrypted> per namespace; each client
   * reads the one it understands.
   *
   * @param {{ ns: string, encrypted: object }[]} parts
   */
  function sendEncryptedStanza(account, to, parts, withBody) {
    const children = [];
    if (withBody) {
      children.push(Stanza.node("body", null, null, FALLBACK_BODY));
    }
    for (const { ns, encrypted } of parts) {
      children.push(toXmlNode(buildEncrypted(ns, encrypted), Stanza));
    }
    children.push(Stanza.node("store", NS_HINTS));
    for (const { ns } of parts) {
      children.push(Stanza.node("encryption", NS_EME, { namespace: NS[ns], name: "OMEMO" }));
    }
    account.sendStanza(Stanza.node("message", null, { to, type: "chat" }, children));
  }

  /** Encrypts and sends one chat message; throws if it can't be encrypted. */
  async function sendEncrypted(conversation, text) {
    const account = conversation._account;
    const omemo = accounts.get(account);
    if (!omemo?.store) {
      throw new Error("OMEMO isn't ready for this account yet.");
    }
    const ourJid = bareJidOf(account);
    const peerJid = bare(conversation.to);
    const { byNs, notices, heldBack } = await recipientsByNamespace(omemo, ourJid, peerJid);
    for (const t of heldBack) {
      const state = omemo.store.trustOf(t.jid, omemo.store.deviceKey(t.jid, t.deviceId));
      log(`not encrypting to ${t.jid} device ${t.deviceId}: its key is ${state ?? "unknown"}`);
    }
    for (const notice of notices) {
      say(conversation, noticeText(notice));
    }
    if (![...byNs.twomemo, ...byNs.oldmemo].some((r) => r.jid === peerJid)) {
      if (heldBack.some((r) => r.jid === peerJid)) {
        throw new Error(`none of ${peerJid}'s devices are trusted yet (type /omemo to see them, then /omemo verify <device> or /omemo trust <device>).`);
      }
      throw new Error(`${peerJid} has no OMEMO devices${mode === "always" ? " (type /omemo off to allow unencrypted messages with them)" : ""}.`);
    }
    const parts = [];
    for (const ns of ["twomemo", "oldmemo"]) {
      if (!byNs[ns].length) {
        continue;
      }
      const { encrypted, skipped } = encryptMessage(omemo.store, ns, { ourJid, body: text, recipients: byNs[ns] });
      for (const s of skipped) {
        log(`${ns}: couldn't encrypt for ${s.jid} device ${s.deviceId}: ${s.reason}`);
      }
      if (encrypted.keys.length) {
        parts.push({ ns, encrypted });
      }
    }
    const reachesPeer = parts.some(({ ns, encrypted }) =>
      encrypted.keys.some((k) => byNs[ns].some((r) => r.jid === peerJid && r.deviceId === k.rid)));
    if (!reachesPeer) {
      throw new Error(`couldn't encrypt for any of ${peerJid}'s devices.`);
    }
    sendEncryptedStanza(account, conversation.to, parts, true);
    log(`sent an encrypted message to ${peerJid} (${parts.map(({ ns, encrypted }) => `${ns}: ${encrypted.keys.length} device keys`).join(", ")})`);
    // Local echo, as Thunderbird's own _displaySentMsg does.
    const who = account._connection?._jid?.jid || account.name;
    conversation.writeMessage(who, text, {
      outgoing: true,
      isEncrypted: true,
      _alias: conversation.account?.alias || conversation.account?.statusInfo?.displayName,
    });
  }

  /** An empty OMEMO message to one device, confirming a session it started (4.10). */
  function sendEmptyMessage(account, ns, peerJid, deviceId) {
    const omemo = accounts.get(account);
    const { encrypted } = encryptMessage(omemo.store, ns, {
      ourJid: bareJidOf(account),
      body: null,
      recipients: [{ jid: peerJid, deviceId }],
    });
    if (encrypted.keys.length) {
      sendEncryptedStanza(account, peerJid, [{ ns, encrypted }], false);
      log(`sent an empty ${ns} message to ${peerJid} device ${deviceId} to confirm the session`);
    }
  }

  /**
   * Decrypts an incoming message (or carbon) in place: the <encrypted> body
   * replaces the fallback <body>, or a notice does if decryption fails.
   *
   * @returns {"none"|"decrypted"|"failed"|"empty"} "empty": an empty OMEMO
   *   message, which shouldn't reach the conversation; "failed": a notice
   *   replaced the body.
   */
  function decryptInPlace(account, stanza) {
    const carbon = stanza.getChildren("sent").concat(stanza.getChildren("received")).find((c) => c.uri === NS_CARBONS);
    const isSent = carbon?.localName === "sent";
    const target = carbon ? carbon.getElement(["forwarded", "message"]) : stanza;
    const elements = (target?.children ?? []).filter((c) => c.type !== "text" && c.localName === "encrypted" && namespaceOf({ ns: c.uri }));
    const omemo = accounts.get(account);
    if (!elements.length || !omemo?.store) {
      return "none";
    }
    const ourJid = bareJidOf(account);
    const sender = target.attributes.from ?? ourJid;
    const peerJid = bare(isSent ? target.attributes.to : sender);
    if (!decrypts(account, peerJid)) {
      return "none";
    }

    // One <encrypted> per namespace the sender used; take the one with a key
    // for this device, twomemo first.
    const parsed = elements
      .map((e) => safely("parsing an <encrypted> element", () => parseEncrypted(fromXmlNode(e, e.uri))))
      .filter(Boolean)
      .sort((a, b) => (a.namespace === "twomemo" ? -1 : 0) - (b.namespace === "twomemo" ? -1 : 0));
    const us = { jid: ourJid, deviceId: omemo.store.deviceId };
    const chosen = parsed.find((m) => findOurKey(m, us)) ?? parsed[0];
    if (parsed.length && !parsed.some((m) => findOurKey(m, us)) && parsed.every((m) => m.payload === null)) {
      // An empty message for another of this account's devices (e.g. a
      // session confirmation for our phone): nothing for us to show.
      log(`ignored an empty message from ${bare(sender)} meant for another device`);
      return "empty";
    }

    let text;
    let empty = false;
    let failed = false;
    let untrusted = false;
    try {
      if (!chosen) {
        throw new Error("the <encrypted> element is malformed");
      }
      const message = chosen;
      const result = decryptMessage(omemo.store, message, { ourJid, sender });
      if (result.body === null) {
        empty = true;
      }
      text = result.body;
      omemo.store.recordMessageFrom(bare(sender), message.sid);
      log(`decrypted a ${message.namespace} ${empty ? "empty message" : "message"} from ${bare(sender)} device ${message.sid}`);
      // Trust (milestone 5): note new or changed keys, and don't vouch for a
      // message from a device we don't trust.
      const decision = decideTrust(omemo.store, bare(sender), message.sid, fingerprintOfWireKey(message.namespace, result.peerIdentityKey));
      if (!empty) {
        const lines = decision.notices.map((n) => `[OMEMO] ${noticeText(n)}`);
        if (!decision.use) {
          untrusted = true;
          lines.push(`[OMEMO] This message came from a device you don't trust (${bare(sender)} device ${message.sid}).`);
        }
        if (lines.length) {
          text = `${lines.join("\n")}\n${text}`;
        }
      }
      if (result.sessionStarted && !isSent) {
        safely("confirming a new session", () => sendEmptyMessage(account, message.namespace, bare(sender), message.sid));
      }
      if (result.preKeyUsed !== null) {
        omemo.republishBundle(message.namespace).catch((e) => log(`ERROR: republishing our bundle failed: ${e?.message ?? e}`));
      }
    } catch (e) {
      failed = true;
      text = e instanceof OmemoError ? DECRYPT_NOTICES[e.code] : `[OMEMO] This message couldn't be read: ${e?.message ?? e}`;
      log(`couldn't decrypt a message from ${bare(sender)}: ${e?.message ?? e}`);
    }
    // Swap the fallback body (and any HTML version) for what we decrypted.
    target.children = target.children.filter((c) => c.type === "text" || (c.localName !== "body" && c.localName !== "html"));
    if (text !== null && text !== undefined) {
      target.addChild(Stanza.node("body", null, null, text));
    }
    // "failed" also for an untrusted sender: it gets no padlock.
    return empty ? "empty" : failed || untrusted ? "failed" : "decrypted";
  }

  conv.dispatchMessage = function (aMsg, aAction = false) {
    const wants = safely("dispatchMessage", () => {
      log(`dispatchMessage hook fired: to ${this.to}, ${String(aMsg).length} characters, action ${Boolean(aAction)}`);
      tb.onOutgoing?.(this.id, String(aMsg));
      return wantsEncryption(this._account, bare(this.to));
    }) ?? "no";
    if (wants === "no" && !this._omemoQueue) {
      return originals.get("dispatchMessage").call(this, aMsg, aAction);
    }
    // Same /me handling as Thunderbird's own dispatchMessage.
    const text = aAction ? `/me${aMsg}` : String(aMsg);
    // One queue per conversation keeps rapid messages in order (4.3), also
    // with plaintext ones in between once the queue exists.
    this._omemoQueue = (this._omemoQueue ?? Promise.resolve())
      .then(async () => {
        const account = this._account;
        const peerJid = bare(this.to);
        let decision = wants;
        if (decision === "not-ready") {
          // Sent while OMEMO starts: wait for it rather than guess.
          await started.get(account);
          decision = wantsEncryption(account, peerJid);
          if (decision === "not-ready") {
            throw new Error("OMEMO isn't ready for this account yet, so it can't tell whether this chat is encrypted. Try again in a moment.");
          }
        }
        let encrypt = decision === "yes";
        if (decision === "if-devices") {
          const { found, error } = await lookUpDevices(account, peerJid);
          if (found === null) {
            throw new Error(`couldn't check whether ${peerJid} uses OMEMO (${error}). Try again in a moment.`);
          }
          encrypt = found;
        }
        if (!encrypt) {
          originals.get("dispatchMessage").call(this, aMsg, aAction);
          return;
        }
        await sendEncrypted(this, text);
      })
      .catch((e) => {
        log(`ERROR: an encrypted message to ${this.to} was not sent: ${e?.message ?? e}`);
        safely("showing a send error", () => this.writeMessage(this.name,
          `[OMEMO] Your message was not sent, because it couldn't be encrypted: ${e?.message ?? e}`, { system: true, error: true }));
      });
    delete this._typingState;
    return undefined;
  };

  acct.onConnection = function (...args) {
    const result = originals.get("onConnection").apply(this, args);
    safely("starting OMEMO", () => startAccount(this));
    return result;
  };

  acct._disconnect = function (...args) {
    safely("stopping OMEMO", () => {
      stopAccount(this);
    });
    return originals.get("_disconnect").apply(this, args);
  };

  acct.sendStanza = function (aStanza, ...rest) {
    safely("adding caps to presence", () => {
      // Our broadcast presence: no addressee, no type (available).
      if (aStanza?.qName === "presence" && !aStanza.attributes.to && !aStanza.attributes.type
          && !aStanza.getChildren("c").some((c) => c.uri === NS_CAPS)) {
        aStanza.addChild(Stanza.node("c", NS_CAPS, { hash: "sha-1", node: CAPS_NODE, ver: ver() }));
      }
    });
    return originals.get("sendStanza").call(this, aStanza, ...rest);
  };

  acct.onIQStanza = function (aStanza, ...rest) {
    const handled = safely("answering disco#info for our caps", () => {
      const query = aStanza.getElement(["query"]);
      if (aStanza.attributes.type !== "get" || query?.uri !== NS_DISCO_INFO) {
        return false;
      }
      const node = query.attributes.node;
      if (node !== `${CAPS_NODE}#${ver()}`) {
        return false;
      }
      const children = [
        Stanza.node("identity", null, identity()),
        ...SupportedFeatures.map((feature) => Stanza.node("feature", null, { var: feature })),
      ];
      this.sendStanza(Stanza.iq("result", aStanza.attributes.id, aStanza.attributes.from,
        Stanza.node("query", NS_DISCO_INFO, { node }, children)));
      return true;
    });
    if (handled) {
      return undefined;
    }
    return originals.get("onIQStanza").call(this, aStanza, ...rest);
  };

  acct.onMessageStanza = function (aStanza, ...rest) {
    const swallowed = safely("reading an OMEMO device list push", () => {
      const event = aStanza.getElement(["event"]);
      if (event?.uri !== NS_PUBSUB_EVENT) {
        return false;
      }
      const parsed = parseEvent(fromXmlNode(aStanza));
      if (!parsed || !DEVICE_LIST_NODES.has(parsed.node)) {
        return false;
      }
      const omemo = accounts.get(this);
      log(`device list push for ${parsed.node} from ${parsed.from ?? "our account"} to ${bareJidOf(this)}`);
      omemo?.handleEvent(parsed)
        .then(() => {
          const who = parsed.from ? bare(parsed.from) : bareJidOf(this);
          noDevicesUntil.delete(`${bareJidOf(this)} ${who}`);
          notifyConversations(this, who);
        })
        .catch((e) => log(`ERROR: handling a device list push failed: ${e?.message ?? e}`));
      return true;
    });
    if (swallowed) {
      return undefined;
    }
    const outcome = safely("decrypting a message", () => decryptInPlace(this, aStanza));
    if (outcome === "empty") {
      return undefined;
    }
    if (outcome === "decrypted") {
      const kind = aStanza.getChildren("sent").some((c) => c.uri === NS_CARBONS) ? "our own message from another device"
        : aStanza.getChildren("received").some((c) => c.uri === NS_CARBONS) ? "a carbon of an incoming message" : "an incoming message";
      const writesBefore = markedWrites;
      markEncrypted++;
      try {
        return originals.get("onMessageStanza").call(this, aStanza, ...rest);
      } finally {
        markEncrypted--;
        // Diagnostics for a missing padlock (2026-09-26).
        log(markedWrites > writesBefore
          ? `padlock: ${kind} was shown as encrypted`
          : `padlock: Thunderbird didn't show ${kind} while handling it, so it gets no padlock`);
      }
    }
    safely("onMessageStanza diagnostics", () => {
      const element = aStanza.getElement(["encrypted"]);
      const encrypted = element && [NS.oldmemo, NS.twomemo].includes(element.uri) ? element : null;
      log(`onMessageStanza hook fired: from ${aStanza.attributes.from}, type ${aStanza.attributes.type}, `
        + (encrypted ? `<encrypted> in ${encrypted.uri}` : "no OMEMO <encrypted>"));
      if (encrypted) {
        tb.onIncomingEncrypted?.(String(aStanza.attributes.from), { namespace: encrypted.uri, xml: encrypted.getXML() });
      }
    });
    return originals.get("onMessageStanza").call(this, aStanza, ...rest);
  };

  // While Thunderbird handles a message we decrypted, whatever it writes to a
  // conversation (the incoming message, or a carbon of our own) gets the
  // encrypted flag, so it shows a padlock like our local echo does.
  let markEncrypted = 0;
  let markedWrites = 0;
  const inheritedWriteMessage = conv.writeMessage;
  if (typeof inheritedWriteMessage === "function") {
    patchOwn(conv, "writeMessage", {
      value(who, text, properties) {
        if (markEncrypted > 0 && properties && !properties.system && !properties.error) {
          properties = { ...properties, isEncrypted: true };
          markedWrites++;
        } else if (markEncrypted > 0) {
          log(`padlock: not marking a message written with ${properties ? `flags ${Object.keys(properties).join(", ")}` : "no flags"}`);
        }
        return inheritedWriteMessage.call(this, who, text, properties);
      },
    });
  }

  // Thunderbird's own encryption button and status for XMPP 1:1 chats.
  if (states) {
    patchOwn(conv, "encryptionState", {
      get() {
        return safely("reading the encryption state", () => encryptionStateOf(this)) ?? states.NOT_SUPPORTED;
      },
    });
    patchOwn(conv, "initializeEncryption", {
      value() {
        safely("switching encryption on", () => {
          const omemo = accounts.get(this._account);
          const peerJid = bare(this.to);
          if (mode === null || !omemo?.store) {
            log(`encryption can't be switched on for ${peerJid} in this build`);
            return;
          }
          omemo.store.setEncryptionChoice(peerJid, "on");
          log(`encryption switched on for ${peerJid}`);
          notifyConversation(this);
        });
      },
    });
  }

  const MODE_NAMES = {
    manual: "off unless switched on per chat",
    available: "always use OMEMO when available",
    always: "always use OMEMO",
  };

  /** Writes a line from the add-on into a conversation. */
  function say(conversation, text) {
    conversation.writeMessage(conversation.name, `[OMEMO] ${text}`, { system: true, noLog: true });
  }

  /**
   * The /omemo command: status, on/off/default for this chat, trust, or
   * the add-on's page (help, qr).
   *
   * @returns {boolean} whether the command applied (an XMPP 1:1 chat).
   */
  function runCommand(conversation, args) {
    if (!conv.isPrototypeOf(conversation)) {
      return false;
    }
    const account = conversation._account;
    const omemo = accounts.get(account);
    const peerJid = bare(conversation.to);
    const word = String(args ?? "").trim().toLowerCase();
    // The add-on's page needs nothing from this account.
    const pages = { help: ["instructions", "the instructions"], qr: ["verify", "the QR code for your phone"] };
    if (word in pages) {
      const [section, what] = pages[word];
      if (tb.onShowPage) {
        tb.onShowPage(section);
        say(conversation, `Opening ${what} in a new tab.`);
      } else {
        say(conversation, `See ${what} in Add-ons and Themes > OMEMO > Options.`);
      }
      return true;
    }
    if (!omemo?.store) {
      say(conversation, "OMEMO isn't ready for this account yet.");
      return true;
    }
    // Trust can be set whatever the encryption setting.
    const [verb, deviceArg, ...fingerprintWords] = word.split(/\s+/);
    if (["verify", "trust", "distrust"].includes(verb)) {
      setDeviceTrust(conversation, omemo, peerJid, verb, deviceArg, fingerprintWords.join(""));
      return true;
    }
    if (verb === "remove") {
      removeOwnDevice(conversation, omemo, deviceArg);
      return true;
    }
    if (mode === null && word !== "" && word !== "status") {
      say(conversation, "This build doesn't let you change encryption per chat.");
      return true;
    }
    const choices = { on: "on", off: "off", default: null };
    if (word in choices) {
      omemo.store.setEncryptionChoice(peerJid, choices[word]);
      notifyConversation(conversation);
      say(conversation, word === "on"
        ? "Encryption is on for this chat."
        : word === "off"
          ? "Encryption is off for this chat: messages go out unencrypted."
          : `This chat follows your setting again (${MODE_NAMES[mode]}).`);
      return true;
    }
    if (word !== "" && word !== "status") {
      say(conversation, "Usage: /omemo [on | off | default | status | help | qr | verify <device> [fingerprint] | trust <device> | distrust <device> | remove <device>]. Type /omemo help for what each one does.");
      return true;
    }
    // Status, once we know the contact's devices.
    lookUpDevices(account, peerJid).then(({ found, error }) => {
      const store = omemo.store;
      const ourJid = bareJidOf(account);
      const wants = wantsEncryption(account, peerJid);
      const lines = [
        `Setting: ${mode === null ? "test build (fixed list)" : MODE_NAMES[mode]}; this chat: ${store.encryptionChoice(peerJid) ?? "follows the setting"}.`,
        `Messages to ${peerJid} are ${wants === "yes" || (wants === "if-devices" && knownToHaveDevices(account, peerJid)) ? "encrypted" : "not encrypted"}.`,
        `This Thunderbird: device ${store.deviceId}, fingerprint ${formatFingerprint(store.identityKeyPair().publicKey.curve25519)}`,
      ];
      const contact = deviceLines(store, peerJid);
      lines.push(contact.length ? `${peerJid}'s devices:`
        : found === null ? `${peerJid}'s OMEMO devices couldn't be looked up just now (${error}).`
          : `${peerJid} has no OMEMO devices.`, ...contact);
      const own = deviceLines(store, ourJid);
      if (own.length) {
        // Not "(jid):", which Thunderbird turns into a frowning smiley.
        lines.push(`Your other devices, on ${ourJid}:`, ...own);
      }
      if ([...contact, ...own].some((l) => l.includes(QUIET))) {
        lines.push("Every app install is its own device, and old installs stay listed. A device you haven't heard from lately is most likely an old install.");
      }
      say(conversation, lines.join("\n"));
    }).catch((e) => say(conversation, `Couldn't get the status: ${e?.message ?? e}`));
    return true;
  }

  /**
   * One line per device a JID lists (other than this Thunderbird), most
   * recently heard from first: its number, label or namespace, when its last
   * message came, fingerprint and trust.
   */
  function deviceLines(store, jid) {
    const twomemo = store.devices("twomemo", jid);
    const oldmemo = store.devices("oldmemo", jid);
    const ids = [...new Set([...twomemo, ...oldmemo].map((d) => d.id))].filter((id) => id !== store.deviceId);
    const last = (id) => store.lastMessageFrom(jid, id) ?? -1;
    const usable = ids.filter((id) => {
      const fp = store.deviceKey(jid, id);
      const state = fp ? store.trustOf(jid, fp) : null;
      return state !== "undecided" && state !== "distrusted";
    });
    const stale = staleAmong(store, jid, usable);
    return ids.sort((a, b) => last(b) - last(a)).map((id) => {
      const label = twomemo.find((d) => d.id === id)?.label;
      const kind = label ? `"${label}"` : twomemo.some((d) => d.id === id) ? "newer OMEMO" : "older OMEMO";
      const fp = store.deviceKey(jid, id);
      const trust = fp ? `${fp} (${TRUST_DESCRIPTIONS[store.trustOf(jid, fp)] ?? "unknown"})` : "fingerprint not known yet";
      const skipped = stale.has(id) ? `; left out when encrypting (silent over ${STALE_AFTER_MS / 86400000} days)` : "";
      return `- device ${id}, ${kind}: ${heardFrom(store.lastMessageFrom(jid, id))}; ${trust}${skipped}`;
    });
  }

  // How long without a message before /omemo status flags a device.
  const QUIET_AFTER_MS = 30 * 24 * 60 * 60 * 1000;
  const QUIET = "no messages";

  /** "last message 3 hours ago", or a no-messages note. */
  function heardFrom(time) {
    if (time === null) {
      return `${QUIET} from it yet`;
    }
    const minutes = Math.max(0, Math.round((now() - time) / 60000));
    const ago = minutes < 2 ? "just now"
      : minutes < 120 ? `${minutes} minutes ago`
        : minutes < 48 * 60 ? `${Math.round(minutes / 60)} hours ago`
          : `${Math.round(minutes / (24 * 60))} days ago`;
    return now() - time > QUIET_AFTER_MS ? `${QUIET} for ${ago.replace(" ago", "")}` : `last message ${ago}`;
  }

  /**
   * /omemo remove <device>: takes one of this account's old installs off our
   * device lists (milestone 6).
   */
  function removeOwnDevice(conversation, omemo, deviceArg) {
    const store = omemo.store;
    const account = conversation._account;
    const ourJid = bareJidOf(account);
    if (!deviceArg) {
      say(conversation, "Add a device number: /omemo remove <device>. Type /omemo to see your other devices.");
      return;
    }
    const deviceId = Number(deviceArg);
    if (deviceId === store.deviceId) {
      say(conversation, `Device ${deviceId} is this Thunderbird, which can't remove itself.`);
      return;
    }
    const ours = ["twomemo", "oldmemo"].some((ns) => store.devices(ns, ourJid).some((d) => d.id === deviceId));
    if (!Number.isInteger(deviceId) || !ours) {
      say(conversation, `Device ${deviceArg} isn't one of your devices (${ourJid}). Only your own devices can be removed; type /omemo to see them.`);
      return;
    }
    omemo.removeOwnDevice(deviceId).then((removed) => {
      notifyConversations(account);
      say(conversation, removed.length
        ? `Removed device ${deviceId} from your device list. If that app is still in use, it adds itself back the next time it connects.`
        : `Device ${deviceId} was already off your device list.`);
    }).catch((e) => say(conversation, `Couldn't remove device ${deviceId}: ${e?.message ?? e}`));
  }

  /**
   * /omemo verify|trust|distrust <device> [fingerprint]: sets our trust in a
   * device of the contact's (or one of our own) by its current key.
   */
  function setDeviceTrust(conversation, omemo, peerJid, verb, deviceArg, fingerprintArg) {
    const store = omemo.store;
    const ourJid = bareJidOf(conversation._account);
    if (!deviceArg) {
      say(conversation, `Add a device number: /omemo ${verb} <device>. Type /omemo to see the device numbers.`);
      return;
    }
    const deviceId = Number(deviceArg);
    const listed = (jid) => ["twomemo", "oldmemo"].filter((ns) => store.devices(ns, jid).some((d) => d.id === deviceId));
    // A device counts if it's on a device list or we've seen its key.
    const known = (jid) => listed(jid).length > 0 || store.deviceKey(jid, deviceId) !== null;
    const jid = known(peerJid) ? peerJid : known(ourJid) ? ourJid : null;
    if (!Number.isInteger(deviceId) || jid === null) {
      say(conversation, `There's no device ${deviceArg} for ${peerJid} (or for you). Type /omemo to see the device numbers.`);
      return;
    }
    (async () => {
      let fp = store.deviceKey(jid, deviceId);
      if (fp === null) {
        // No message from it yet: take the key from its published bundle.
        const ns = listed(jid)[0] ?? "twomemo";
        const bundle = await omemo.getBundle(ns, jid, deviceId);
        if (!bundle) {
          throw new Error(`device ${deviceId} hasn't published its keys`);
        }
        fp = formatFingerprint(bundle.identityKey.curve25519);
        store.setDeviceKey(jid, deviceId, fp);
      }
      if (verb === "verify" && fingerprintArg && fingerprintArg.replace(/\s/g, "") !== fp.replace(/ /g, "")) {
        say(conversation, `That fingerprint doesn't match device ${deviceId}'s key (${fp}). Not verified.`);
        return;
      }
      const state = { verify: "verified", trust: "trusted", distrust: "distrusted" }[verb];
      store.setTrust(jid, fp, state);
      notifyConversation(conversation);
      say(conversation, `${jid === ourJid ? "Your" : `${jid}'s`} device ${deviceId} (${fp}) is now ${TRUST_DESCRIPTIONS[state]}.`);
    })().catch((e) => say(conversation, `Couldn't ${verb} device ${deviceId}: ${e?.message ?? e}`));
  }

  /**
   * This Thunderbird's device on each ready account, for the options page's
   * "verify on your phone" QR codes.
   *
   * @returns {{ jid: string, deviceId: number, fingerprint: string, uri: string }[]}
   */
  function ownDevices() {
    const out = [];
    for (const [account, omemo] of accounts) {
      if (omemo.store) {
        const jid = bareJidOf(account);
        const fingerprint = formatFingerprint(omemo.store.identityKeyPair().publicKey.curve25519);
        out.push({ jid, deviceId: omemo.store.deviceId, fingerprint, uri: verificationUri(jid, [{ deviceId: omemo.store.deviceId, fingerprint }]) });
      }
    }
    return out.sort((a, b) => a.jid.localeCompare(b.jid));
  }

  /** Changes the mode (from the options page); redraws every chat's lock. */
  function updateSettings(settings) {
    const next = settings?.mode ?? null;
    if (next !== null && !MODES.includes(next)) {
      throw new Error(`Unknown encryption mode "${next}".`);
    }
    mode = next;
    log(`encryption setting: ${mode === null ? "test build (fixed list)" : MODE_NAMES[mode]}`);
    for (const account of accounts.keys()) {
      notifyConversations(account);
    }
  }

  // Accounts that connected before we were installed.
  for (const account of safely("listing connected accounts", () => tb.connectedAccounts?.() ?? []) ?? []) {
    safely("starting OMEMO for a connected account", () => startAccount(account));
  }
  log(`hooks installed; caps ver ${ver()}`);

  return {
    accounts,
    runCommand,
    updateSettings,
    ownDevices,
    saveAll,
    async uninstall() {
      for (const [proto, name] of targets) {
        proto[name] = originals.get(name);
      }
      for (const { obj, name, previous } of ownPatches.reverse()) {
        if (previous) {
          Object.defineProperty(obj, name, previous);
        } else {
          delete obj[name];
        }
      }
      for (const f of addedFeatures) {
        const i = SupportedFeatures.indexOf(f);
        if (i >= 0) {
          SupportedFeatures.splice(i, 1);
        }
      }
      await Promise.all([...accounts.keys()].map((a) => stopAccount(a)));
      await Promise.all(pendingSaves);
      maintenanceTimers.clear();
    },
  };
}
