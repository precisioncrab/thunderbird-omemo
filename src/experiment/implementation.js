/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Experiment API implementation. This file runs in the privileged
 * "addon_parent" scope declared in manifest.json's experiment_apis entry,
 * which is what lets it reach into Thunderbird's internal chat modules the
 * same way in-tree code (e.g. chat/modules/OTR.sys.mjs) does.
 *
 * It only does what needs this scope: load the bundled core
 * (dist/omemo-core.mjs) and Thunderbird's modules, and hand them to the
 * core's installBridge (src/omemo/bridge.js), which holds all the hooks
 * and is tested in Node against a fake Thunderbird. Confirmed in
 * Thunderbird on 2026-09-25: the modules load, the hook targets exist and
 * fire, and the core's self-test passes (docs/STATUS.md).
 *
 * Neither hook exists as a stable, versioned WebExtension API today, which is
 * exactly why this needs an Experiment. Expect to revisit the hooks on
 * Thunderbird upgrades; see docs/PLAN.md "Open risks worth tracking".
 */

var { ExtensionCommon } = ChromeUtils.importESModule(
  "resource://gre/modules/ExtensionCommon.sys.mjs"
);

const XMPP_BASE_URL = "resource:///modules/xmpp-base.sys.mjs";
const XMPP_XML_URL = "resource:///modules/xmpp-xml.sys.mjs";
const IM_SERVICES_URL = "resource:///modules/IMServices.sys.mjs";
const TIMER_URL = "resource://gre/modules/Timer.sys.mjs";

// The core, bundled by scripts/build.mjs, loads from the add-on's own files
// through a resource:// name (docs/TASKS.md 3.1). Gecko caches ES modules by
// URL, even across restarts (0.0.7 got 0.0.6's core that way), so each load
// uses a fresh name, and the core's version is checked against ours.
const RESOURCE_PREFIX = "thunderbird-omemo";
let _resourceName = null;

let _core = null;
let _bridge = null;

// The encryption setting from the options page (docs/TASKS.md 4.1); the
// background script sends it with setSettings, possibly before install().
// Opt-in by default: nothing is encrypted until the user switches a chat on
// (the maintainer's decision, 2026-09-25; this replaced the test1/test2-only list of
// the first test builds).
let _settings = { mode: "manual" };

// The /omemo chat command, for XMPP 1:1 chats.
const PRPL_XMPP = "prpl-jabber";
let _commandRegistered = false;

// Listeners from the background script. Module-level, because the bridge
// is installed once for the whole add-on.
const _outgoingSinks = new Set();
const _incomingSinks = new Set();
const _diagnosticSinks = new Set();
const _pageSinks = new Set();

function fireAll(sinks, ...args) {
  for (const fire of sinks) {
    try {
      fire.async(...args);
    } catch {
      // a closed context; its unregister will follow
    }
  }
}

// Diagnostics: one line per notable event to the Browser Console
// (Ctrl+Shift+J), also forwarded to the add-on's own console (onDiagnostic).
// Only lengths, addresses and ids are logged, never message text. Lines from
// before the background listens are kept and replayed.
const _diagnosticBacklog = [];
const DIAGNOSTIC_BACKLOG_MAX = 100;

function diag(message) {
  console.log(`[omemo] ${message}`);
  _diagnosticBacklog.push(message);
  if (_diagnosticBacklog.length > DIAGNOSTIC_BACKLOG_MAX) {
    _diagnosticBacklog.shift();
  }
  fireAll(_diagnosticSinks, message);
}

// Run fn, logging instead of throwing (errors thrown from an Experiment
// reach the add-on only as a generic message).
function safely(what, fn) {
  try {
    return fn();
  } catch (e) {
    console.error(`[omemo] ${what} failed:`, e);
    diag(`ERROR: ${what} failed: ${e?.message ?? e}`);
    return undefined;
  }
}

// Thunderbird waits at shutdown until every key store is saved: writes are
// batched a moment after each change, and a lost ratchet change breaks the
// next message. IOUtils.profileBeforeChange is the shutdown phase meant for
// last writes (JSONFile uses it); AsyncShutdown's is the same phase.
let _saveBlocker = null;

function addSaveBlocker(bridge) {
  safely("registering the save at shutdown", () => {
    const client = (typeof IOUtils !== "undefined" && IOUtils.profileBeforeChange)
      || ChromeUtils.importESModule("resource://gre/modules/AsyncShutdown.sys.mjs").AsyncShutdown.profileBeforeChange;
    const condition = () => bridge.saveAll();
    client.addBlocker("OMEMO: saving the key stores", condition);
    _saveBlocker = { client, condition };
  });
}

function removeSaveBlocker(blocker) {
  if (blocker) {
    safely("removing the save at shutdown", () => blocker.client.removeBlocker(blocker.condition));
  }
}

function resourceHandler() {
  return Cc["@mozilla.org/network/protocol;1?name=resource"].getService(Ci.nsISubstitutingProtocolHandler);
}

// Thunderbird's own secure random generator, for when the module scope has
// no Web Crypto (it had it when checked on 2026-09-25). Newer builds have
// generateRandomBytesInto; older ones return an array from generateRandomBytes.
function xpcomRandomBytes(n) {
  const rng = Cc["@mozilla.org/security/random-generator;1"].getService(Ci.nsIRandomGenerator);
  if (typeof rng.generateRandomBytesInto === "function") {
    const out = new Uint8Array(n);
    rng.generateRandomBytesInto(out);
    return out;
  }
  return Uint8Array.from(rng.generateRandomBytes(n));
}

/** Loads the core and runs its self-test; returns it, or null on failure. */
function loadCore(extension) {
  return safely("loading the core", () => {
    _resourceName = `${RESOURCE_PREFIX}-${Date.now().toString(36)}`;
    resourceHandler().setSubstitution(_resourceName, extension.rootURI);
    const core = ChromeUtils.importESModule(`resource://${_resourceName}/dist/omemo-core.mjs`);
    if (core.CORE_VERSION !== extension.version) {
      throw new Error(`the core is version ${core.CORE_VERSION ?? "unknown"}, but the add-on is ${extension.version}; restart Thunderbird`);
    }
    if (!core.hasWebCrypto()) {
      core.setRandomSource(xpcomRandomBytes);
      diag("no Web Crypto in the core's scope; using Thunderbird's nsIRandomGenerator");
    }
    diag(core.selfTest());
    return core;
  }) ?? null;
}

/** XMPP accounts that are connected right now. */
function connectedXmppAccounts(xmppBase) {
  const { IMServices } = ChromeUtils.importESModule(IM_SERVICES_URL);
  return IMServices.accounts.getAccounts()
    .filter((a) => a.connected)
    .map((a) => a.prplAccount?.wrappedJSObject ?? a.prplAccount)
    .filter((p) => p && xmppBase.XMPPAccountPrototype.isPrototypeOf(p));
}

this.omemoXmpp = class extends ExtensionCommon.ExtensionAPI {
  getAPI(context) {
    const { EventManager } = ExtensionCommon;
    const event = (name, sinks, replay = []) => new EventManager({
      context,
      name: `omemoXmpp.${name}`,
      register(fire) {
        for (const line of replay) {
          fire.async(line);
        }
        sinks.add(fire);
        return () => sinks.delete(fire);
      },
    }).api();

    return {
      omemoXmpp: {
        async install() {
          if (_bridge) {
            return;
          }
          _core ??= loadCore(context.extension);
          if (!_core) {
            throw new Error("[omemo] The core didn't load; see the [omemo] ERROR line.");
          }
          const loaded = safely("loading Thunderbird's XMPP modules", () => {
            const xmppBase = ChromeUtils.importESModule(XMPP_BASE_URL);
            const { Stanza, SupportedFeatures } = ChromeUtils.importESModule(XMPP_XML_URL);
            const { setTimeout, clearTimeout } = ChromeUtils.importESModule(TIMER_URL);
            diag(`loaded ${XMPP_BASE_URL}; exports: ${Object.keys(xmppBase).join(", ")}`);
            return { xmppBase, Stanza, SupportedFeatures, setTimeout, clearTimeout };
          });
          if (!loaded) {
            throw new Error("[omemo] Thunderbird's XMPP modules didn't load; see the [omemo] ERROR line.");
          }
          const { xmppBase, Stanza, SupportedFeatures, setTimeout, clearTimeout } = loaded;
          _bridge = safely("installing the hooks", () => _core.bridge.installBridge({
            xmppBase,
            Stanza,
            SupportedFeatures,
            setTimer: setTimeout,
            clearTimer: clearTimeout,
            appName: (typeof Services !== "undefined" && Services.appinfo?.name) || "Thunderbird",
            fileAccessFor: (jid) => _core.persist.geckoFileAccess(jid),
            connectedAccounts: () => connectedXmppAccounts(xmppBase),
            log: diag,
            onOutgoing: (conversationId, text) => fireAll(_outgoingSinks, conversationId, text),
            onIncomingEncrypted: (from, payload) => fireAll(_incomingSinks, from, payload),
            mode: _settings.mode,
            onShowPage: (section) => fireAll(_pageSinks, section),
            encryptionStates: {
              NOT_SUPPORTED: Ci.prplIConversation.ENCRYPTION_NOT_SUPPORTED,
              AVAILABLE: Ci.prplIConversation.ENCRYPTION_AVAILABLE,
              ENABLED: Ci.prplIConversation.ENCRYPTION_ENABLED,
              TRUSTED: Ci.prplIConversation.ENCRYPTION_TRUSTED,
            },
          })) ?? null;
          if (!_bridge) {
            throw new Error("[omemo] The hooks didn't install; see the [omemo] ERROR line.");
          }
          addSaveBlocker(_bridge);
          safely("registering the /omemo command", () => {
            const { IMServices } = ChromeUtils.importESModule(IM_SERVICES_URL);
            IMServices.cmd.registerCommand({
              name: "omemo",
              get helpString() {
                return "omemo [on|off|default|status|help|qr|verify|trust|distrust|remove]: OMEMO encryption for this chat. /omemo help opens the instructions for each command. Without a word, shows the status, devices and fingerprints.";
              },
              usageContext: IMServices.cmd.COMMAND_CONTEXT.IM,
              priority: IMServices.cmd.COMMAND_PRIORITY.PRPL,
              run(aMsg, aConv) {
                const conversation = aConv?.wrappedJSObject ?? aConv;
                return safely("running /omemo", () => _bridge?.runCommand(conversation?.target ?? conversation, aMsg)) ?? false;
              },
            }, PRPL_XMPP);
            _commandRegistered = true;
          });
        },

        async getOwnDevices() {
          return safely("listing this Thunderbird's devices", () => _bridge?.ownDevices()) ?? [];
        },

        async setSettings(settings) {
          _settings = { mode: settings?.mode ?? "manual" };
          safely("applying the encryption setting", () => _bridge?.updateSettings(_settings));
        },

        async uninstall() {
          const bridge = _bridge;
          const blocker = _saveBlocker;
          _bridge = null;
          _saveBlocker = null;
          try {
            await bridge?.uninstall();
          } finally {
            removeSaveBlocker(blocker);
          }
        },

        onOutgoingPlaintext: event("onOutgoingPlaintext", _outgoingSinks),
        onDiagnostic: event("onDiagnostic", _diagnosticSinks, _diagnosticBacklog),
        onIncomingEncrypted: event("onIncomingEncrypted", _incomingSinks),
        onShowPage: event("onShowPage", _pageSinks),
      },
    };
  }

  onShutdown(isAppShutdown) {
    if (_commandRegistered) {
      _commandRegistered = false;
      safely("unregistering the /omemo command", () => {
        ChromeUtils.importESModule(IM_SERVICES_URL).IMServices.cmd.unregisterCommand("omemo", PRPL_XMPP);
      });
    }
    const bridge = _bridge;
    const blocker = _saveBlocker;
    _bridge = null;
    _saveBlocker = null;
    // Restores Thunderbird's functions at once; the key stores finish saving
    // in the background. The shutdown blocker stays until they have, so
    // quitting meanwhile still waits for them; at app shutdown it's what
    // Thunderbird is waiting on, so it stays.
    bridge?.uninstall()
      .catch((e) => console.error("[omemo] uninstall failed:", e))
      .finally(() => {
        if (!isAppShutdown) {
          removeSaveBlocker(blocker);
        }
      });
    if (_resourceName) {
      const name = _resourceName;
      _resourceName = null;
      _core = null;
      safely("unregistering the resource:// name", () => resourceHandler().setSubstitution(name, null));
    }
  }
};
