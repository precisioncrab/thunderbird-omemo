/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * One account's OMEMO lifecycle over PEP (docs/TASKS.md 3.6-3.9), built on
 * the key store, pep.js and formats.js. Everything Thunderbird-specific is
 * passed in (the PEP transport and file access), so this runs in Node
 * against the fake pubsub server.
 *
 * start(), on connect: load the key store, or create one (first connect)
 * with a device id not already in our device lists; then, per namespace,
 * add our device to our device list, keeping the other devices on it, and
 * publish that list and our bundle. A namespace whose PEP fails is logged
 * and skipped; the other still works.
 *
 * handleEvent(), for PEP notifications: a contact's device list updates the
 * store, and a change to our own list that drops our device (another client
 * cleaning up) republishes it with our device back in.
 *
 * Milestone 6: start() and maintain() (which the bridge runs every few
 * hours) replace a signed prekey that's a week old and republish the
 * bundle; removeOwnDevice() takes one of this account's old installs off
 * our device lists.
 */

import * as keys from "../crypto/keys.js";
import { OmemoStore, createStore, bareJid } from "./store.js";
import { createSaver } from "./persist.js";
import { createPep } from "./pep.js";
import * as formats from "./formats.js";

/** Our device's label in twomemo device lists. */
export const DEVICE_LABEL = "Thunderbird";

/**
 * How long a contact's device list, fetched or pushed during this
 * connection, is used without fetching it again. A list saved from an
 * earlier connection is always fetched again before use: a device removed
 * while we were offline must not keep getting our messages.
 */
export const DEVICE_LIST_MAX_AGE_MS = 60 * 60 * 1000;

/**
 * @param {object} options
 * @param {string} options.jid - the account's JID.
 * @param {(iq: object) => Promise<object>} options.sendIq - PEP transport.
 * @param {import("./persist.js").FileAccess} options.fileAccess
 * @param {(line: string) => void} [options.log]
 * @param {(n: number) => Uint8Array} [options.random]
 * @param {() => number} [options.now]
 * @param {object} [options.saverOptions] - passed to createSaver.
 */
export function createOmemoAccount({ jid, sendIq, fileAccess, log = () => {}, random, now, saverOptions = {} }) {
  const ourJid = bareJid(jid);
  const pep = createPep(sendIq);
  let store = null;
  const saver = createSaver(fileAccess, () => JSON.stringify(store.toJSON()), {
    onError: (e) => log(`ERROR: saving the key store failed: ${e?.message ?? e}`),
    ...saverOptions,
  });
  const storeOptions = { onChange: () => saver.schedule(), ...(random ? { random } : {}), ...(now ? { now } : {}) };
  const clock = now ?? Date.now;
  // When each contact's device list was last fetched or pushed in this
  // connection: "<ns> <jid>" -> time. Empty on every connect, since a new
  // account object is made each time.
  const listFetchedAt = new Map();
  const markFresh = (ns, jid) => listFetchedAt.set(`${ns} ${jid}`, clock());
  const isFresh = (ns, jid) => clock() - (listFetchedAt.get(`${ns} ${jid}`) ?? -Infinity) < DEVICE_LIST_MAX_AGE_MS;

  /** Our published device list for a namespace, or [] if there is none. */
  async function fetchDeviceList(ns, who) {
    const { node, itemId } = formats.deviceListLocation(ns);
    const items = await pep.fetchItems(who === ourJid ? null : who, node);
    // XEP-0384 uses item "current"; take the newest item if it's missing.
    const item = items.find((i) => i.id === itemId) ?? items.at(-1);
    if (!item?.payload) {
      return [];
    }
    return formats.parseDeviceList(ns, item.payload);
  }

  async function publishDeviceList(ns, devices) {
    const { node, itemId } = formats.deviceListLocation(ns);
    await pep.publish(node, itemId, formats.buildDeviceList(ns, devices), { "pubsub#access_model": "open" });
    store.setDevices(ns, ourJid, devices);
  }

  async function publishBundle(ns) {
    const { node, itemId } = formats.bundleLocation(ns, store.deviceId);
    const options = ns === "twomemo"
      ? { "pubsub#access_model": "open", "pubsub#max_items": "max" }
      : { "pubsub#access_model": "open" };
    await pep.publish(node, itemId, formats.buildBundle(ns, store.bundle(ns)), options);
  }

  /** Adds our device to a list if it's missing. @returns {object[]|null} the new list, or null if unchanged. */
  function withOurDevice(ns, devices) {
    if (devices.some((d) => d.id === store.deviceId)) {
      return null;
    }
    return [...devices, { id: store.deviceId, label: ns === "twomemo" ? DEVICE_LABEL : null }];
  }

  return {
    get store() {
      return store;
    },

    /**
     * Connect-time setup. Resolves once both namespaces are published (or
     * have failed and been logged).
     *
     * @returns {Promise<{ deviceId: number, created: boolean, published: string[], failed: string[] }>}
     */
    async start() {
      const text = await fileAccess.read();
      const lists = {};
      for (const ns of keys.NAMESPACES) {
        try {
          lists[ns] = await fetchDeviceList(ns, ourJid);
        } catch (e) {
          lists[ns] = null; // unknown: don't publish over it
          log(`ERROR: ${ns}: fetching our device list failed: ${e?.message ?? e}`);
        }
      }

      let created = false;
      if (text !== null) {
        store = OmemoStore.fromJSON(JSON.parse(text), storeOptions);
      } else {
        const inUse = Object.values(lists).flatMap((l) => (l ?? []).map((d) => d.id));
        store = createStore({ avoidDeviceIds: inUse, ...storeOptions });
        created = true;
        log(`created OMEMO keys for ${ourJid}, device id ${store.deviceId}`);
      }

      const published = [];
      const failed = [];
      for (const ns of keys.NAMESPACES) {
        if (lists[ns] === null) {
          failed.push(ns);
          continue;
        }
        try {
          const updated = withOurDevice(ns, lists[ns]);
          if (updated) {
            await publishDeviceList(ns, updated);
          } else {
            store.setDevices(ns, ourJid, lists[ns]);
          }
          if (store.rotateSignedPreKeyIfDue(ns)) {
            log(`${ns}: replaced our signed prekey (a week old)`);
          }
          await publishBundle(ns);
          published.push(ns);
        } catch (e) {
          failed.push(ns);
          log(`ERROR: ${ns}: publishing failed: ${e?.message ?? e}`);
        }
      }
      await saver.flush();
      log(`OMEMO ready for ${ourJid}: device ${store.deviceId}; published ${published.join(", ") || "nothing"}${failed.length ? `; failed ${failed.join(", ")}` : ""}`);
      return { deviceId: store.deviceId, created, published, failed };
    },

    /**
     * A PEP notification (pep.parseEvent's result).
     *
     * @returns {Promise<boolean>} whether it was an OMEMO device list (so the
     *   message should not reach the conversation).
     */
    async handleEvent(event) {
      const ns = keys.NAMESPACES.find((n) => formats.deviceListLocation(n).node === event.node);
      if (!ns || !store) {
        return false;
      }
      const from = event.from ? bareJid(event.from) : ourJid;
      const { itemId } = formats.deviceListLocation(ns);
      const item = event.items.find((i) => i.id === itemId) ?? event.items.at(-1);
      let devices;
      try {
        devices = item?.payload ? formats.parseDeviceList(ns, item.payload) : [];
      } catch (e) {
        log(`ignored a malformed ${ns} device list from ${from}: ${e?.message ?? e}`);
        return true;
      }
      if (from !== ourJid) {
        store.setDevices(ns, from, devices);
        markFresh(ns, from);
        return true;
      }
      const updated = withOurDevice(ns, devices);
      if (updated) {
        log(`${ns}: our device was dropped from our device list; publishing it again`);
        try {
          await publishDeviceList(ns, updated);
        } catch (e) {
          log(`ERROR: ${ns}: republishing our device list failed: ${e?.message ?? e}`);
        }
      } else {
        store.setDevices(ns, ourJid, devices);
      }
      return true;
    },

    /**
     * A contact's devices (docs/TASKS.md 3.9): from the store if the list
     * was fetched or pushed in this connection within
     * DEVICE_LIST_MAX_AGE_MS, otherwise (or with `refresh`) fetched again.
     *
     * @returns {Promise<{ id: number, label: string|null }[]>}
     * @throws if the list has to be fetched and can't be (never falls back
     *   to a list that may be out of date).
     */
    async getDevices(ns, who, { refresh = false } = {}) {
      const target = bareJid(who);
      if (!refresh && isFresh(ns, target)) {
        return store.devices(ns, target).map(({ id, label }) => ({ id, label }));
      }
      const devices = await fetchDeviceList(ns, target);
      store.setDevices(ns, target, devices);
      markFresh(ns, target);
      return devices;
    },

    /**
     * A contact device's bundle, with its signed prekey signature checked.
     *
     * @returns {Promise<ReturnType<typeof formats.parseBundle>|null>} null if
     *   the device hasn't published one.
     * @throws if it's malformed or the signature doesn't verify.
     */
    async getBundle(ns, who, deviceId) {
      const { node, itemId } = formats.bundleLocation(ns, deviceId);
      const items = await pep.fetchItems(bareJid(who), node, ns === "twomemo" ? itemId : undefined);
      // twomemo keeps every device's bundle on one node, so only the item
      // with this device's id will do. An oldmemo node holds one device's
      // bundle; take the newest item if "current" is missing.
      const item = ns === "twomemo"
        ? items.find((i) => i.id === itemId)
        : items.find((i) => i.id === itemId) ?? items.at(-1);
      return item?.payload ? formats.parseBundle(ns, item.payload) : null;
    },

    /**
     * Periodic upkeep while connected: a signed prekey that's due is
     * replaced and the bundle republished.
     *
     * @returns {Promise<string[]>} the namespaces whose bundle was republished.
     */
    async maintain() {
      const republished = [];
      if (!store) {
        return republished;
      }
      for (const ns of keys.NAMESPACES) {
        if (store.rotateSignedPreKeyIfDue(ns)) {
          try {
            await publishBundle(ns);
            republished.push(ns);
            log(`${ns}: replaced our signed prekey (a week old) and republished our bundle`);
          } catch (e) {
            log(`ERROR: ${ns}: republishing our bundle after a signed prekey change failed: ${e?.message ?? e}`);
          }
        }
      }
      return republished;
    },

    /**
     * Takes one of this account's other devices (an old install) off our
     * published device lists. If that app is still in use, it adds itself
     * back the next time it connects.
     *
     * @returns {Promise<string[]>} the namespaces it was removed from.
     * @throws for this Thunderbird's own device, or if a list can't be read.
     */
    async removeOwnDevice(deviceId) {
      if (deviceId === store.deviceId) {
        throw new Error("that's this Thunderbird");
      }
      const removed = [];
      for (const ns of keys.NAMESPACES) {
        const list = await fetchDeviceList(ns, ourJid);
        if (list.some((d) => d.id === deviceId)) {
          await publishDeviceList(ns, list.filter((d) => d.id !== deviceId));
          removed.push(ns);
        } else {
          store.setDevices(ns, ourJid, list);
        }
      }
      return removed;
    },

    /** Republishes our bundle (after a pre key was used up). */
    async republishBundle(ns) {
      await publishBundle(ns);
    },

    /** Writes any pending store change now (on disconnect or shutdown). */
    async stop() {
      if (store) {
        await saver.flush();
      }
    },
  };
}
