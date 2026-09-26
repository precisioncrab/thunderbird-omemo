/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests for src/omemo/persist.js: batched, non-overlapping saves, and the
 * Thunderbird file access against a fake IOUtils/PathUtils.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { createSaver, storeFileName, geckoFileAccess } from "../src/omemo/persist.js";
import { createStore, OmemoStore } from "../src/omemo/store.js";

/** Timers the test fires by hand. */
function manualTimers() {
  const pending = new Map();
  let next = 1;
  return {
    setTimer: (fn) => {
      pending.set(next, fn);
      return next++;
    },
    clearTimer: (id) => pending.delete(id),
    fire() {
      const fns = [...pending.values()];
      pending.clear();
      for (const fn of fns) {
        fn();
      }
    },
    get count() {
      return pending.size;
    },
  };
}

/** A promise with its resolve function. */
function deferred() {
  let resolve;
  const promise = new Promise((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

const settle = () => new Promise((r) => setImmediate(r));

test("a burst of changes becomes one write of the latest state", async () => {
  const timers = manualTimers();
  const writes = [];
  let state = 0;
  const saver = createSaver({ write: async (t) => writes.push(t) }, () => `state ${state}`, timers);
  for (state = 1; state <= 5; state++) {
    saver.schedule();
  }
  state = 5;
  assert.equal(timers.count, 1, "one timer for the burst");
  assert.deepEqual(writes, []);
  timers.fire();
  await settle();
  assert.deepEqual(writes, ["state 5"]);
  timers.fire();
  await settle();
  assert.equal(writes.length, 1, "nothing more to write");
});

test("flush writes at once and cancels the timer; with nothing pending it does nothing", async () => {
  const timers = manualTimers();
  const writes = [];
  const saver = createSaver({ write: async (t) => writes.push(t) }, () => "x", timers);
  await saver.flush();
  assert.deepEqual(writes, []);
  saver.schedule();
  await saver.flush();
  assert.deepEqual(writes, ["x"]);
  assert.equal(timers.count, 0);
});

test("writes never overlap, and a change during a write is written after it", async () => {
  const timers = manualTimers();
  const gates = [];
  let active = 0;
  let maxActive = 0;
  const writes = [];
  let state = "a";
  const saver = createSaver({
    write: async (t) => {
      active++;
      maxActive = Math.max(maxActive, active);
      const gate = deferred();
      gates.push(gate);
      await gate.promise;
      writes.push(t);
      active--;
    },
  }, () => state, timers);

  saver.schedule();
  timers.fire(); // first write starts, blocked on its gate
  await settle();
  state = "b";
  saver.schedule();
  const flushed = saver.flush(); // must wait for the first write, then write "b"
  let flushDone = false;
  flushed.then(() => {
    flushDone = true;
  });
  await settle();
  assert.equal(flushDone, false);
  gates[0].resolve();
  await settle();
  assert.equal(gates.length, 2, "the second write started after the first finished");
  assert.equal(flushDone, false, "flush waits for the write it asked for");
  gates[1].resolve();
  await flushed;
  assert.deepEqual(writes, ["a", "b"]);
  assert.equal(maxActive, 1);
});

test("a failed write is reported and retried on the next flush", async () => {
  const timers = manualTimers();
  const errors = [];
  let fail = true;
  const writes = [];
  const saver = createSaver({
    write: async (t) => {
      if (fail) {
        throw new Error("disk full");
      }
      writes.push(t);
    },
  }, () => "data", { ...timers, onError: (e) => errors.push(e.message) });
  saver.schedule();
  await saver.flush();
  assert.deepEqual(errors, ["disk full"]);
  assert.deepEqual(writes, []);
  fail = false;
  await saver.flush();
  assert.deepEqual(writes, ["data"]);
});

test("store file names: the bare JID, lowercased, with odd characters replaced", () => {
  assert.equal(storeFileName("Alice@Example.org/Thunderbird"), "alice@example.org.json");
  assert.equal(storeFileName("we ird\\na:me@host"), "we_ird_na_me@host.json");
  assert.throws(() => storeFileName("/resource"), /needs the account's JID/);
});

/** An in-memory IOUtils/PathUtils, recording calls. */
function fakeGecko({ failPermissions = false } = {}) {
  const files = new Map();
  const dirs = new Set();
  const calls = [];
  return {
    files,
    dirs,
    calls,
    PathUtils: { profileDir: "/profile", join: (...parts) => parts.join("/") },
    IOUtils: {
      exists: async (p) => files.has(p) || dirs.has(p),
      readUTF8: async (p) => files.get(p),
      makeDirectory: async (p, opts) => {
        calls.push(["makeDirectory", p, opts]);
        dirs.add(p);
      },
      writeUTF8: async (p, text, opts) => {
        calls.push(["writeUTF8", p, opts]);
        files.set(p, text);
      },
      setPermissions: async (p, mode) => {
        calls.push(["setPermissions", p, mode]);
        if (failPermissions) {
          throw new Error("not supported");
        }
      },
    },
  };
}

test("Thunderbird file access: <profile>/omemo/<jid>.json, atomic writes, owner-only permissions", async () => {
  const gecko = fakeGecko();
  const access = geckoFileAccess("bob@example.org/x", gecko);
  assert.equal(access.path, "/profile/omemo/bob@example.org.json");
  assert.equal(await access.read(), null, "no file yet");
  await access.write("{}");
  assert.equal(await access.read(), "{}");
  assert.deepEqual(gecko.calls, [
    ["makeDirectory", "/profile/omemo", { ignoreExisting: true }],
    ["writeUTF8", "/profile/omemo/bob@example.org.json", { tmpPath: "/profile/omemo/bob@example.org.json.tmp" }],
    ["setPermissions", "/profile/omemo/bob@example.org.json", 0o600],
  ]);
  const windows = fakeGecko({ failPermissions: true });
  await geckoFileAccess("bob@example.org", windows).write("{}");
  assert.equal(windows.files.size, 1, "a permissions failure (Windows) doesn't fail the write");
});

test("end to end: a store saves through the saver and loads back", async () => {
  const gecko = fakeGecko();
  const access = geckoFileAccess("carol@example.org", gecko);
  const timers = manualTimers();
  let store = null;
  const saver = createSaver(access, () => JSON.stringify(store.toJSON()), timers);
  store = createStore({ onChange: () => saver.schedule() });
  store.removePreKey("twomemo", 1);
  await saver.flush();
  const loaded = OmemoStore.fromJSON(JSON.parse(await access.read()));
  assert.equal(loaded.deviceId, store.deviceId);
  assert.equal(loaded.preKey("twomemo", 1), null);
});
