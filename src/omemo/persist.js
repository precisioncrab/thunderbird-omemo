/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Saving the key store (docs/TASKS.md 3.2). One JSON file per account under
 * <profile>/omemo/. Changes are batched: the store's onChange schedules a
 * write a moment later, so a burst of changes (a message to five devices)
 * costs one write, and writes never overlap. Each write goes to a temporary
 * file first and replaces the old one only when complete.
 *
 * The file access is passed in, so this runs under Node in tests;
 * geckoFileAccess() is the Thunderbird version, built on IOUtils and
 * PathUtils (available in Thunderbird's privileged module scope).
 */

/**
 * @typedef {object} FileAccess
 * @property {() => Promise<string|null>} read - the saved text, or null if
 *   there's no file yet.
 * @property {(text: string) => Promise<void>} write - replaces the file
 *   atomically.
 */

/**
 * Batches saves of `getText()` through `access.write`.
 *
 * @param {FileAccess} access
 * @param {() => string} getText - called at write time, so the latest
 *   state is what gets written.
 * @param {object} [options]
 * @param {number} [options.delayMs] - how long to wait for more changes.
 * @param {(e: Error) => void} [options.onError] - a failed write; the next
 *   change retries.
 * @param {typeof setTimeout} [options.setTimer]
 * @param {typeof clearTimeout} [options.clearTimer]
 * @returns {{ schedule: () => void, flush: () => Promise<void> }}
 */
export function createSaver(access, getText, { delayMs = 500, onError = () => {}, setTimer = setTimeout, clearTimer = clearTimeout } = {}) {
  let timer = null;
  let dirty = false;
  let writing = null; // the in-flight write, if any

  async function writeNow() {
    timer = null;
    // Wait out any write in flight, including one another caller starts
    // while we wait, so we return only once our change is on disk.
    while (writing) {
      await writing;
    }
    if (!dirty) {
      return;
    }
    dirty = false;
    const current = (async () => {
      try {
        await access.write(getText());
      } catch (e) {
        dirty = true; // keep it for the next attempt
        onError(e);
      }
    })();
    writing = current;
    await current;
    if (writing === current) {
      writing = null;
    }
  }

  return {
    /** Marks the store changed and writes it after delayMs. */
    schedule() {
      dirty = true;
      if (timer === null) {
        timer = setTimer(() => {
          writeNow();
        }, delayMs);
      }
    },
    /** Writes any pending change now (e.g. on shutdown or disconnect). */
    async flush() {
      if (timer !== null) {
        clearTimer(timer);
        timer = null;
      }
      await writeNow();
    },
  };
}

/**
 * The file name for an account's store: its bare JID, lowercased, with
 * anything unusual for a file name replaced.
 *
 * @param {string} jid
 * @returns {string}
 */
export function storeFileName(jid) {
  const slash = jid.indexOf("/");
  const bare = (slash < 0 ? jid : jid.slice(0, slash)).toLowerCase();
  if (!bare) {
    throw new Error("A store needs the account's JID.");
  }
  return `${bare.replace(/[^a-z0-9@._-]/g, "_")}.json`;
}

/**
 * Thunderbird file access for one account's store, in <profile>/omemo/.
 * The file holds private keys, so on systems with Unix permissions it is
 * made readable by the user only.
 *
 * @param {string} jid - the account's JID.
 * @param {object} [globals] - IOUtils and PathUtils; defaults to the
 *   module scope's (tests pass fakes).
 * @returns {FileAccess & { path: string }}
 */
export function geckoFileAccess(jid, { IOUtils = globalThis.IOUtils, PathUtils = globalThis.PathUtils } = {}) {
  const dir = PathUtils.join(PathUtils.profileDir, "omemo");
  const path = PathUtils.join(dir, storeFileName(jid));
  return {
    path,
    async read() {
      if (!(await IOUtils.exists(path))) {
        return null;
      }
      return IOUtils.readUTF8(path);
    },
    async write(text) {
      await IOUtils.makeDirectory(dir, { ignoreExisting: true });
      await IOUtils.writeUTF8(path, text, { tmpPath: `${path}.tmp` });
      try {
        await IOUtils.setPermissions(path, 0o600);
      } catch {
        // Windows has no Unix permissions; the profile folder is per-user.
      }
    },
  };
}
