# Code review: Thunderbird OMEMO 0.1.0

Reviewed 2026-09-26 at public `main` commit `5a8f749b5fd6b62e4835242a734451bc9ccc420e`. The local checkout was clean and `git ls-remote origin refs/heads/main` returned the same commit. `npm test` passed all 251 tests.

This review focused on the security-sensitive paths identified in `docs/HANDOFF.md`: encryption policy, device discovery, trust, message/session handling, persistence, PEP, and Thunderbird integration. The documented limitations around OTR coexistence, unencrypted profile key files, Thunderbird-version compatibility, and the incomplete oldmemo interop matrix are not repeated as new findings.

## Resolution (2026-09-26)

All five findings were checked against the code and confirmed, then fixed. Each fix has regression tests that fail on the 0.1.0 code and pass now (265 tests in all).

1. **Fixed.** `lookUpDevices()` now tells "no devices" (both namespaces answered, both empty) from "couldn't tell" (OMEMO not ready, or either lookup failed). Only the first sends plaintext or is remembered for ten minutes; the second blocks the message with a "try again in a moment" notice, and `/omemo status` says the lookup failed. The same fail-open existed in mode "manual": the per-chat "on" lives in the key store, so a message sent while the store was loading went out in plaintext. A message sent while OMEMO starts now waits for it, and if it fails to start the message is blocked. Tests: `test/messaging.test.js` ("a failed device lookup blocks the message...", "a message sent while OMEMO starts...", "if OMEMO fails to start...").
2. **Fixed.** `getDevices()` uses a contact's stored list only if it was fetched or pushed during this connection and is under an hour old (`DEVICE_LIST_MAX_AGE_MS`); otherwise it fetches it again before encrypting, and a failed fetch blocks the message instead of using the saved list. Tests: `test/account.test.js` (offline removal, push, expiry) and `test/messaging.test.js` ("a device the contact removed while we were offline gets no key...").
3. **Fixed.** The bridge tracks the saves that disconnects start; `uninstall()` waits for them, and a new `saveAll()` writes every pending change and waits for those saves. The Experiment registers `saveAll()` as a shutdown blocker (`IOUtils.profileBeforeChange`, falling back to AsyncShutdown's), so Thunderbird doesn't quit before the key stores are on disk. Tests: `test/bridge.test.js` with a deliberately slow write. The blocker itself runs only in Thunderbird and needs a check there.
4. **Fixed.** `storeFileName()` percent-encodes (as UTF-8, uppercase hex) every character outside `a-z 0-9 @ . _ -`, so names can't collide, even case-insensitively. Names of ordinary JIDs are unchanged. A store under its 0.1.0 name moves to the new name on first read if it belongs to this account (its own device list there has the store's device id) and no JID whose name didn't change claims it; otherwise it stays for the other account. Tests: `test/persist.test.js`.
5. **Fixed.** For twomemo, `getBundle()` takes only the item whose id is the requested device id; the newest-item fallback stays for oldmemo's per-device node. Test: `test/account.test.js`.

## Findings

### 1. High: "available" mode sends plaintext when device discovery fails

Locations: `src/omemo/bridge.js:291-312`, `src/omemo/bridge.js:648-655`

`lookUpDevices()` converts every exception into `found = false`, including a PEP timeout, a disconnected account, a failed OMEMO startup, or one namespace failing while the other lookup is still in progress. It then negative-caches that result for ten minutes. In `dispatchMessage()`, `false` means calling Thunderbird's original plaintext send path.

This makes the "Always use OMEMO when available" setting fail open. A contact can have OMEMO devices, but a temporary lookup failure causes the current message, and subsequent messages during the negative-cache window, to be sent unencrypted. The UI describes this mode as encrypting contacts who use OMEMO, so an indeterminate lookup must not be treated as proof that the contact has no devices.

Recommended change:

- Return three states from discovery: devices found, confirmed empty, and lookup failed.
- Send plaintext only after successful empty responses from both namespace lookups.
- On an error or while the account is not ready, block the send and show a clear retryable notice.
- Negative-cache only confirmed-empty results, never failures.
- Add regression tests for a timeout, one namespace rejecting, and sending before `omemo.start()` completes.

### 2. High: cached peer device lists can keep removed devices as recipients

Locations: `src/omemo/account.js:101-109`, `src/omemo/account.js:197-205`, `src/omemo/bridge.js:396-404`

Peer device lists are persisted. On reconnect, `start()` refreshes only this account's own lists. `getDevices()` returns any non-empty stored peer list indefinitely unless its caller explicitly requests `refresh: true`, but production callers never do so. Outgoing encryption therefore depends entirely on receiving every PEP device-list notification.

If a contact removes a lost or compromised device while Thunderbird is offline, and the current PEP item is not pushed after reconnect or a notification is otherwise missed, Thunderbird continues including that removed device's key in outgoing messages. The 90-day silence rule limits some stale devices eventually, but it does not make device removal timely and does not help a recently active removed device.

Recommended change:

- Give cached peer lists an expiry and refresh them before sending after reconnect or once the expiry elapses.
- At minimum, mark all peer lists stale on account reconnect and fetch current lists before the first send to each peer.
- Preserve fail-closed behavior when that refresh fails.
- Test an offline removal: persist a list, change the server's current list while disconnected, reconnect, then verify the removed device receives no encrypted key.

### 3. Medium: shutdown does not wait for ratchet state to reach disk

Locations: `src/omemo/persist.js:39-87`, `src/omemo/bridge.js:227-237`, `src/omemo/bridge.js:672-676`, `src/experiment/implementation.js:243-254`

Store writes are intentionally delayed by 500 ms. `stopAccount()` returns the flush promise, but the `_disconnect` wrapper discards it. The Experiment's `onShutdown()` also starts `bridge.uninstall()` without awaiting it or registering a shutdown blocker; the comment explicitly says saving finishes in the background.

Closing Thunderbird or disabling the add-on immediately after a send or decrypt can therefore terminate the add-on before the latest Double Ratchet state is durable. Rolling back outbound ratchet state can reuse a message number/key after restart and commonly makes the next message undecryptable as a replay. Rolling back inbound state can also resurrect already-consumed state.

Recommended change:

- Register a Thunderbird shutdown blocker for the pending store flushes, or use the host's supported asynchronous shutdown mechanism.
- Track every in-flight save and make shutdown wait for it before releasing the Experiment resources.
- Where Thunderbird's disconnect hook cannot be asynchronous, start the flush there but retain it in a collection that shutdown must await.
- Add a durability test with a deliberately delayed `fileAccess.write()` and a shutdown immediately after a session change.

### 4. Medium: different valid account JIDs can share one key-store file

Location: `src/omemo/persist.js:98-104`

`storeFileName()` replaces every character outside `[a-z0-9@._-]` with `_`. That mapping is not one-to-one. For example, the distinct valid bare JIDs `alice+work@example.org` and `alice_work@example.org` both map to `alice_work@example.org.json`.

When both accounts exist in one Thunderbird profile, they can load and overwrite the same identity keys, sessions, trust decisions, and device id. Besides corrupting both accounts, this can publish one account's stored device identity under the other account.

Recommended change:

- Use a reversible filename encoding such as UTF-8 followed by base64url or percent-encoding, or append a cryptographic hash of the exact normalized bare JID.
- Include a migration path for existing filenames.
- Add collision tests covering `+`, `_`, escaped localparts, and non-ASCII JIDs.

### 5. Low: a missing twomemo bundle item can be replaced with another device's bundle

Location: `src/omemo/account.js:215-219`

All twomemo device bundles share one PEP node and use the device id as the item id. After asking for a specific item, `getBundle()` uses the last returned item when the requested id is absent. That fallback is appropriate for oldmemo's per-device node only; for twomemo it can associate device A's bundle and fingerprint with device B's id if a server ignores the item filter or returns an unexpected result set.

The immediate result is failed delivery and incorrect trust/fingerprint state for the target device. It also hides a malformed or non-conforming server response instead of treating the requested bundle as unavailable.

Recommended change:

- For twomemo, accept only an item whose id exactly equals the requested device id; otherwise return `null` or raise a protocol error.
- Keep the last-item compatibility fallback only where the protocol location is a per-device oldmemo node.
- Add a test where the requested twomemo item is missing but another device's item is returned.

## Overall assessment

The crypto core is unusually well tested, and the known-answer, tamper, replay, serialization, and integration tests provide a strong baseline. The most important fixes are outside the primitives: make device discovery fail closed, and ensure peer device-list removals cannot remain stale. Those two findings directly affect whether message recipients and plaintext/encrypted behavior match the user's security setting.
