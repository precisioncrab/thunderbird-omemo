# Handoff notes

_How to pick this project up or review it. The current state and log are in `docs/STATUS.md` (newest on top); the architecture and milestones are in `docs/PLAN.md`; the task list and per-namespace protocol constants are in `docs/TASKS.md`. Last updated 2026-09-26, after the fixes from the first code review (`docs/CODE_REVIEW.md`)._

## Setup

In PowerShell or Git Bash, from `thunderbird-omemo/`:

```
npm install
npm test
```

This needs Node 22 or newer (`npm test` passes a glob to `node --test`). All 265 tests should pass. `npm run test:coverage` adds Node's coverage report; the crypto core is fully covered apart from three unreachable length checks. Shared test helpers (vector loading, hex/base64, `replay` for injecting recorded randomness) are in `test/helpers.js`.

You only need the test-vector generator when changing what the vectors cover. It needs `uv`; see `tools/gen-vectors/README.md`. The generated files in `test/vectors/` are committed, so tests don't need Python.

## Layout

| Path | What it is |
|---|---|
| `manifest.json` | WebExtension manifest: the `omemoXmpp` Experiment API, background script, options page. Gecko id `thunderbird-omemo@precisioncrab` (permanent) |
| `src/experiment/` | The privileged Experiment (`implementation.js`, `schema.json`). It loads the bundled core under a fresh `resource://` name, checks its version, runs the crypto self-test, hands Thunderbird's XMPP prototypes and services to `installBridge`, registers the `/omemo` chat command, and forwards events (diagnostics, `onShowPage`) to the background script |
| `src/background.js` | Ordinary WebExtension background script: passes the options page's setting to the Experiment, opens the options page as a tab for `/omemo help` and `/omemo qr`, shows diagnostics |
| `src/options/` | The options page, in three tabs: Settings (encryption mode, in `browser.storage.local`), Verify on phone (QR codes), Instructions (every `/omemo` command, devices, trust, what the add-on can access). Its script is bundled with qrcode-generator (MIT) into `dist/options.js` |
| `src/core.js` | Entry of the core bundle (`dist/omemo-core.mjs`): exports the crypto core, the OMEMO layer and `installBridge` |
| `src/omemo/bridge.js` | Everything that touches Thunderbird: the hooks on `XMPPConversationPrototype` and `XMPPAccountPrototype`, the per-account lifecycle, encrypt on send, decrypt on receive (carbons included), the padlock and lock button, the `/omemo` command, trust decisions per recipient, stale-device filtering, the 6-hourly upkeep timer. Written against injected Thunderbird objects so it runs in Node against `test/fake-thunderbird.js` |
| `src/omemo/account.js` | One account's OMEMO over PEP: load or create the key store, publish device lists and bundles, handle device list pushes, fetch contacts' devices and bundles, rotate the signed prekey (`maintain()`), remove our own old devices |
| `src/omemo/store.js` | The per-account key store: device id, identity key, per-namespace signed prekey (plus replaced ones kept 30 days) and 100 pre keys, sessions, device lists (`firstSeen`, labels), encryption choices, trust per identity key, each device's last key and last message time. Strict JSON load; newer fields are optional so older stores load |
| `src/omemo/persist.js` | Batched, non-overlapping, atomic saves to `<profile>/omemo/<jid>.json` (unusual characters percent-encoded; 0.1.0's names are migrated) |
| `src/omemo/messages.js` | Encrypt one body for many devices; decrypt with session start/reuse; `OmemoError` codes |
| `src/omemo/trust.js` | "Blind trust before verification" (Conversations' model): decides per device key whether to encrypt to it, and what to tell the user |
| `src/omemo/fingerprint.js` | Fingerprints in Conversations' hex groups, and the `xmpp:` URI for QR verification |
| `src/omemo/formats.js`, `xml.js`, `xmlnode.js` | OMEMO XML (device lists, bundles, `<encrypted>`) for both namespaces; a strict XML parser/builder/serializer; conversion to and from Thunderbird's `XMLNode` (escaping attribute values, which Thunderbird doesn't) and a `sendIq` with a timeout |
| `src/omemo/pep.js`, `caps.js` | PEP publish/fetch/notifications; the XEP-0115 caps hash so servers push OMEMO device lists to us |
| `src/crypto/` | The crypto core on `@noble` (MIT): `xeddsa.js`, `keys.js`, `protobuf.js`, `x3dh.js`, `double-ratchet.js` (per-namespace profiles, transactional decrypt, `serializeState`), `payload.js`, `envelope.js` (XEP-0420), `random.js` (all randomness, injectable), `self-test.js` |
| `scripts/` | `build.mjs` bundles the core and the options script; `package.mjs` builds `dist/thunderbird-omemo-<version>.xpi` (reproducible zip) |
| `test/` | `node --test` suites; `fake-thunderbird.js` and `fake-pep.js` stand in for Thunderbird's XMPP code and a pubsub server; `vectors/` is the reference data |
| `tools/gen-vectors/` | Python generator for `test/vectors/` (dev only, MIT-licensed dependencies only) |
| `docs/` | `PLAN.md`, `TASKS.md`, `STATUS.md`, this file |

## Reviewing the code

A suggested reading order, from the protocol outward:

1. `src/crypto/` with its tests: XEdDSA, X3DH, the Double Ratchet and payload encryption, checked byte for byte against python-omemo's twomemo vectors (`test/vectors/`). oldmemo has no permissive reference, so its key schedule is checked against the generic MIT libraries and its wire framing against real Cheogram clients only.
2. `src/omemo/store.js`, `messages.js`, `trust.js`: key storage, the message layer, and trust decisions.
3. `src/omemo/account.js`, `pep.js`, `formats.js`: what gets published and fetched.
4. `src/omemo/bridge.js` and `src/experiment/implementation.js`: the Thunderbird integration, where a bug could leak plaintext or mislabel a message as encrypted.

Properties worth checking:

- **No plaintext fallback:** in a conversation that should be encrypted, a message that can't be encrypted is not sent at all (`sendEncrypted` throws; `dispatchMessage` shows an error). When it can't be told whether a chat is encrypted (OMEMO still starting, a failed device lookup), the message waits or is blocked, never sent in plaintext.
- **Current device lists:** a contact's saved device list is fetched again before use in each connection, and hourly, so a device removed while we were offline gets nothing.
- **Durable saves:** ratchet changes are saved half a second later in a batch; a disconnect writes at once, and uninstall and Thunderbird's shutdown (a shutdown blocker) wait for every write to finish.
- **The padlock is only on what was decrypted:** `writeMessage` is flagged `isEncrypted` only while Thunderbird handles a message we decrypted from a trusted device (the `markEncrypted` counter in `bridge.js`).
- **Decryption is transactional:** ratchet state commits only after the MAC verifies; forged or replayed messages can't change session state.
- **Trust:** after a contact has one verified device, a new or changed key is held back until the user decides; distrusted keys are never used.
- **Sender binding:** the XEP-0420 envelope's `<from>` must match the stanza's sender.

Known limits (also in `docs/STATUS.md`, "Open risks"): keys are stored unencrypted in the profile, as in other desktop clients; OTR/OMEMO coexistence isn't handled (users are told to turn OTR off); oldmemo interop is confirmed with Cheogram only; the Experiment depends on Thunderbird internals (tested on Thunderbird 156); the `padlock:` log lines in `bridge.js` are temporary diagnostics.

## Running it in Thunderbird

1. `npm run package` writes `dist/thunderbird-omemo-<version>.xpi` (the version is `manifest.json`'s). If the same version is rebuilt while Thunderbird holds the file open, the script adds the local time to the name.
2. Thunderbird needs `xpinstall.signatures.required` set to `false` (Settings > General > Config Editor), since the add-on is unsigned, and `chat.otr.enable` set to `false` (Thunderbird's OTR crashed it in testing).
3. Add-ons and Themes > gear icon > Install Add-on From File, pick the `.xpi`, restart. **Install over the old version; don't remove it first** (a removed add-on waits in an undo state, and reinstalling then can get it removed at the next restart). A temporary add-on also works: Debug Add-ons > This Thunderbird > Load Temporary Add-on, pick `manifest.json`.
4. Every build loads the core under a fresh `resource://` name and checks it against the add-on's version, so a stale cached core shows up as an error instead of silently running.
5. Diagnostics: Add-ons and Themes > gear > Debug Add-ons > This Thunderbird > Inspect shows every `[omemo]` line (never message text). Expect `crypto self-test passed`, `hooks installed`, and `OMEMO ready for <jid>` per account.

## Conventions and gotchas

- **The repo is public.** Keep personal details out of commits and docs (names, personal XMPP addresses, local paths); tests and docs use `test1`/`test2@test.snikket.chat`. Commits use "Precision Crab" and the GitHub no-reply address.
- **Licensing:** MPL-2.0 with permissive dependencies, and no copyleft code anywhere, dev tooling included, so Thunderbird could adopt it. Every oldmemo implementation is GPL/AGPL, so don't add one as a reference.
- **Randomness and clocks are injectable:** crypto functions take `random(n)`; the store, account and bridge take `now()`. Tests replay the reference's recorded random draws.
- **Naming:** protobuf field names are the same across both namespaces (`n`, `pn`, `dhPub`, `ciphertext`, `preKeyId`, ...). Framing that differs (oldmemo's `0x33` byte, where the MAC goes) belongs in the ratchet's per-namespace profile.
- **Chat text:** Thunderbird turns text smileys like `):` into emoji in every message, including the add-on's notices, so avoid them in `say()` strings.
- **Line endings:** Windows git converts LF to CRLF on checkout; the warnings are harmless. `core.filemode false` is set.
- **Finishing a change:** run `npm test`, update `docs/STATUS.md` (state table, next steps, a log entry) and any doc that names the change as next, then commit and push. No AI attribution trailers.
- **Releases:** bump `manifest.json` and `package.json`, `npm run package`, then a GitHub release with the `.xpi` attached. There's no addons.thunderbird.net listing: it doesn't accept Experiment add-ons.
