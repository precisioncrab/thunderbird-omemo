# Handoff notes

_How to pick this project up. The current state and log are in `docs/STATUS.md`. The next task is the first unchecked item in `docs/TASKS.md`._

## Setup

In PowerShell or Git Bash, from `thunderbird-omemo/`:

```
npm install
npm test
```

This needs Node 22 or newer (`npm test` passes a glob to `node --test`). Expect all tests to pass. `npm run test:coverage` adds Node's coverage report; the crypto core is fully covered apart from three unreachable length checks. Shared test helpers (vector loading, hex/base64, `replay` for injecting recorded randomness) are in `test/helpers.js`.

You only need the test-vector generator when changing what the vectors cover. It needs `uv`; see `tools/gen-vectors/README.md`. The generated files in `test/vectors/` are committed, so tests don't need Python.

## Loading in Thunderbird (task 4.0)

The add-on has never run in Thunderbird. The Experiment logs one `[omemo]` line per hook call (lengths and addresses only, never message text), so a single run shows whether the hooks work.

1. `manifest.json` is filled in (2026-09-25): author Precision Crab, homepage the GitHub repo, gecko `id` `thunderbird-omemo@precisioncrab`. The id is a permanent name tag, not a mailbox; it follows Daynizer's add-on id pattern and can still change until the add-on is first published.
2. You need Thunderbird 128 or newer, with an XMPP account under Chat and a second account or client to talk to.
3. Build the add-on file: `npm run package` in `thunderbird-omemo/` writes `dist/thunderbird-omemo-<version>.xpi` (it bundles the crypto core first; the version is `manifest.json`'s). Rebuild after any change, reinstall, and restart Thunderbird: it keeps running the old build otherwise, and since 0.0.8 the core loads under a fresh resource:// name each time and is checked against the add-on's version, so a stale cached core (which bit 0.0.7) shows up as an error instead of silently running. If the same version is rebuilt while Thunderbird holds its file open, the script adds the local time to the name (`-HHMMSS`) and says so.
4. Install it: Add-ons and Themes > gear icon > Install Add-on From File, then pick the newest `dist/thunderbird-omemo-<version>.xpi`. **Install over the old version; don't remove it first** (a removed add-on waits in an undo state, and reinstalling it then can get it removed at the next restart, as happened on 2026-09-25). The add-on is unsigned, so `xpinstall.signatures.required` must be `false` (Config Editor) for it to stay installed across restarts, as Daynizer's notes found. "Install Add-on From File" only takes an `.xpi`, never `manifest.json`. The alternative is a temporary add-on: Add-ons and Themes > gear icon > Debug Add-ons > This Thunderbird > Load Temporary Add-on, then pick `manifest.json` (it unloads when Thunderbird closes). Both paths are the ones Daynizer's add-on uses.
5. Open either console: Ctrl+Shift+J (Thunderbird's Error Console), or Add-ons and Themes > gear > Debug Add-ons > This Thunderbird > Inspect (the add-on's own console, which also gets every Experiment line as of 2026-09-25). After installing you should see `[omemo] loaded resource:///modules/xmpp-base.sys.mjs; exports: ...` `[omemo] crypto self-test passed (...)` and `[omemo] hooks installed on dispatchMessage and onMessageStanza`. The self-test line also says whether Thunderbird's module scope has Web Crypto; if not, an extra line says it switched to Thunderbird's own random generator. (The background script's own lines are in Debug Add-ons > This Thunderbird > Inspect.)
6. Send a message in an XMPP chat: expect `[omemo] dispatchMessage hook fired: to ...`.
7. Receive a message: expect `[omemo] onMessageStanza hook fired: from ...`.
8. Disconnect and reconnect the XMPP account, then repeat 6 and 7.
9. Copy every `[omemo]` line, plus any error mentioning omemo or the add-on, into `docs/STATUS.md` or a chat with the assistant.

Thunderbird's built-in OTR crashed Thunderbird during testing on 2026-09-25 (see STATUS). To turn it off: Settings > General > Config Editor, set `chat.otr.enable` to false, restart.

If step 5 shows an error instead, the most likely cause is the module path or an export name (the check runs before anything is patched, so chat keeps working). The error names what's missing.

## Layout

| Path | What it is |
|---|---|
| `src/experiment/` | Privileged Experiment API that wraps Thunderbird's XMPP send/receive functions, with `[omemo]` console diagnostics; it loads the core and hands Thunderbird's objects to `src/omemo/bridge.js` (see "Loading in Thunderbird") |
| `src/background.js` | Ordinary WebExtension background script: starts the Experiment, passes on the encryption setting, shows diagnostics |
| `src/options/` | The options page: encryption mode (stored in `browser.storage.local`) and QR codes for verifying Thunderbird on a phone; its script is bundled with qrcode-generator (MIT) into `dist/options.js` |
| `scripts/` | `build.mjs` bundles the crypto core into `dist/omemo-core.mjs`; `package.mjs` builds `dist/thunderbird-omemo-<version>.xpi` |
| `src/core.js`, `src/omemo/` | The bundle's entry, and the OMEMO layer on top of the crypto core: `store.js` (per-account key store and first-connect setup), `persist.js` (saving it), `xml.js` (parser, builder, serializer), `formats.js` (device lists, bundles, `<encrypted>`), `messages.js` (encrypting for devices and decrypting, with `OmemoError` codes) |
| `src/crypto/` | The OMEMO crypto core. `xeddsa.js`, `keys.js`, `protobuf.js`, `x3dh.js`, `double-ratchet.js`, `payload.js` and `envelope.js` (XEP-0420, with a small strict XML parser) are done, sessions included (`serializeState`/`deserializeState`). Milestone 2 is complete |
| `test/` | `node --test` suites, plus `vectors/`, the reference data they check against |
| `tools/gen-vectors/` | Python generator for `test/vectors/` (dev only, MIT-licensed dependencies only) |
| `docs/` | `PLAN.md` (architecture, milestones), `TASKS.md` (task list and per-namespace constants), `STATUS.md` (state and log), this file |

## What's real

- **Thunderbird hook points:** confirmed by reading comm-central's source (`docs/PLAN.md`, "Milestone 0 findings"). The hooks (now in `src/omemo/bridge.js`) are confirmed working in Thunderbird 156 (2026-09-25).
- **Finished crypto modules:** each is checked byte for byte against the reference implementation where one exists, using the data in `test/vectors/`.
- **The per-namespace constants table** in `docs/TASKS.md` is confirmed for twomemo fully, and for oldmemo's key schedule. oldmemo's wire framing is not confirmed until the interop tests (4.12).
- **Remaining `TODO(verify)` comments** mark spec details in `src/experiment/` that later tasks replace or confirm.

## Conventions and gotchas

- **Licensing:** the repo stays MPL-2.0 with permissive dependencies, and no copyleft code anywhere, including dev tooling. That keeps it adoptable by Thunderbird. Every oldmemo implementation is GPL/AGPL, so don't add one as a reference.
- **Randomness is injectable:** crypto functions take an optional `random(n)`. Tests replay the reference's recorded random draws in the order the reference consumed them.
- **Naming:** protobuf field names are the same across both namespaces (`n`, `pn`, `dhPub`, `ciphertext`, `preKeyId`, ...), so the ratchet code can treat both alike. Framing that differs (oldmemo's `0x33` byte, where the MAC goes) belongs in the ratchet's per-namespace profile.
- **Line endings:** Windows git converts LF to CRLF on checkout. The warnings are harmless. This repo has `core.filemode false`, because the initial commit came from a Linux sandbox with executable bits set.
- **Finishing a task, every time:** check it off in `docs/TASKS.md`, update `docs/STATUS.md` (state table, next steps, log) and any other doc that names it as next, run `npm test`, then commit and push with a message describing what changed. The project-root `NEXT.md` and `_context.md` sit outside the repo and need the same update. No AI attribution trailers.
- **No addons.thunderbird.net listing:** ATN rejects Experiment add-ons (2026-09-26), so releases are self-distributed unsigned `.xpi` files.
