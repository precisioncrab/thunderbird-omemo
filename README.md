# Thunderbird OMEMO

OMEMO end-to-end encryption for XMPP accounts in Thunderbird Chat.

[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-ea4aaa?logo=githubsponsors)](https://github.com/sponsors/precisioncrab)

Free and open source. If it's useful to you, please consider
[sponsoring its development](https://github.com/sponsors/precisioncrab).

## What this is

Thunderbird's built-in chat client supports XMPP natively, but has never shipped OMEMO
(see [Mozilla bug 1237416](https://bugzilla.mozilla.org/show_bug.cgi?id=1237416), open
since 2015). This project adds it as a WebExtension with an Experiment API, without
forking Thunderbird: it hooks the existing JavaScript XMPP implementation that ships
inside Thunderbird itself (`chat/protocols/xmpp/` in comm-central) to encrypt and
decrypt 1:1 conversations using the Double Ratchet / X3DH construction defined by
[XEP-0384: OMEMO Encryption](https://xmpp.org/extensions/xep-0384.html).

Full architecture writeup, the confirmed integration points in Thunderbird's source,
milestones, and the project's licensing/distribution plan live in
[`docs/PLAN.md`](docs/PLAN.md).

## Status

Early release (0.1.0). In Thunderbird (tested on Thunderbird 156 on Windows, with a Snikket
server), it encrypts and decrypts one-to-one XMPP chats with OMEMO, in both the older
namespace Conversations-family apps use and the newer one, and interoperates with
Cheogram chats in both directions. What's in place:

- Opt-in encryption: an options page ("only chats I switch on", "always use OMEMO when
  available", "always use OMEMO"), Thunderbird's own lock button to switch a chat on,
  and an `/omemo` chat command (`on`, `off`, `default`, status, `help`, `qr`, `verify`,
  `trust`, `distrust`), explained on the options page's Instructions tab.
- Trust like Conversations: devices are trusted automatically until you verify one of a
  contact's devices; after that, new devices wait for your approval, and changed keys
  are always flagged. The "Encryption Status" button, at the right of the bar at the top of
  the chat, reads "Private" when
  all of a contact's devices are verified, and "Unverified" until then.
- Fingerprints in the same form Conversations shows, and a QR code on the options page
  that phones scan to verify Thunderbird.
- Padlocks on encrypted messages, notices instead of unreadable text when something
  can't be decrypted, and never a silent fallback to plaintext in an encrypted chat.
- Key upkeep: the signed prekey (used only to start new sessions) is replaced weekly, as
  the Signal X3DH spec suggests, while the identity key and fingerprints never change;
  devices silent for 90 days are left out when encrypting; and `/omemo remove` takes
  your own old installs off your device list.

Not done yet: group chats. The crypto core matches reference implementations byte for
byte where references exist.

See `docs/STATUS.md` for the current state, `docs/TASKS.md` for the task list, and
`docs/PLAN.md` for the architecture and its "Milestone 0 findings" (the exact
Thunderbird functions this project hooks into).

## Install

The add-on isn't on addons.thunderbird.net (see [Distribution](#distribution)), so it's
installed from a file, and Thunderbird has to be told to accept an unsigned add-on:

1. In Thunderbird, open Settings > General, scroll to the bottom and click
   **Config Editor**. Search for `xpinstall.signatures.required` and set it to `false`.
2. While you're there, search for `chat.otr.enable` and set it to `false`. Thunderbird's
   built-in OTR encryption can start on its own in XMPP chats, and the two don't yet
   coordinate; OTR has also crashed Thunderbird in testing. Restart Thunderbird after
   changing it.
3. Download `thunderbird-omemo-<version>.xpi` from the
   [Releases](https://github.com/precisioncrab/thunderbird-omemo/releases) page.
4. Open Add-ons and Themes, click the gear icon, choose **Install Add-on From File**, and
   pick the `.xpi`. Restart Thunderbird.
5. Open the add-on's options (Add-ons and Themes > OMEMO for Thunderbird Chat > Options)
   to choose when chats are encrypted. The **Instructions** tab explains the `/omemo`
   chat commands; `/omemo help` in any chat opens it too.

To update, install the new `.xpi` over the old one; don't remove the old version first.
Your keys, verifications and settings stay in your Thunderbird profile either way.

## Scope (v1)

One-to-one XMPP chats only. Targets both the legacy `eu.siacs.conversations.axolotl`
namespace ("oldmemo", still the widest-deployed baseline) and the current
`urn:xmpp:omemo:2` namespace ("twomemo"). Group chat (MUC) OMEMO is out of scope for v1.

## What this add-on can access

Thunderbird shows this add-on as having "full, unrestricted access to Thunderbird and
your computer". It shows that for every add-on that uses an Experiment API, which is the
only way to reach Thunderbird's chat code. In practice, Experiment code can do what your
own user account can do (not what needs administrator rights). What this add-on actually
uses:

- Thunderbird's XMPP chat code, to encrypt outgoing and decrypt incoming messages.
- Its own key files, `<Thunderbird profile>/omemo/<account JID>.json`. No other files.
- Your XMPP accounts' existing connections, to publish and fetch OMEMO keys on your own
  servers.
- The encryption setting, in the add-on's own WebExtension storage.

It makes no other network connections: no telemetry, no update checks, no license
server.

## Where keys are kept

Each account's OMEMO keys and sessions are stored in one file,
`<Thunderbird profile>/omemo/<account JID>.json`. The private keys in it are **not
encrypted**, the same as in other desktop OMEMO clients (Gajim, Dino): anyone who can
read your Thunderbird profile can read them. On Linux and macOS the file is readable by
your user only. Protect the profile the way you protect the rest of your mail.

## Distribution

Source is public here under MPL-2.0 so anyone can build and run it themselves, and so
Mozilla can pick this up directly if/when native OMEMO work starts on Thunderbird
itself.

**Why it isn't on addons.thunderbird.net.** Normal Thunderbird add-ons can only use
Thunderbird's official add-on APIs, and those have nothing for chat. The one way to
change what Thunderbird's chat sends and receives is an *Experiment*: add-on code that
runs inside Thunderbird itself and reaches its internal code directly. Thunderbird's
official add-on site no longer reviews or accepts add-ons that use Experiments, so this
one can't be listed there or signed by Mozilla.

Releases are therefore unsigned `.xpi` files on the
[Releases](https://github.com/precisioncrab/thunderbird-omemo/releases) page, installed
from file as described under [Install](#install). This add-on is a bridge until
Thunderbird ships native OMEMO support. See `docs/PLAN.md` for the reasoning.

## Supporting this project

This add-on is free, and the hope is that Thunderbird adopts OMEMO natively (the code is
MPL-2.0, Thunderbird's own license, for exactly that reason). If it's useful to you,
please consider [sponsoring its development](https://github.com/sponsors/precisioncrab).

## License

MPL-2.0. See `LICENSE`. Dependencies are MIT-licensed (`@noble/curves`,
`@noble/hashes`, `@noble/ciphers`). The repository deliberately contains no copyleft
code, including dev tooling, so that Thunderbird could adopt it; see
`tools/gen-vectors/README.md`.

## Development

Requires Node 22 or newer.

```
npm install
npm test
```

Crypto modules are checked against known-answer vectors in `test/vectors/`, which
`tools/gen-vectors/` generates from MIT-licensed reference implementations.
`npm run package` builds the `.xpi` into `dist/`. `docs/HANDOFF.md` covers the layout
and conventions. Bug reports are welcome as GitHub issues.
