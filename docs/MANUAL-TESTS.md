# Manual tests

_Checks that only a person in Thunderbird can run. Tick each box as you go and note anything odd under the section. Results go into `docs/STATUS.md` (log entry, newest on top). Created 2026-09-26 for the 0.1.1 release and the interop work (task 4.12)._

## Before you start

- [ ] The build under test is installed over the old one (never remove first), then Thunderbird restarted.
- [ ] `chat.otr.enable` is false (except in section 6).
- [ ] The Error Console is open (Ctrl+Shift+J) and filtered on `[omemo]`.
- Accounts: test1 and test2 in Thunderbird; the phones as noted per section.

**Two different locks.** The small padlock beside a sender's name means that message was encrypted. It never shows verification, and a follow-on message from the same sender has none (Thunderbird only draws it on the sender line). The chat's state is at the **right end of the bar at the top of the chat** (the strip with the contact's picture, name and status message): the text "Encryption Status:" and a small dropdown button with one of these labels. Thunderbird hides both when the chat has no encryption state:

| Button label | Meaning |
|---|---|
| (hidden) | No OMEMO for this contact, or OMEMO not set up for this chat |
| Insecure | The contact has OMEMO, but this chat isn't encrypted |
| Unverified | Encrypted, but not every one of the contact's devices is verified |
| Private | Encrypted, and every one of the contact's devices is verified |

## 1. The encryption button

- [x] Message padlocks: shown on the sender line only; follow-on messages have none (confirmed 2026-09-26 from a screenshot).
- [ ] In a test1/test2 chat, "Encryption Status:" and its button appear at the right end of the contact bar. If not, check what the add-on reports: set `devtools.chrome.enabled` to true in the Config Editor, open the Error Console (Ctrl+Shift+J), and run the line below (0 hidden, 1 Insecure, 2 Unverified, 3 Private). A 3 with no button means Thunderbird isn't redrawing it; a 0 means the add-on reports the wrong state.

  ```js
  ChromeUtils.importESModule("resource:///modules/IMServices.sys.mjs").IMServices.conversations.getUIConversations().map(c => `${c.name}: ${c.encryptionState}`).join("\n")
  ```
- [ ] In a chat where every contact device is verified (`/omemo` lists all as verified), the button reads **Private**.
- [ ] Hovering over it says the conversation is encrypted and private.
- [ ] `/omemo distrust <device>` on one contact device: the button changes to **Unverified** without reopening the chat. Then `/omemo verify <device>` again: back to **Private**.
- [ ] After restarting Thunderbird, the button still reads **Private** once the account has connected.
- [ ] Setting "only chats I switch on", with a contact who has OMEMO and a chat that's off (`/omemo default`): the button reads **Insecure**. Switching the chat on from the button's menu makes it **Unverified** or **Private**.
- [ ] A chat with an SMS contact (a cheogram.com address): the button is hidden.

Notes:

## 2. The encryption settings (Add-ons and Themes > OMEMO > Options)

For each setting, send one message to a contact with OMEMO (test2) and one to an SMS contact.

- [ ] **Only chats I switch on:** both go out unencrypted unless the chat was switched on (`/omemo on`).
- [ ] **Always use OMEMO when available:** test2's message is encrypted (padlock) without switching anything on; the SMS message goes out as normal text.
- [ ] **Always use OMEMO:** test2's is encrypted; the SMS message is **not sent**, and the chat says to type `/omemo off`. After `/omemo off` it sends.
- [ ] Changing the setting takes effect at once, without a restart.

Notes:

## 3. The code review fixes (0.1.1)

- [x] Send a message, quit Thunderbird at once, restart: the next messages decrypt both ways (passed 2026-09-26).
- [ ] **Sending while connecting:** with the chat switched on, set test1 offline and back online (or restart Thunderbird), and send a message the moment it reconnects. It arrives encrypted (padlock on test2's side), and nothing arrives as plain text.
- [ ] **Device removed while offline:** close Thunderbird. On test2's phone, remove one of test2's old devices (in Conversations or Cheogram: the account's OMEMO settings, "clean up" or delete other devices). Start Thunderbird and send to test2. `/omemo` no longer lists the removed device, and the console's `sent an encrypted message` line counts one device fewer.
- [ ] Optional, **failed lookup:** in "Always use OMEMO when available", start a chat with a contact Thunderbird hasn't messaged yet this session, and pull the network cable just before sending. The message is not sent, and the chat says it couldn't check whether the contact uses OMEMO. Plug back in and send again: it goes out encrypted. (If Thunderbird just shows the account as disconnected instead, that's fine too; the point is that nothing goes out as plain text.)

Notes:

## 4. Other OMEMO apps (task 4.12)

Per app, fill in one row for each direction. "First" is the first message after a fresh install or a new session; "Restart" means restart that side, then send.

| App (version) | Format | TB to app: first | follow-up | App to TB: first | follow-up | Restart TB | Restart app | QR verify |
|---|---|---|---|---|---|---|---|---|
| Cheogram | older | done | done | done | done | | | done |
| Conversations | older | | | | | | | |
| An app with the newer format (check omemo.top; Kaidan is one candidate) | newer | | | | | | | |
| Gajim or Dino (optional) | | | | | | | | |

- [ ] Each app shows Thunderbird's fingerprint the same way `/omemo` does.
- [ ] A photo sent from the app: note what Thunderbird shows (expected today: an `aesgcm://` link it can't open; that's the encrypted-files gap).
- [ ] Nothing in the console reads `couldn't decrypt` during normal use.

Notes:

## 5. Thunderbird versions

- [x] Thunderbird 156 on Windows (the release build).
- [ ] The current Thunderbird ESR (check thunderbird.net for its number): the add-on loads, `/omemo` answers, and a message goes each way.
- [ ] Optional: another operating system (Linux or macOS).

Notes:

## 6. OTR

Back up the profile first; OTR crashed Thunderbird once in earlier testing.

- [ ] Set `chat.otr.enable` to true and restart. Does Thunderbird crash? If so, note when (at start, opening a chat, sending).
- [ ] In an OMEMO chat, does the "Encryption Status:" button's menu offer OTR options?
- [ ] Does an OMEMO chat still send and receive encrypted?
- [ ] Set `chat.otr.enable` back to false afterwards.

Notes:

## 7. Time-based (no action needed until the date)

- [ ] After about 2026-10-02: the console shows `replaced our signed prekey (a week old)`, and messages keep decrypting both ways, including from a phone that starts a new session (reinstall or new device).
- [ ] After late December 2026: a device silent for 90 days shows "left out when encrypting" in `/omemo`.

Notes:
