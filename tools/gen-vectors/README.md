# gen-vectors

Generates the known-answer test vectors in `test/vectors/` from reference OMEMO implementations, so the JavaScript crypto core can be checked byte-for-byte against code that already interoperates with real clients.

It drives Syndace's MIT-licensed Python libraries through a scripted Alice/Bob conversation: python-xeddsa, python-x3dh, python-doubleratchet, python-omemo and python-twomemo (the stack Gajim's OMEMO support uses). All randomness is seeded, so the output is byte-identical on every run. Each operation records its random draws, KDF/AEAD steps and output bytes, so a test can inject the same randomness and compare everything.

## Output

| File | Contents |
|---|---|
| `xeddsa.json` | XEdDSA signatures (spec, natural-sign-bit, Ed25519 seed), key conversions, X25519 |
| `twomemo.json` | `urn:xmpp:omemo:2` from python-twomemo: keys, bundle XML, a 9-message conversation with every message's payload, framed ratchet message and `<encrypted>` XML |
| `oldmemo.json` | `eu.siacs.conversations.axolotl` **key schedule only**: keys, X3DH, and every root/chain KDF step of the same conversation, from the generic python-x3dh and python-doubleratchet set up with oldmemo's constants. No ciphertexts or XML (see Licensing) |

The conversation covers:
- the key exchange;
- a second message sent before the reply;
- ratchet steps in both directions;
- two messages delivered out of order;
- an empty OMEMO message.

## Running

Needs [uv](https://docs.astral.sh/uv/). From this directory:

```
uv venv .venv --python 3.12
uv pip install --python .venv -r requirements.txt
.venv/Scripts/python gen_vectors.py
```

On Linux/macOS the interpreter is `.venv/bin/python`. Then run `npm test` from the repo root. Commit regenerated vectors only when a change is intended; unchanged inputs must give an unchanged diff.

## Licensing

The goal is that Thunderbird could adopt this project as-is, so the repository holds no copyleft code, including dev tooling:
- **This repo:** this script is MPL-2.0 like the rest of the repo.
- **Its dependencies:** everything it imports is MIT, BSD, Apache-2.0 or PSF (see `requirements.txt`). The reference libraries run only at dev time to produce data. Nothing from them is copied into the repository or shipped in the add-on.

**Why oldmemo is limited to the key schedule:** oldmemo has no permissively licensed implementation. libsignal, python-oldmemo (AGPL-3.0), and the clients built on them are all GPL or AGPL, which is exactly why Thunderbird never got OMEMO. So `oldmemo.json` comes from the generic MIT X3DH and Double Ratchet libraries set up with oldmemo's constants. It covers the key schedule; oldmemo's wire framing is proven against real clients in the interop tests (`docs/TASKS.md` 4.12). Do not add copyleft libraries here.

## Reference quirks worth knowing

These surfaced while building the vectors and are handled in the generator:
- **Clamped keys only:** libxeddsa signs correctly only with already-clamped private keys.
- **Natural sign bit:** libxeddsa signs with the key's natural Ed25519 sign bit instead of forcing it to 0. Its `priv_force_sign` output breaks its other functions, which re-clamp. So `xeddsa.json` "signatures" only uses keys whose natural sign bit is already 0, where the library and spec XEdDSA agree.
- **Nonce input:** the nonce hash takes the clamped private key bytes as stored, not the key reduced mod q (this matches libsignal).
- **Where oldmemo's sign bit travels:** oldmemo publishes identity keys in Curve25519 form, which has no sign bit. The Ed25519 sign bit therefore travels in the top bit of the signed prekey signature's last byte (libsignal's convention). Peers built on python-omemo rely on this.
