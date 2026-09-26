# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
Generates known-answer test vectors for the crypto core (docs/TASKS.md 2.2)
by driving Syndace's permissively licensed reference implementations
(python-xeddsa, python-x3dh, python-doubleratchet, python-omemo and
python-twomemo, all MIT) through a scripted Alice/Bob conversation, and
writes everything as JSON to test/vectors/.

oldmemo has no permissively licensed reference: every implementation we
know of, python-oldmemo included, is GPL or AGPL. To keep this repository
free of copyleft tooling, so Thunderbird could adopt it, the oldmemo vectors
come from the generic MIT X3DH and Double Ratchet libraries configured with
oldmemo's constants. They cover the key schedule; oldmemo's wire framing is
proven against real clients instead (docs/TASKS.md 4.12).

All randomness is replaced by a seeded generator, so re-running this produces
byte-identical output. Every random draw is recorded next to the operation
that consumed it, so the JS side can inject the same values and compare
every output byte.

The reference libraries are only imported at dev time to produce data; none
of their code is copied into this repository or shipped in the add-on.

Run from this directory (see README.md):
    .venv/Scripts/python gen_vectors.py
"""

import asyncio
import base64
import hashlib
import importlib.metadata
import json
import os
import secrets
import subprocess
import sys
import types
import xml.etree.ElementTree as ET
from pathlib import Path

# Bytes hashing is randomized per process, which changes set iteration order
# inside the libraries (e.g. which pre key gets picked). Pin it by re-running
# ourselves with a fixed hash seed.
if os.environ.get("PYTHONHASHSEED") != "0":
    sys.exit(subprocess.run([sys.executable, *sys.argv], env={**os.environ, "PYTHONHASHSEED": "0"}).returncode)

import doubleratchet
import xeddsa
import x3dh
import x3dh.base_state
import x3dh.identity_key_pair
from doubleratchet.recommended import (
    HashFunction,
    aead_aes_hmac,
    diffie_hellman_ratchet_curve25519,
    kdf_hkdf,
    kdf_separate_hmacs,
)
from omemo.message import Message
from omemo.storage import Just, Nothing, Storage

import twomemo
import twomemo.etree
import twomemo.twomemo

OUT_DIR = Path(__file__).resolve().parents[2] / "test" / "vectors"
SEED = b"thunderbird-omemo test vectors v1"


# --- deterministic randomness, with a log of every draw ---


class Recorder:
    """Seeded replacement for all randomness, plus a per-operation log."""

    def __init__(self, seed):
        self.seed = seed
        self.counter = 0
        self.draws = []
        self.trace = []

    def bytes(self, n, source):
        out = b""
        while len(out) < n:
            out += hashlib.sha256(self.seed + self.counter.to_bytes(8, "big")).digest()
            self.counter += 1
        out = out[:n]
        self.draws.append({"source": source, "value": out.hex()})
        return out

    def begin(self):
        """Start a new operation; returns the previous operation's log."""
        log = {"random": self.draws, "trace": self.trace}
        self.draws, self.trace = [], []
        return log


REC = Recorder(SEED)


def install_randomness():
    secrets.token_bytes = lambda n=32: REC.bytes(n, "token_bytes")

    def choice(seq):
        seq = sorted(seq)
        return seq[int.from_bytes(REC.bytes(4, "choice"), "big") % len(seq)]

    secrets.choice = choice
    diffie_hellman_ratchet_curve25519.DiffieHellmanRatchet._generate_priv = staticmethod(
        lambda: REC.bytes(32, "ratchet_priv")
    )
    # Signed prekeys carry a creation timestamp; pin it (2026-01-01T00:00:00Z).
    x3dh.base_state.time = types.SimpleNamespace(time=lambda: 1767225600)


def install_tracing(module, aead=True):
    """Log every KDF step (and AEAD call, if aead) made by one namespace's classes."""

    def wrap_classmethod(cls, name, record):
        original = getattr(cls, name)

        async def wrapper(_cls, *args):
            out = await original(*args)
            REC.trace.append(record(args, out))
            return out

        setattr(cls, name, classmethod(wrapper))

    wrap_classmethod(module.RootChainKDFImpl, "derive", lambda a, out: {
        "step": "root_kdf", "root_key": a[0].hex(), "dh_out": a[1].hex(),
        "new_root_key": out[:32].hex(), "chain_key": out[32:].hex(),
    })
    wrap_classmethod(module.MessageChainKDFImpl, "derive", lambda a, out: {
        "step": "chain_kdf", "chain_key": a[0].hex(),
        "next_chain_key": out[:32].hex(), "message_key": out[32:].hex(),
    })
    if not aead:
        return
    wrap_classmethod(module.AEADImpl, "encrypt", lambda a, out: {
        "step": "aead_encrypt", "plaintext": a[0].hex(), "message_key": a[1].hex(),
        "associated_data": a[2].hex(), "output": out.hex(),
    })
    wrap_classmethod(module.AEADImpl, "decrypt", lambda a, out: {
        "step": "aead_decrypt", "ciphertext": a[0].hex(), "message_key": a[1].hex(),
        "associated_data": a[2].hex(), "plaintext": out.hex(),
    })


def install_x3dh_tracing():
    base = x3dh.base_state.BaseState
    active = base.get_shared_secret_active
    passive = base.get_shared_secret_passive

    async def traced_active(self, bundle, *args, **kwargs):
        shared_secret, associated_data, header = await active(self, bundle, *args, **kwargs)
        REC.trace.append({
            "step": "x3dh_active", "shared_secret": shared_secret.hex(),
            "associated_data": associated_data.hex(), "ephemeral_pub": header.ephemeral_key.hex(),
            "pre_key_pub": header.pre_key.hex() if header.pre_key else None,
        })
        return shared_secret, associated_data, header

    async def traced_passive(self, header, *args, **kwargs):
        shared_secret, associated_data, spk = await passive(self, header, *args, **kwargs)
        REC.trace.append({
            "step": "x3dh_passive", "shared_secret": shared_secret.hex(),
            "associated_data": associated_data.hex(),
        })
        return shared_secret, associated_data, spk

    base.get_shared_secret_active = traced_active
    base.get_shared_secret_passive = traced_passive


# --- minimal in-memory storage for the omemo backends ---


class MemoryStorage(Storage):
    def __init__(self):
        super().__init__(True)
        self.data = {}

    async def _load(self, key):
        return Just(self.data[key]) if key in self.data else Nothing()

    async def _store(self, key, value):
        self.data[key] = value

    async def _delete(self, key):
        self.data.pop(key, None)


# --- helpers ---


def b64d(s):
    return base64.b64decode(s)


def clamp(k):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


def xml_string(element):
    return ET.tostring(element, encoding="unicode")


def versions():
    names = ["xeddsa", "x3dh", "doubleratchet", "omemo", "twomemo"]
    return {n: importlib.metadata.version(n) for n in names}


def write(name, data):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / name
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {path.relative_to(OUT_DIR.parents[1])}")


def header_of(encrypted_message):
    h = encrypted_message.header
    return {"dh_pub": h.ratchet_pub.hex(), "pn": h.previous_sending_chain_length, "n": h.sending_chain_length}


# --- XEdDSA and key conversions ---


def xeddsa_vectors():
    # libxeddsa (python-xeddsa) differs from the XEdDSA spec in two ways that
    # matter here: it needs an already-clamped private key, and it signs with
    # the key's natural Ed25519 sign bit instead of forcing it to 0 (and its
    # priv_force_sign output breaks its other functions, which re-clamp). So:
    #   - "signatures" only uses keys whose natural sign bit is already 0,
    #     where libxeddsa and spec XEdDSA agree; these must match our sign()
    #     byte for byte. Keys with sign bit 1 have no reference here;
    #     test/xeddsa.test.js covers them by checking against Ed25519.
    #   - "natural_sign_signatures" is what python-omemo peers actually send.
    #     In oldmemo bundles the sign bit rides in the top bit of the
    #     signature's last byte (libsignal's curve_sigs convention), since the
    #     identity key is published in Curve25519 form, which has no sign bit.
    REC.begin()
    signatures = []
    for msg_len in [0, 1, 33, 100, 1000]:
        while True:
            raw = REC.bytes(32, "priv")
            if xeddsa.priv_to_ed25519_pub(clamp(raw))[31] >> 7 == 0:
                break
        msg = REC.bytes(msg_len, "msg")
        nonce = REC.bytes(64, "nonce")
        ed_pub = xeddsa.priv_to_ed25519_pub(clamp(raw))
        sig = xeddsa.ed25519_priv_sign(clamp(raw), msg, nonce)
        assert xeddsa.ed25519_verify(sig, ed_pub, msg)
        signatures.append({
            "priv": raw.hex(), "curve25519_pub": xeddsa.priv_to_curve25519_pub(raw).hex(),
            "ed25519_pub": ed_pub.hex(), "message": msg.hex(), "nonce": nonce.hex(), "signature": sig.hex(),
        })

    natural_sign_signatures = []
    want_sign_bits = {0, 1}
    while want_sign_bits:
        priv = clamp(REC.bytes(32, "priv"))
        ed_pub = xeddsa.priv_to_ed25519_pub(priv)
        sign_bit = ed_pub[31] >> 7
        if sign_bit not in want_sign_bits:
            continue
        want_sign_bits.discard(sign_bit)
        msg = REC.bytes(33, "msg")
        sig = xeddsa.ed25519_priv_sign(priv, msg, REC.bytes(64, "nonce"))
        assert xeddsa.ed25519_verify(sig, ed_pub, msg)
        libsignal_sig = bytearray(sig)
        libsignal_sig[63] |= ed_pub[31] & 0x80
        natural_sign_signatures.append({
            "priv": priv.hex(), "curve25519_pub": xeddsa.priv_to_curve25519_pub(priv).hex(),
            "ed25519_pub": ed_pub.hex(), "sign_bit": sign_bit, "message": msg.hex(),
            "signature": sig.hex(), "signature_with_sign_bit": bytes(libsignal_sig).hex(),
        })

    seed_signatures = []
    want_sign_bits = {0, 1}
    while want_sign_bits:
        seed = REC.bytes(32, "seed")
        ed_pub = xeddsa.seed_to_ed25519_pub(seed)
        sign_bit = ed_pub[31] >> 7
        if sign_bit not in want_sign_bits:
            continue
        want_sign_bits.discard(sign_bit)
        msg = REC.bytes(64, "msg")
        sig = xeddsa.ed25519_seed_sign(seed, msg)
        assert xeddsa.ed25519_verify(sig, ed_pub, msg)
        seed_signatures.append({
            "seed": seed.hex(), "priv": xeddsa.seed_to_priv(seed).hex(), "ed25519_pub": ed_pub.hex(),
            "sign_bit": sign_bit, "curve25519_pub": xeddsa.ed25519_pub_to_curve25519_pub(ed_pub).hex(),
            "message": msg.hex(), "signature": sig.hex(),
        })

    conversions = []
    for _ in range(4):
        curve_pub = xeddsa.priv_to_curve25519_pub(REC.bytes(32, "priv"))
        conversions.append({
            "curve25519_pub": curve_pub.hex(),
            "ed25519_pub_sign_bit_0": xeddsa.curve25519_pub_to_ed25519_pub(curve_pub, False).hex(),
            "ed25519_pub_sign_bit_1": xeddsa.curve25519_pub_to_ed25519_pub(curve_pub, True).hex(),
        })

    x25519 = []
    for _ in range(2):
        priv = REC.bytes(32, "priv")
        other_pub = xeddsa.priv_to_curve25519_pub(REC.bytes(32, "priv"))
        x25519.append({"priv": priv.hex(), "other_pub": other_pub.hex(),
                       "shared_secret": xeddsa.x25519(priv, other_pub).hex()})

    REC.begin()
    return {
        "signatures": signatures,
        "natural_sign_signatures": natural_sign_signatures,
        "seed_signatures": seed_signatures,
        "conversions": conversions,
        "x25519": x25519,
    }


# --- conversations ---


ALICE = ("alice@example.org", 1111111)
BOB = ("bob@example.org", 2222222)

# (sender, text). An empty text sends an empty OMEMO message (no payload).
SCRIPT = [
    ("alice", "Hi Bob, first message (carries the key exchange)."),
    ("alice", "Second message, sent before Bob has replied."),
    ("bob", "Hi Alice! Bob's first reply, a new ratchet key."),
    ("bob", "Bob again, same chain."),
    ("alice", "Alice replies, another ratchet step."),
    ("bob", "Short."),
    ("alice", "Seventh: delivered after the eighth."),
    ("alice", "Eighth: delivered before the seventh."),
    ("bob", ""),
]
# Every send and delivery, in order. Messages 6 and 7 arrive swapped.
TIMELINE = [
    ("send", 0), ("deliver", 0), ("send", 1), ("deliver", 1),
    ("send", 2), ("deliver", 2), ("send", 3), ("deliver", 3),
    ("send", 4), ("deliver", 4), ("send", 5), ("deliver", 5),
    ("send", 6), ("send", 7), ("deliver", 7), ("deliver", 6),
    ("send", 8), ("deliver", 8),
]


def choose_identity(name, kind, sign_bit):
    """
    Draw an identity key. kind is "priv" (a Curve25519 scalar, like our
    add-on and libsignal clients) or "seed" (an Ed25519 seed, python-omemo's
    default). sign_bit picks a key whose natural Ed25519 sign bit is 0 or 1,
    to exercise both paths through signature verification.
    """
    while True:
        secret = REC.bytes(32, f"{name}_identity_{kind}")
        if kind == "priv":
            secret = clamp(secret)  # libxeddsa signs correctly only with clamped keys
            ed_pub = xeddsa.priv_to_ed25519_pub(secret)
        else:
            ed_pub = xeddsa.seed_to_ed25519_pub(secret)
        if ed_pub[31] >> 7 == sign_bit:
            break
    priv = secret if kind == "priv" else xeddsa.seed_to_priv(secret)
    identity = {"kind": kind, kind: secret.hex(), "ed25519_pub": ed_pub.hex(),
                "curve25519_pub": xeddsa.priv_to_curve25519_pub(priv).hex()}
    if kind == "seed":
        identity["priv"] = priv.hex()
    return secret, identity


def describe_keys(state_json, spk_id, pre_key_id):
    """Signed prekey and pre keys from an X3DH state's JSON, as hex."""
    # The X3DH state stores bytes as JSON strings of code points 0-255.
    state_bytes = lambda s: bytes(map(ord, s))
    spk = state_json["signed_pre_key"]
    spk_priv = state_bytes(spk["priv"])
    pre_keys = []
    for encoded in state_json["pre_keys"]:
        priv = state_bytes(encoded)
        pub = xeddsa.priv_to_curve25519_pub(priv)
        pre_keys.append({"id": pre_key_id(pub), "priv": priv.hex(), "pub": pub.hex()})
    return {
        "signed_pre_key": {
            "id": spk_id, "priv": spk_priv.hex(), "pub": xeddsa.priv_to_curve25519_pub(spk_priv).hex(),
            "signature": state_bytes(spk["sig"]).hex(), "timestamp": spk["timestamp"],
        },
        "pre_keys": sorted(pre_keys, key=lambda k: k["id"]),
    }


# --- twomemo, through python-twomemo's backend ---


async def make_twomemo_party(name, jid, device_id, identity_kind, sign_bit):
    storage = MemoryStorage()
    REC.begin()
    secret, identity = choose_identity(name, identity_kind, sign_bit)
    await storage.store("/ikp/is_seed", identity_kind == "seed")
    await storage.store_bytes("/ikp/key", secret)
    backend = twomemo.Twomemo(storage)
    await backend.generate_pre_keys(3)
    bundle = await backend.get_bundle(jid, device_id)
    setup_log = REC.begin()

    keys = describe_keys(storage.data[f"/{twomemo.twomemo.NAMESPACE}/x3dh"],
                         bundle.signed_pre_key_id, lambda pub: bundle.pre_key_ids[pub])
    assert keys["signed_pre_key"]["pub"] == bundle.bundle.signed_pre_key.hex()
    return backend, {"jid": jid, "device_id": device_id, "identity": identity, **keys,
                     "setup_random": setup_log["random"]}


async def twomemo_vectors():
    namespace = twomemo.twomemo.NAMESPACE
    etree = twomemo.etree
    ET.register_namespace("", namespace)  # xmlns='...' like real clients, not ns0: prefixes

    # Alice stands in for our add-on: a Curve25519 identity whose natural sign
    # bit is 0, so the reference's encodings match what XEdDSA-with-forced-
    # sign-bit produces. Bob is a python-omemo-style peer: an Ed25519 seed
    # whose public key has sign bit 1, published as-is.
    alice, alice_info = await make_twomemo_party("alice", *ALICE, "priv", 0)
    bob, bob_info = await make_twomemo_party("bob", *BOB, "seed", 1)

    # Bob's bundle, as it would be published and fetched over PEP.
    bundle_xml = xml_string(etree.serialize_bundle(await bob.get_bundle(*BOB)))
    bob_info["bundle_xml"] = bundle_xml
    bob_bundle = etree.parse_bundle(ET.fromstring(bundle_xml), *BOB)

    backends = {"alice": alice, "bob": bob}
    sessions = {}
    peers = {"alice": "bob", "bob": "alice"}
    own = {"alice": ALICE, "bob": BOB}

    sent = {}
    for action, index in TIMELINE:
        sender, text = SCRIPT[index]
        REC.begin()

        if action == "send":
            backend = backends[sender]
            plaintext = text.encode("utf-8")
            if plaintext:
                content, key_material = await backend.encrypt_plaintext(plaintext)
            else:
                content, key_material = await backend.encrypt_empty()

            if sender not in sessions:
                # Only Alice gets here: she starts the session from Bob's bundle.
                session, encrypted = await backend.build_session_active(*BOB, bob_bundle, key_material)
                sessions[sender] = session
            else:
                session = sessions[sender]
                encrypted = await backend.encrypt_key_material(session, key_material)

            # The initiator keeps attaching the key exchange until a reply confirms the session.
            unconfirmed = session.initiation.name == "ACTIVE" and not session.confirmed
            key_exchange = session.key_exchange if unconfirmed else None
            message = Message(namespace, own[sender][0], own[sender][1], content,
                              frozenset([(encrypted, key_exchange)]))

            record = {
                "index": index, "from": sender, "plaintext": text, "empty": not plaintext,
                "payload_key_material": (key_material.key + key_material.auth_tag).hex(),
                "payload_ciphertext": content.ciphertext.hex(),
                "header": header_of(encrypted.encrypted_message),
                "ratchet_message": encrypted.serialize().hex(),
                "key_exchange": key_exchange is not None,
                "xml": xml_string(etree.serialize_message(message)),
            }
            record["encrypt"] = REC.begin()
            sent[index] = (record, encrypted, key_exchange, content)

        else:
            record, encrypted, key_exchange, content = sent[index]
            receiver = peers[sender]
            backend = backends[receiver]
            if receiver not in sessions:
                session, key_material = await backend.build_session_passive(
                    *own[sender], key_exchange, encrypted)
                sessions[receiver] = session
            else:
                key_material = await backend.decrypt_key_material(sessions[receiver], encrypted)
            if record["empty"]:
                plaintext = b""
            else:
                plaintext = await backend.decrypt_plaintext(content, key_material)
            assert plaintext.decode("utf-8") == record["plaintext"], index
            record["decrypt"] = REC.begin()

    return {
        "namespace": namespace,
        "alice": alice_info,
        "bob": bob_info,
        "timeline": [list(event) for event in TIMELINE],
        "messages": [sent[i][0] for i in range(len(SCRIPT))],
    }


# --- oldmemo key schedule, from the generic MIT libraries ---
#
# Configured with oldmemo's constants as documented in docs/TASKS.md. The
# ratchet's message cipher here is the library's generic AES-CBC + HMAC, not
# oldmemo's framing (version byte, protobuf layout, 8-byte MAC), so these
# vectors record keys and KDF steps but no ciphertexts or XML.


class OldmemoX3DH(x3dh.BaseState):
    @staticmethod
    def _encode_public_key(key_format, pub):
        # 0x05 type byte + Curve25519 key; the identity key is held in Ed25519 form.
        if key_format is x3dh.IdentityKeyFormat.ED_25519:
            pub = xeddsa.ed25519_pub_to_curve25519_pub(pub)
        return b"\x05" + pub


class OldmemoRootKDF(kdf_hkdf.KDF):
    @staticmethod
    def _get_hash_function():
        return HashFunction.SHA_256

    @staticmethod
    def _get_info():
        return b"WhisperRatchet"


class OldmemoMessageKDF(kdf_separate_hmacs.KDF):
    @staticmethod
    def _get_hash_function():
        return HashFunction.SHA_256


class GenericAEAD(aead_aes_hmac.AEAD):
    @staticmethod
    def _get_hash_function():
        return HashFunction.SHA_256

    @staticmethod
    def _get_info():
        return b"WhisperMessageKeys"


class OldmemoDoubleRatchet(doubleratchet.DoubleRatchet):
    @staticmethod
    def _build_associated_data(associated_data, header):
        return associated_data


OLDMEMO_KDFS = types.SimpleNamespace(RootChainKDFImpl=OldmemoRootKDF, MessageChainKDFImpl=OldmemoMessageKDF)
RATCHET_CONFIG = (diffie_hellman_ratchet_curve25519.DiffieHellmanRatchet, OldmemoRootKDF, OldmemoMessageKDF,
                  b"\x02\x01", 1000, 1000, GenericAEAD)


def make_oldmemo_party(name, jid, device_id, sign_bit):
    REC.begin()
    secret, identity = choose_identity(name, "priv", sign_bit)
    state = OldmemoX3DH.create(
        x3dh.IdentityKeyFormat.ED_25519, x3dh.HashFunction.SHA_256, b"WhisperText",
        x3dh.identity_key_pair.IdentityKeyPairPriv(secret),
    )
    state.generate_pre_keys(3)
    setup_log = REC.begin()

    # Pre key ids are assigned by the OMEMO layer, not X3DH; number them by public key.
    pubs = sorted(state.bundle.pre_keys)
    keys = describe_keys(state.json, 1, lambda pub: pubs.index(pub) + 1)
    return state, {"jid": jid, "device_id": device_id, "identity": identity, **keys,
                   "setup_random": setup_log["random"]}


async def oldmemo_vectors():
    # Alice stands in for our add-on (sign bit 0). Bob is a peer whose
    # identity key has natural sign bit 1: in a real oldmemo bundle that bit
    # rides in the top bit of the signed prekey signature's last byte.
    alice, alice_info = make_oldmemo_party("alice", *ALICE, 0)
    bob, bob_info = make_oldmemo_party("bob", *BOB, 1)

    encoded_identity = {
        name: OldmemoX3DH._encode_public_key(x3dh.IdentityKeyFormat.ED_25519, state.bundle.identity_key)
        for name, state in (("alice", alice), ("bob", bob))
    }
    peers = {"alice": "bob", "bob": "alice"}
    ratchets = {}
    handshake = None
    alice_confirmed = False

    sent = {}
    for action, index in TIMELINE:
        sender, text = SCRIPT[index]
        receiver = peers[sender]
        # libsignal authenticates every message with sender IK + recipient IK.
        associated_data = encoded_identity[sender] + encoded_identity[receiver]
        REC.begin()

        if action == "send":
            # The ratchet carries the body's key material: key + GCM tag (32 B),
            # or 16 random bytes for an empty message.
            key_material = REC.bytes(32 if text else 16, "key_material")
            if sender not in ratchets:
                shared_secret, x3dh_ad, handshake = await alice.get_shared_secret_active(bob.bundle)
                assert x3dh_ad == associated_data
                ratchets[sender], encrypted = await OldmemoDoubleRatchet.encrypt_initial_message(
                    *RATCHET_CONFIG, shared_secret, bob.bundle.signed_pre_key, key_material, associated_data)
            else:
                encrypted = await ratchets[sender].encrypt_message(key_material, associated_data)

            record = {
                "index": index, "from": sender, "plaintext": text, "empty": not text,
                "key_material": key_material.hex(),
                "header": header_of(encrypted),
                "key_exchange": sender == "alice" and not alice_confirmed,
                "associated_data": associated_data.hex(),
            }
            record["encrypt"] = REC.begin()
            sent[index] = (record, encrypted, key_material)

        else:
            record, encrypted, key_material = sent[index]
            if receiver not in ratchets:
                shared_secret, _, spk = await bob.get_shared_secret_passive(handshake)
                ratchets[receiver], plaintext = await OldmemoDoubleRatchet.decrypt_initial_message(
                    *RATCHET_CONFIG, shared_secret, spk.priv, encrypted, associated_data)
            else:
                plaintext = await ratchets[receiver].decrypt_message(encrypted, associated_data)
            assert plaintext == key_material, index
            alice_confirmed = alice_confirmed or receiver == "alice"
            record["decrypt"] = REC.begin()

    return {
        "namespace": "eu.siacs.conversations.axolotl",
        "alice": alice_info,
        "bob": bob_info,
        "timeline": [list(event) for event in TIMELINE],
        "messages": [sent[i][0] for i in range(len(SCRIPT))],
    }


def about(what):
    return {
        "_about": (
            f"Known-answer vectors for {what}. Generated by tools/gen-vectors/gen_vectors.py; "
            "do not edit by hand. Byte strings are hex. 'random' lists every random draw an operation "
            "made, in order; 'trace' lists its KDF/AEAD steps."
        ),
        "libraries": versions(),
    }


async def main():
    install_randomness()
    install_x3dh_tracing()
    install_tracing(twomemo.twomemo)
    install_tracing(OLDMEMO_KDFS, aead=False)

    write("xeddsa.json", {**about("XEdDSA and Curve25519/Ed25519 conversions"), **xeddsa_vectors()})
    write("twomemo.json", {**about("twomemo (X3DH, Double Ratchet, payload, XML), from python-twomemo"),
                           **(await twomemo_vectors())})
    write("oldmemo.json", {**about("the oldmemo key schedule (X3DH, root and chain KDFs), from the "
                                   "generic python-x3dh and python-doubleratchet with oldmemo's constants; "
                                   "no ciphertexts, since the framing is not oldmemo's"),
                           **(await oldmemo_vectors())})


if __name__ == "__main__":
    asyncio.run(main())
