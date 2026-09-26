/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * XEdDSA: signing with a Curve25519 (X25519/Montgomery) key pair, as used by
 * Signal and by OMEMO (XEP-0384) to let identity keys serve double duty as
 * both ECDH keys and signing keys.
 *
 * Reference: https://signal.org/docs/specifications/xeddsa/ (revision 1,
 * 2016-10-20). Section numbers below refer to that document.
 *
 * Signing follows the spec, with the nonce input matching libsignal's
 * implementation (see signingKeyPair); test/vectors.test.js checks it
 * byte-for-byte against the reference (test/vectors/xeddsa.json). verify()
 * adds libsignal's sign-bit convention on top of the spec, see there.
 *
 * Also exports the Montgomery <-> Edwards public key conversions, which
 * twomemo needs because it publishes identity keys in Ed25519 form.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { sha512 } from "@noble/hashes/sha512";

const Point = ed25519.Point;
const Fp = Point.Fp;
const B = Point.BASE;
const p = ed25519.CURVE.p; // 2^255 - 19
const q = ed25519.CURVE.n; // prime order of B (the spec's q)
const S_LIMIT = 1n << 253n; // 2^|q|: verify rejects s at or above this (section 4.1)

// hash1 prefix (section 2.5): the 32-byte little-endian encoding of
// 2^256 - 1 - 1, i.e. 0xFE followed by 31 bytes of 0xFF.
const HASH1_PREFIX = new Uint8Array(32).fill(0xff);
HASH1_PREFIX[0] = 0xfe;

/**
 * Converts a Curve25519 private key into the Edwards public key / private
 * scalar pair XEdDSA signs with (section 2.3, calculate_key_pair).
 *
 * @param {Uint8Array} kBytes - 32-byte X25519 private key. Clamped here, so
 *   raw keys (e.g. from x25519.utils.randomPrivateKey) work as-is.
 * @returns {{ A: Uint8Array, a: bigint }} A: 32-byte Edwards public key with
 *   sign bit 0. a: the private scalar matching A (k or -k mod q).
 */
export function calculateKeyPair(kBytes) {
  const { A, a } = signingKeyPair(kBytes);
  return { A, a };
}

/**
 * xeddsa_sign (section 4.1).
 *
 * @param {Uint8Array} kBytes - 32-byte X25519 private key.
 * @param {Uint8Array} message
 * @param {Uint8Array} random64 - exactly 64 bytes of fresh randomness (the
 *   spec's Z). Never reuse it across signatures.
 * @returns {Uint8Array} 64-byte signature (R || s).
 */
export function sign(kBytes, message, random64) {
  if (random64.length !== 64) {
    throw new Error("XEdDSA sign needs exactly 64 bytes of fresh randomness.");
  }
  const { A, a, nonceKey } = signingKeyPair(kBytes);
  const r = hashToScalar(HASH1_PREFIX, nonceKey, message, random64);
  const R = B.multiply(r).toBytes();
  const h = hashToScalar(R, A, message);
  const s = modQ(r + h * a);
  return concatBytes(R, numberToBytesLE(s));
}

/**
 * xeddsa_verify (section 4.1), for a peer's X25519 public key, with
 * libsignal's sign-bit convention: if the top bit of the signature's last
 * byte is set, it is the Edwards sign bit of the signer's key, and is cleared
 * from s before checking. XEdDSA signers always leave that bit 0 (s < 2^253),
 * so for them this is exactly the spec. Signers that sign with their key's
 * natural sign bit (python-omemo peers in oldmemo, whose identity keys are
 * published in Curve25519 form and so carry no sign bit) set it; see
 * test/vectors/xeddsa.json "natural_sign_signatures".
 *
 * @param {Uint8Array} uBytes - 32-byte X25519 public key (Montgomery u).
 * @param {Uint8Array} message
 * @param {Uint8Array} signature - 64-byte (R || s).
 * @returns {boolean} false for any malformed input; never throws.
 */
export function verify(uBytes, message, signature) {
  if (uBytes.length !== 32 || signature.length !== 64 || bytesToNumberLE(uBytes) >= p) {
    return false;
  }
  let A;
  try {
    A = montgomeryToEdwards(uBytes);
  } catch {
    return false; // u = -1 has no Edwards image
  }
  const sig = Uint8Array.from(signature);
  A[31] |= sig[63] & 0x80;
  sig[63] &= 0x7f;
  return verifyEdwards(A, message, sig);
}

/**
 * The same check as verify(), for a public key already in Edwards form. Use
 * this for twomemo identity keys, which are published in Ed25519 form and may
 * have either sign bit, so they must not be round-tripped through a
 * Montgomery u (that would lose the sign bit).
 *
 * @param {Uint8Array} ABytes - 32-byte Ed25519 public key.
 * @param {Uint8Array} message
 * @param {Uint8Array} signature - 64-byte (R || s).
 * @returns {boolean} false for any malformed input; never throws.
 */
export function verifyEdwards(ABytes, message, signature) {
  if (ABytes.length !== 32 || signature.length !== 64) {
    return false;
  }
  const R = signature.subarray(0, 32);
  const s = bytesToNumberLE(signature.subarray(32));
  if (s >= S_LIMIT) {
    return false;
  }
  let APoint;
  try {
    APoint = Point.fromBytes(ABytes); // throws if A is not on the curve
  } catch {
    return false;
  }
  const h = hashToScalar(R, ABytes, message);
  const Rcheck = B.multiplyUnsafe(modQ(s))
    .subtract(APoint.multiplyUnsafe(h))
    .toBytes();
  return bytesEqual(R, Rcheck);
}

/**
 * Montgomery u -> Edwards public key with sign bit 0 (section 5.1,
 * convert_mont): y = (u - 1) / (u + 1) mod p.
 *
 * @param {Uint8Array} uBytes - 32-byte X25519 public key.
 * @returns {Uint8Array} 32-byte Edwards encoding. Not checked to be on the
 *   curve; verifyEdwards() does that.
 * @throws if u = -1 mod p, which has no image.
 */
export function montgomeryToEdwards(uBytes) {
  const u = Fp.create(bytesToNumberLE(uBytes) & ((1n << 255n) - 1n));
  const y = Fp.mul(Fp.sub(u, 1n), Fp.inv(Fp.add(u, 1n)));
  return numberToBytesLE(y); // y < p < 2^255, so the sign bit is 0
}

/**
 * Edwards public key -> Montgomery u: u = (1 + y) / (1 - y) mod p. The sign
 * bit is dropped, since both x and -x map to the same u.
 *
 * @param {Uint8Array} ABytes - 32-byte Ed25519 public key.
 * @returns {Uint8Array} 32-byte X25519 public key.
 * @throws if A is not a valid point, or is the identity (y = 1).
 */
export function edwardsToMontgomery(ABytes) {
  const { y } = Point.fromBytes(ABytes).toAffine();
  const u = Fp.mul(Fp.add(1n, y), Fp.inv(Fp.sub(1n, y)));
  return numberToBytesLE(u);
}

// --- internals ---

/**
 * calculate_key_pair, plus the private key bytes that go into the nonce
 * hash. The spec writes hash1(a || M || Z) with a = k mod q, but libsignal's
 * implementation (and libxeddsa, our reference) hashes the key as held: the
 * clamped k itself when no negation is needed, otherwise -k mod q. Both give
 * valid signatures, since the nonce only has to be secret and unique; we
 * match the implementations so signatures can be compared byte for byte.
 */
function signingKeyPair(kBytes) {
  const kClamped = clamp(kBytes);
  const k = modQ(bytesToNumberLE(kClamped));
  const A = B.multiply(k).toBytes().slice();
  const signBit = (A[31] & 0x80) !== 0;
  A[31] &= 0x7f;
  if (!signBit) {
    return { A, a: k, nonceKey: kClamped };
  }
  const a = modQ(-k);
  return { A, a, nonceKey: numberToBytesLE(a) };
}

function clamp(kBytes) {
  if (kBytes.length !== 32) {
    throw new Error("X25519 private key must be 32 bytes.");
  }
  const c = Uint8Array.from(kBytes);
  c[0] &= 248;
  c[31] &= 127;
  c[31] |= 64;
  return c;
}

function modQ(n) {
  const r = n % q;
  return r < 0n ? r + q : r;
}

function hashToScalar(...parts) {
  return modQ(bytesToNumberLE(sha512(concatBytes(...parts))));
}

function bytesToNumberLE(bytes) {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    n = (n << 8n) | BigInt(bytes[i]);
  }
  return n;
}

function numberToBytesLE(n) {
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return bytes;
}

function concatBytes(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  return a.every((byte, i) => byte === b[i]);
}
