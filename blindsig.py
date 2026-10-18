"""Chaum FDH-RSA blind signatures — the search gate's membership proof.

The property: the gate knows a request comes from SOMEONE with a Handshake
identity, and cannot know WHICH one, even with full logs of both servers.
Blind signatures give that by math:

    issuance (issuer, knows the name):
        client:  nonce ← random 32B;  m = FDH(nonce)
                 r ← random;  b = m · r^e  mod n          (blinded)
        server:  s_b = b^d mod n                          (signs blind)
        client:  s = s_b · r⁻¹ mod n   →  s = m^d mod n   (unblinds)

    redemption (gate, knows only "a member"):
        verify:  s^e mod n == FDH(nonce)

The server signed something it could not read, so token {nonce, s} is
unlinkable to the issuance request. FDH (full-domain hash) is what makes
textbook RSA blinding sound: hashing onto the full modulus destroys the
multiplicative structure behind forgery tricks (Chaum's construction as
analysed by Bellare-Rogaway).

The issuer SIGNS (holds d); the gate only VERIFIES (holds n, e). The
blind/unblind client half is here for the tests and as the reference for
client implementations.
"""
import hashlib
import json
import secrets

# ------------------------------------------------------------------ FDH

def fdh(nonce: bytes, n: int) -> int:
    """Full-domain hash of `nonce` onto Z_n.

    SHA-256 counter expansion to the modulus byte-length, reduced mod n.
    Deterministic; every implementation must match it bit for bit.
    """
    nbytes = (n.bit_length() + 7) // 8
    out = b""
    counter = 0
    while len(out) < nbytes:
        out += hashlib.sha256(counter.to_bytes(4, "big") + nonce).digest()
        counter += 1
    return int.from_bytes(out[:nbytes], "big") % n


# ------------------------------------------------------------- client side

def new_nonce() -> bytes:
    return secrets.token_bytes(32)


def blind(nonce: bytes, n: int, e: int):
    """→ (blinded_int, r). r must stay secret and be used exactly once."""
    m = fdh(nonce, n)
    while True:
        r = secrets.randbelow(n - 2) + 2
        # r must be invertible mod n; for an RSA modulus a non-invertible r
        # would factor n, so this loop body effectively never repeats.
        try:
            pow(r, -1, n)
            break
        except ValueError:
            continue
    return (m * pow(r, e, n)) % n, r


def unblind(signed_blinded: int, r: int, n: int) -> int:
    return (signed_blinded * pow(r, -1, n)) % n


# ------------------------------------------------------------- server side

def sign_blinded(blinded: int, n: int, d: int) -> int:
    """The issuer's only cryptographic act: sign what it cannot read."""
    if not (0 < blinded < n):
        raise ValueError("blinded value out of range")
    return pow(blinded, d, n)


def verify(nonce: bytes, signature: int, n: int, e: int) -> bool:
    if not (0 < signature < n):
        return False
    return pow(signature, e, n) == fdh(nonce, n)


# ------------------------------------------------------------------- keys

def generate_keypair(bits: int = 2048):
    """RSA keypair as plain integers, via the cryptography package (its
    prime generation, not ours). Returns ({n,e}, {n,e,d})."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pub = key.public_key().public_numbers()
    priv = key.private_numbers()
    return ({"n": pub.n, "e": pub.e},
            {"n": pub.n, "e": pub.e, "d": priv.d})


def save_key(path: str, key: dict):
    with open(path, "w") as fh:
        json.dump({k: str(v) for k, v in key.items()}, fh)


def load_key(path: str) -> dict:
    with open(path) as fh:
        return {k: int(v) for k, v in json.load(fh).items()}


# ------------------------------------------------------------------- epochs
#
# Keeping no records: the gate's spent-set lives in RAM, which is only safe
# because tokens are scoped to an ISSUER-KEY EPOCH. Each key has a short id and
# a validity window; the issuer signs with the current key, the gate verifies
# against the key the token names, and when a key rotates out its whole
# spent-bucket is dropped — rotation IS garbage collection, and a gate restart
# can never enable double-spend beyond the current epoch. This is the Privacy
# Pass key_id/rotation model (RFC 9576 §7.1, RFC 9578 §4) applied to our
# self-contained gate.

def key_id(pub: dict) -> str:
    """A short, stable id for a public key: 8 bytes of SHA-256(n || e), hex.

    Names the epoch a token was signed under. The gate looks the key up by
    this, so it must be derivable identically on both sides — hence a fixed
    canonical encoding (big-endian, byte-length from the modulus)."""
    n, e = int(pub["n"]), int(pub["e"])
    nbytes = (n.bit_length() + 7) // 8
    ebytes = (e.bit_length() + 7) // 8
    h = hashlib.sha256(n.to_bytes(nbytes, "big") + e.to_bytes(ebytes, "big"))
    return h.digest()[:8].hex()


def current_signing_key(keyset: list, now: int) -> dict:
    """The issuer key to sign with: the newest whose window is open now.

    Newest-by-not_before so a freshly rotated-in key takes over immediately;
    raises if the keyset has no open key (a rotation gap — refuse to sign
    rather than sign under an expired epoch)."""
    live = [k for k in keyset
            if int(k["not_before"]) <= now < int(k["not_after"])]
    if not live:
        raise ValueError("no issuer key is valid right now (rotation gap)")
    return max(live, key=lambda k: int(k["not_before"]))


def public_view(keyset: list) -> list:
    """The keyset with private exponents stripped — what the gate may hold.

    Carries id + (n, e) + window only. The gate can VERIFY and know when a
    key expires; it can never SIGN, and holds no secret to leak."""
    out = []
    for k in keyset:
        pub = {"n": str(k["n"]), "e": str(k["e"])}
        out.append({"key_id": k.get("key_id") or key_id(pub),
                    "n": str(k["n"]), "e": str(k["e"]),
                    "not_before": int(k["not_before"]),
                    "not_after": int(k["not_after"])})
    return out


# ------------------------------------------------------------- wire format
#
# key_id . nonce . signature  — all hex. The key_id is what lets the gate pick
# the right epoch key to verify against and the right spent-bucket to burn in.

def token_encode(kid: str, nonce: bytes, signature: int) -> str:
    return kid + "." + nonce.hex() + "." + format(signature, "x")


def token_decode(token: str):
    parts = str(token).split(".")
    if len(parts) != 3:
        raise ValueError("malformed token")
    kid, nonce_hex, sig_hex = parts
    if len(kid) != 16 or len(nonce_hex) != 64 or not sig_hex:
        raise ValueError("malformed token")
    return kid, bytes.fromhex(nonce_hex), int(sig_hex, 16)
