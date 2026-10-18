"""The search gate's privacy and correctness properties.

Pins the epoch model that makes a RAM-only spent-set safe: a token verifies
only in its key's window, a spent nonce is refused, rotating a key out drops
its whole bucket (so nonces can recur under a NEW key but never under the same
one), and — the safety catch — a fresh gate (RAM wiped, as after a restart)
can re-accept an old token ONLY while its epoch is still open, never after the
key has rotated out. Verify-and-spend must be atomic under concurrency.
"""
import importlib.util
import os
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


blindsig = _load("blindsig")
gate = _load("gate")

# One small keypair for the whole suite: 1024-bit is plenty to exercise the
# math and keeps the tests fast (this is not the production key size).
_PUB, _PRIV = blindsig.generate_keypair(1024)


def make_token(priv, pub, now_ok=True):
    """A full client→issuer→client token under key `priv`."""
    kid = blindsig.key_id(pub)
    nonce = blindsig.new_nonce()
    b, r = blindsig.blind(nonce, pub["n"], pub["e"])
    s_b = blindsig.sign_blinded(b, priv["n"], priv["d"])
    s = blindsig.unblind(s_b, r, pub["n"])
    return kid, nonce, s


def keyset_file(tmp, keys):
    import json
    path = os.path.join(tmp, "keyset.json")
    with open(path, "w") as fh:
        json.dump(keys, fh)
    # Bump mtime deterministically so reload() always re-reads in a fast test.
    os.utime(path, (time.time() + len(keys), time.time() + len(keys)))
    return path


def pubrow(pub, not_before, not_after):
    return {"key_id": blindsig.key_id(pub), "n": str(pub["n"]), "e": str(pub["e"]),
            "not_before": int(not_before), "not_after": int(not_after)}


class EpochTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self.now = 1_000_000

    def _keys(self, kset):
        return gate.KeySet(keyset_file(self.tmp, kset))

    def test_valid_token_redeems_once(self):
        ks = self._keys([pubrow(_PUB, self.now - 10, self.now + 100)])
        kid, nonce, sig = make_token(_PRIV, _PUB)
        ok, why = ks.redeem(kid, nonce, sig, self.now)
        self.assertTrue(ok, why)

    def test_spent_nonce_is_refused(self):
        ks = self._keys([pubrow(_PUB, self.now - 10, self.now + 100)])
        kid, nonce, sig = make_token(_PRIV, _PUB)
        self.assertTrue(ks.redeem(kid, nonce, sig, self.now)[0])
        ok, why = ks.redeem(kid, nonce, sig, self.now)
        self.assertFalse(ok)
        self.assertIn("spent", why)

    def test_token_outside_window_is_refused(self):
        ks = self._keys([pubrow(_PUB, self.now - 100, self.now - 10)])  # closed
        kid, nonce, sig = make_token(_PRIV, _PUB)
        ok, why = ks.redeem(kid, nonce, sig, self.now)
        self.assertFalse(ok)

    def test_unknown_key_is_refused(self):
        other_pub, _ = blindsig.generate_keypair(1024)
        ks = self._keys([pubrow(_PUB, self.now - 10, self.now + 100)])
        kid, nonce, sig = make_token(_PRIV, _PUB)
        # Present the right token but claim a key_id the gate does not hold.
        ok, why = ks.redeem(blindsig.key_id(other_pub), nonce, sig, self.now)
        self.assertFalse(ok)
        self.assertIn("unknown", why)

    def test_forged_signature_is_refused(self):
        ks = self._keys([pubrow(_PUB, self.now - 10, self.now + 100)])
        kid = blindsig.key_id(_PUB)
        nonce = blindsig.new_nonce()
        ok, why = ks.redeem(kid, nonce, 12345, self.now)  # not a real signature
        self.assertFalse(ok)

    def test_rotation_drops_the_spent_bucket(self):
        # A nonce spent under key A is forgotten once A rotates out — the RAM
        # set never accumulates across epochs. (Reusing the SAME nonce under a
        # NEW key is fine and expected; nonces are per-epoch.)
        path = keyset_file(self.tmp, [pubrow(_PUB, self.now - 10, self.now + 100)])
        ks = gate.KeySet(path)
        kid, nonce, sig = make_token(_PRIV, _PUB)
        self.assertTrue(ks.redeem(kid, nonce, sig, self.now)[0])
        self.assertIn(kid, ks._spent)
        # Rotate: publish a keyset WITHOUT key A. Reload must drop A's bucket.
        new_pub, _ = blindsig.generate_keypair(1024)
        import json
        with open(path, "w") as fh:
            json.dump([pubrow(new_pub, self.now, self.now + 100)], fh)
        os.utime(path, (time.time() + 99, time.time() + 99))
        ks.reload()
        self.assertNotIn(kid, ks._spent)

    def test_restart_reaccepts_only_within_epoch(self):
        # The safety catch: a fresh gate (new KeySet == RAM wiped) re-accepts an
        # old token IF its epoch is still open (bounded re-spend, acceptable),
        # but NEVER once the key has rotated out.
        kid, nonce, sig = make_token(_PRIV, _PUB)
        # same epoch, fresh gate -> accepted (this is the bounded window)
        ks1 = self._keys([pubrow(_PUB, self.now - 10, self.now + 100)])
        self.assertTrue(ks1.redeem(kid, nonce, sig, self.now)[0])
        ks2 = self._keys([pubrow(_PUB, self.now - 10, self.now + 100)])
        self.assertTrue(ks2.redeem(kid, nonce, sig, self.now)[0],
                        "same-epoch restart should re-accept (bounded)")
        # after rotation (key gone from keyset) -> refused, forever
        other_pub, _ = blindsig.generate_keypair(1024)
        ks3 = self._keys([pubrow(other_pub, self.now, self.now + 100)])
        self.assertFalse(ks3.redeem(kid, nonce, sig, self.now)[0],
                         "a rotated-out epoch must never verify again")

    def test_concurrent_redeem_spends_once(self):
        # verify+spend is atomic: N threads racing one token → exactly one wins.
        ks = self._keys([pubrow(_PUB, self.now - 10, self.now + 1000)])
        kid, nonce, sig = make_token(_PRIV, _PUB)
        wins = []
        barrier = threading.Barrier(12)

        def run():
            barrier.wait()
            if ks.redeem(kid, nonce, sig, self.now)[0]:
                wins.append(1)

        threads = [threading.Thread(target=run) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sum(wins), 1)


class RotationToolTests(unittest.TestCase):
    def test_current_signing_key_picks_the_open_one(self):
        now = 1_000_000
        old_pub, old_priv = blindsig.generate_keypair(1024)
        new_pub, new_priv = blindsig.generate_keypair(1024)
        keyset = [
            {"key_id": blindsig.key_id(old_pub), "n": str(old_priv["n"]),
             "e": str(old_priv["e"]), "d": str(old_priv["d"]),
             "not_before": now - 1000, "not_after": now + 10},   # retiring
            {"key_id": blindsig.key_id(new_pub), "n": str(new_priv["n"]),
             "e": str(new_priv["e"]), "d": str(new_priv["d"]),
             "not_before": now, "not_after": now + 1000},          # current
        ]
        chosen = blindsig.current_signing_key(keyset, now)
        self.assertEqual(chosen["key_id"], blindsig.key_id(new_pub))

    def test_public_view_strips_the_private_exponent(self):
        _pub, priv = blindsig.generate_keypair(1024)
        keyset = [{"n": str(priv["n"]), "e": str(priv["e"]), "d": str(priv["d"]),
                   "not_before": 1, "not_after": 2}]
        view = blindsig.public_view(keyset)
        self.assertNotIn("d", view[0])
        self.assertIn("key_id", view[0])

    def test_no_open_key_refuses_to_sign(self):
        now = 1_000_000
        _pub, priv = blindsig.generate_keypair(1024)
        keyset = [{"key_id": "x", "n": str(priv["n"]), "e": str(priv["e"]),
                   "d": str(priv["d"]), "not_before": now + 10, "not_after": now + 20}]
        with self.assertRaises(ValueError):
            blindsig.current_signing_key(keyset, now)


if __name__ == "__main__":
    unittest.main()
