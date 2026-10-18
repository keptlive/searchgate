#!/usr/bin/env python3
"""The search gate: membership in, identity never — and NO records kept.

Sits between a TLS proxy and a SearXNG instance on loopback. Every /search
request must carry one blind-signature token
(Authorization: Bearer <key_id>.<nonce>.<sig>) minted by a separate issuer
for holders of a Handshake name. The gate verifies the issuer signature and
burns the token so it learns exactly one bit about the caller: "holds an
identity". Which identity is unknowable here BY CONSTRUCTION (blindsig.py).

KEEPS NO RECORDS. The double-spend set lives in RAM ONLY, keyed on the token's
random nonce (never on identity), partitioned by issuer KEY EPOCH. A token
verifies only while its key's window is open; when the issuer rotates a key out
of the public keyset, the gate DROPS that key's whole spent-bucket — rotation
is garbage collection. So a restart/seizure forgets everything, and can never
enable double-spend beyond the current epoch. There is no disk state to hand
over.

WHAT THIS PROCESS DELIBERATELY DOES NOT DO:
  - log queries (errors only, and error lines carry no query text)
  - write ANY request state to disk (the spent-set is RAM; the only file it
    reads is the public keyset the issuer publishes)
  - forward any client-identifying header upstream
  - serve anything without a valid, unspent, in-window token (except
    /healthz and /keys, which are public and carry nothing private)

    SEARCHGATE_KEYSET=/path/to/search-keyset-public.json \
    python3 gate.py --port 8880 --upstream http://127.0.0.1:8888
"""
import argparse
import json
import os
import sys
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import blindsig

KEYSET_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "search-keyset-public.json")
UPSTREAM = "http://127.0.0.1:8888"


class KeySet:
    """The public issuer keyset, hot-reloaded on mtime, plus the RAM spent-set.

    One lock guards both: the valid-keys map and the per-epoch nonce buckets
    move together (when a key leaves the keyset, its bucket must go with it, or
    the RAM set would grow forever — the very record we are removing)."""

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._mtime = 0
        self._keys = {}                 # key_id -> {n, e, not_before, not_after}
        self._spent = {}                # key_id -> set(nonce_hex)
        self.reload(force=True)

    def reload(self, force=False):
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            return
        if not force and mtime == self._mtime:
            return
        try:
            with open(self.path) as fh:
                rows = json.load(fh)
            keys = {r["key_id"]: {"n": int(r["n"]), "e": int(r["e"]),
                                  "not_before": int(r["not_before"]),
                                  "not_after": int(r["not_after"])}
                    for r in rows}
        except (OSError, ValueError, KeyError) as exc:
            print(f"keyset unreadable ({exc}); keeping previous", file=sys.stderr)
            return
        with self._lock:
            self._keys = keys
            self._mtime = mtime
            # Drop spent-buckets for keys no longer published: rotation is GC.
            for kid in list(self._spent):
                if kid not in keys:
                    del self._spent[kid]

    def redeem(self, kid, nonce, sig, now):
        """Verify a token against its epoch key and burn its nonce.
        Returns (ok, why). All under one lock so verify+spend is atomic."""
        with self._lock:
            key = self._keys.get(kid)
            if key is None:
                return False, "unknown or expired key"
            if not (key["not_before"] <= now < key["not_after"]):
                return False, "token key is not in its validity window"
            if not blindsig.verify(nonce, sig, key["n"], key["e"]):
                return False, "invalid token"
            bucket = self._spent.setdefault(kid, set())
            h = nonce.hex()
            if h in bucket:
                return False, "token already spent"
            bucket.add(h)
            return True, ""

    def public(self):
        with self._lock:
            return [{"key_id": kid, "n": str(k["n"]), "e": str(k["e"]),
                     "not_before": k["not_before"], "not_after": k["not_after"]}
                    for kid, k in self._keys.items()]


KEYS = None  # KeySet


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "searchgate"

    # Silence the default per-request access log: a search gate that logs
    # paths logs queries. Errors are printed explicitly, without the path.
    def log_message(self, *args):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _deny(self, code, why):
        self._json(code, {"error": why})

    def do_GET(self):  # noqa: N802
        if self.path == "/healthz":
            return self._json(200, {"ok": True})
        if self.path == "/keys":
            # The public keyset — what a browser needs to know which epoch key
            # to expect. No secret; the whole point is that it is public.
            KEYS.reload()
            return self._json(200, {"keys": KEYS.public()})
        if not (self.path.startswith("/search") or self.path.startswith("/autocompleter")):
            return self._deny(404, "not here")

        KEYS.reload()
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return self._deny(401, "a search token is required")
        try:
            kid, nonce, sig = blindsig.token_decode(auth[7:].strip())
        except ValueError:
            return self._deny(401, "malformed token")
        ok, why = KEYS.redeem(kid, nonce, sig, int(time.time()))
        if not ok:
            return self._deny(401, why)

        # Proxy upstream with a CLEAN request: the query, and nothing that
        # identifies the caller. SearXNG sees the gate, engines see SearXNG.
        req = urllib.request.Request(UPSTREAM + self.path, headers={
            "Accept": self.headers.get("Accept", "application/json")
        })
        try:
            with urllib.request.urlopen(req, timeout=25) as res:
                payload = res.read()
                self.send_response(res.status)
                self.send_header("Content-Type",
                                 res.headers.get("Content-Type", "application/json"))
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
        except urllib.error.HTTPError as err:
            print(f"upstream {err.code}", file=sys.stderr)
            self._deny(502, "search backend error")
        except Exception as exc:
            print(f"upstream failed: {type(exc).__name__}", file=sys.stderr)
            self._deny(502, "search backend unreachable")


def main():
    global KEYS, UPSTREAM
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8880)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--upstream", default=os.environ.get("SEARCHGATE_UPSTREAM",
                                                         "http://127.0.0.1:8888"))
    ap.add_argument("--keyset", default=os.environ.get("SEARCHGATE_KEYSET", KEYSET_FILE))
    args = ap.parse_args()
    UPSTREAM = args.upstream.rstrip("/")
    KEYS = KeySet(args.keyset)
    if not KEYS.public():
        print(f"WARNING: no valid keys in {args.keyset} — every request will "
              f"401 until the issuer publishes a keyset", file=sys.stderr)
    print(f"searchgate on {args.host}:{args.port} -> {UPSTREAM} "
          f"(spent-set in RAM, epoch-scoped; queries unlogged)")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
