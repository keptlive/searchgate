#!/usr/bin/env python3
"""Issuer-key epochs for the search gate — the thing that makes a RAM-only
spent-set safe (NO-RECORDS.md).

    python3 keyrotate.py init                 # first keyset, one live key
    python3 keyrotate.py rotate               # mint a new epoch, retire the old
    python3 keyrotate.py rotate --push        # ... and ship the public view to the gate
    python3 keyrotate.py show                 # windows + ids, no secrets

WHY THIS EXISTS. The gate keeps its double-spend set in RAM, so a restart
forgets which tokens were spent. That is only safe because every token is
bound to an issuer KEY EPOCH: a token verifies only while its key's window is
open, and when the key rotates out the gate drops that key's whole
spent-bucket. So the worst a restart can do is let tokens minted in the
CURRENT epoch be re-spent — bounded by the epoch length, never the whole
history. Rotation is garbage collection.

THE PRIVATE KEYSET stays on the issuer (tenant plane): it holds d and can
sign. THE PUBLIC VIEW (id + n,e + window, no d) is what the gate gets — it can
verify and see expiry, never sign. This tool writes the private set locally
and, with --push, scp's only the public view to the gate.

TUNING (RFC 9576 §6.2 tension): a shorter epoch means a smaller RAM spent-set
and a tighter restart-window, but a SMALLER anonymity cohort — every token
under one key_id is one anonymity set. EPOCH/OVERLAP below is the knob; a day
with an hour of overlap keeps cohorts large while bounding the RAM set.
"""
import argparse
import json
import os
import subprocess
import sys
import time

import blindsig

HERE = os.path.dirname(os.path.abspath(__file__))
PRIV = os.environ.get("SEARCH_KEYSET",
                      os.path.expanduser("~/.hns-creds/search-keyset.json"))
PUB_OUT = os.path.join(HERE, "search-keyset-public.json")

EPOCH = int(os.environ.get("SEARCH_EPOCH_SECONDS", 24 * 3600))
# Overlap: how long a just-retired key still verifies, so tokens a browser
# fetched moments before rotation are not rejected mid-flight.
OVERLAP = int(os.environ.get("SEARCH_OVERLAP_SECONDS", 3600))

EDGE_SSH = os.environ.get("HNS_EDGE_SSH_SEARCH", "root@YOUR_SEARCH_HOST")
EDGE_KEY = os.path.expanduser(os.environ.get("HNS_EDGE_KEY_SEARCH",
                                             "~/.ssh/your_search_host_key"))
EDGE_PUB = "/opt/searchgate/search-keyset-public.json"


def load():
    try:
        with open(PRIV) as fh:
            return json.load(fh)
    except FileNotFoundError:
        return []


def save(keyset):
    os.makedirs(os.path.dirname(PRIV), exist_ok=True)
    tmp = PRIV + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(keyset, fh, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, PRIV)
    # The gate only ever sees the public view — never d.
    with open(PUB_OUT, "w") as fh:
        json.dump(blindsig.public_view(keyset), fh, indent=1)


def mint(now):
    pub, priv = blindsig.generate_keypair(2048)
    kid = blindsig.key_id(pub)
    return {"key_id": kid, "n": str(priv["n"]), "e": str(priv["e"]),
            "d": str(priv["d"]), "not_before": now, "not_after": now + EPOCH}


def prune(keyset, now):
    """Drop keys whose window has fully closed (past not_after)."""
    return [k for k in keyset if now < int(k["not_after"])]


def push():
    subprocess.run(
        ["scp", "-q", "-i", EDGE_KEY, PUB_OUT, f"{EDGE_SSH}:{EDGE_PUB}"],
        check=True, timeout=60)
    print(f"pushed public keyset -> {EDGE_SSH}:{EDGE_PUB} "
          f"(gate hot-reloads on mtime)")


def cmd_init(a):
    now = int(time.time())
    if load():
        print("keyset already exists; use rotate")
        return 1
    save([mint(now)])
    print(f"issuer keyset created ({PRIV}), public view -> {PUB_OUT}")
    if a.push:
        push()
    return 0


def cmd_rotate(a):
    now = int(time.time())
    keyset = load()
    if not keyset:
        print("no keyset yet; run init")
        return 1
    # Close the current key's window now (+overlap so in-flight tokens live),
    # mint the new current key, drop anything already fully expired.
    for k in keyset:
        na = int(k["not_after"])
        if na > now + OVERLAP:
            k["not_after"] = now + OVERLAP
    keyset.append(mint(now))
    keyset = prune(keyset, now)
    save(keyset)
    live = [k["key_id"] for k in keyset if int(k["not_before"]) <= now < int(k["not_after"])]
    print(f"rotated. live key ids: {live} (overlap {OVERLAP}s on the retiring key)")
    if a.push:
        push()
    return 0


def cmd_show(a):
    now = int(time.time())
    keyset = load()
    if not keyset:
        print("no keyset")
        return 0
    print(f"{'key_id':18} {'state':9} {'opens':20} {'closes':20}")
    for k in sorted(keyset, key=lambda x: int(x["not_before"])):
        nb, na = int(k["not_before"]), int(k["not_after"])
        state = ("current" if nb <= now < na else
                 "future" if now < nb else "retiring" if now < na else "expired")
        fmt = lambda t: time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t))
        print(f"{k['key_id']:18} {state:9} {fmt(nb):20} {fmt(na):20}")
    return 0


def cmd_run(a):
    """Daemon: rotate whenever the newest key nears expiry. Robust to restarts
    (it checks remaining life, never sleeps a fixed 24h) — a missed cycle can't
    silently expire the live key and 401 every search. Runs from up.sh."""
    while True:
        now = int(time.time())
        keyset = load()
        if not keyset:
            save([mint(now)])
            push()
            print("run: created initial keyset")
        else:
            newest_end = max(int(k["not_after"]) for k in keyset)
            # Rotate once the freshest key has less than 2x overlap of life
            # left, so a new epoch is always open well before the old closes.
            if newest_end - now < 2 * OVERLAP:
                cmd_rotate(argparse.Namespace(push=True))
            else:
                # Still push (idempotent) so a gate that lost its file recovers.
                try:
                    push()
                except Exception as exc:
                    print(f"run: push skipped ({exc})")
        time.sleep(a.interval)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("init", "rotate"):
        p = sub.add_parser(name)
        p.add_argument("--push", action="store_true",
                       help="scp the public keyset to the gate")
    r = sub.add_parser("run")
    r.add_argument("--interval", type=int, default=3600,
                   help="seconds between expiry checks (default 1h)")
    sub.add_parser("show")
    a = ap.parse_args()
    return {"init": cmd_init, "rotate": cmd_rotate,
            "run": cmd_run, "show": cmd_show}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
