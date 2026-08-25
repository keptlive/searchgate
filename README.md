# searchgate

**A private metasearch gate that proves you belong without learning who you
are.** It answers a single question at the door — *does this person hold a
Handshake name?* — using blind signatures, so the gate can admit you while
being unable to tell which name you hold or to link two of your searches
together. It keeps no request log by construction.

Run by HNS.ONE at `hsearch.hns.one`. The code is here so anyone can run one.

## How it works

The gate is a [Chaum blind-signature](https://en.wikipedia.org/wiki/Blind_signature)
(RSA-FDH) membership check, in the shape of a
[Privacy Pass](https://privacypass.github.io/) issue/redeem flow:

```
1. ISSUE   You prove control of a Handshake name (once), and the issuer
           blind-signs a token. Because the token is blinded, the issuer
           never sees the token it signed — only that a valid holder asked.

2. REDEEM  Later, you unblind the token and present it to the gate with a
           search. The gate verifies the signature against the current
           public key and admits the search. It cannot connect the token
           to the identity that was issued it, or to your other tokens.
```

Two properties fall out of the math, not out of a promise to delete logs:

- **The gate does not know which name you hold.** Membership is proven; identity is not revealed.
- **Two searches are unlinkable.** Nothing on a redeemed token ties it to another.

Spent tokens are tracked in a **RAM-only** set, partitioned by short-lived key
epochs: rotating the issuer key is what garbage-collects the spent set, so
there is never a growing on-disk record of who searched. The private keyset
never lives in this repository — it is generated and held outside it.

## Layout

| File | What it is |
|---|---|
| `blindsig.py` | The RSA-FDH blind-signature primitives and key/epoch model. |
| `gate.py` | The redeem endpoint: verify a token, admit a search, keep no record. |
| `keyrotate.py` | Rotate issuer keys and publish the public keyset. Deploy target is env-configurable (`HNS_EDGE_SSH_SEARCH`, `HNS_EDGE_KEY_SEARCH`). |
| `issuer-pub.json`, `search-keyset-public.json` | The **public** keys clients verify against. No private material. |
| `test_gate.py` | Tests for the issue/redeem/epoch logic. |

## Design notes

- The gate is a privacy stance, not a search-quality one: it proves
  name-membership without learning the name, and forwards the query to a
  metasearch backend. The upstream engine still sees the query text (that is
  what a search is), so the gate's job is to make sure it can never be tied
  back to *you*.
- Keep the issuer and the gate honest about what they can and cannot see; the
  tests pin the epoch-scoped spent-set behavior so a refactor cannot silently
  turn it into a persistent log.

## License

MIT — see [`LICENSE`](./LICENSE).
