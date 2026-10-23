# searchgate

The redeem side of a token-gated search service. `gate.py` sits in front of a
[SearXNG](https://github.com/searxng/searxng) instance and forwards a search
only if the request carries a valid, unspent token. Tokens are RSA blind
signatures with a full-domain hash, so the gate can check that the issuer
signed a token but cannot match it to the issuance request that produced it.

hns.one runs this gate at `hsearch.hns.one` and issues tokens to holders of
Handshake names. The issuer is not part of this repository. To run the whole
system you need an issuer that follows the contract below.

## Files

| File | Purpose |
|---|---|
| `gate.py` | HTTP gate: verifies and spends tokens, proxies to SearXNG |
| `blindsig.py` | blind-signature primitives, key ids, token encoding |
| `keyrotate.py` | creates and rotates issuer keys, writes the public keyset |
| `search-keyset-public.json` | an example public keyset (expired) |
| `test_gate.py` | tests |

## Run the gate

Requires Python 3.8 or later. The gate has no dependencies; `keyrotate.py` and
the tests need the `cryptography` package.

    SEARCHGATE_KEYSET=/path/to/search-keyset-public.json \
    python3 gate.py --host 127.0.0.1 --port 8880 --upstream http://127.0.0.1:8888

Put a TLS proxy in front of it. `GET /healthz` and `GET /keys` (the public
keyset) are open. `GET /search` and `GET /autocompleter` need
`Authorization: Bearer <token>` and are forwarded upstream with only the path,
query and `Accept` header. Everything else returns 404.

The gate rereads the keyset file when it changes. Spent tokens are held in
memory only, in one set per key, and a key's set is dropped when the key leaves
the keyset. Requests are not logged.

**Restart boundary:** a previously spent token can be redeemed again after a
restart while its signing key is still valid. Separate gate processes also
have independent spent sets. This implementation deliberately avoids durable
request state; it does not provide restart-safe or multi-process single use.
Do not use it for that requirement without designing a shared redemption store.

## Keys

    python3 keyrotate.py init      # create the first key
    python3 keyrotate.py rotate    # add a new key; the old one stays valid for the overlap
    python3 keyrotate.py show      # list keys and their windows
    python3 keyrotate.py run       # rotate before expiry, checking hourly

The private keyset is written to `SEARCH_KEYSET` (default
`~/.config/searchgate/search-keyset.json`, mode 0600) and the public view to
`search-keyset-public.json` beside the script. `--push` (and `run`) copies the
public view with scp to `HNS_EDGE_SSH_SEARCH:HNS_EDGE_PATH_SEARCH`, using the
key in `HNS_EDGE_KEY_SEARCH`. Keys last `SEARCH_EPOCH_SECONDS` (86400) with
`SEARCH_OVERLAP_SECONDS` (3600) of overlap.

The public keyset is a JSON array of `{key_id, n, e, not_before, not_after}`:
`n` and `e` as decimal strings, times in Unix seconds. `key_id` is the first 8
bytes, in hex, of SHA-256 over `n` then `e`, each big-endian at its minimum
byte length.

## Issuer contract

1. The client picks the current key (the newest whose window is open, as
   `blindsig.current_signing_key` does), a random 32-byte nonce and a random
   `r`, and sends `b = FDH(nonce) * r^e mod n`.
2. The issuer authenticates the user by its own rules and returns
   `b^d mod n`, signed with that key.
3. The client unblinds: `s = (b^d) * r^-1 mod n`.

`FDH(nonce)` concatenates `SHA-256(counter || nonce)` for a 4-byte big-endian
counter from 0 until it has at least as many bytes as `n`, keeps that many,
reads them as a big-endian integer and reduces it mod `n`.

The token is `<key_id>.<nonce>.<s>`: 16 hex characters, 64 hex characters, and
`s` in hex. The gate accepts it once, while the key is in the keyset and inside
its window, if `s^e mod n == FDH(nonce)`.

The upstream search engines still see the query text, and all tokens issued
under one key form one anonymity set.

## Test

    python3 -m unittest test_gate

## License

MIT. See [LICENSE](LICENSE).
