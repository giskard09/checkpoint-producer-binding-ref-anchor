# checkpoint-producer-binding-ref-anchor

A worked example implementing, in real running code, the checkpoint /
key-binding pattern proposed by **osr21** in
[`coinbase/agentkit#1141`](https://github.com/coinbase/agentkit/pull/1141)
(2026-10-30): a hash-chained event log, a versioned/domain-separated
checkpoint preimage carrying `signer_type`/`signer_id`
([`signing-trust-ref.md`](https://github.com/giskard09/argentum-core/blob/main/docs/spec/signing-trust-ref.md),
first commit 2026-06-21), a detached signature kept outside the hashed
preimage, a `signer_record` declaring `key_source`
([`verifier-key-source-ref-v1.md`](https://github.com/giskard09/argentum-core/blob/main/docs/spec/verifier-key-source-ref-v1.md),
first commit 2026-06-28), and an on-chain anchor with the anchor
transaction's sender tracked as a role (`anchor_submitter`) distinct from
the checkpoint's `signer_id`.

> **Provenance, up front (read `PROVENANCE.md` for the full statement).**
> This is our implementation of osr21's design. Most of the identity/key
> vocabulary already existed in our own specs 3-4 months earlier —
> this looks like independent convergence, not adoption of our work; we
> have no evidence osr21 knew of these specs. The event log is 100%
> synthetic. `key_source = embedded` is recomputable, not anchored —
> `verify.py` reports that distinction explicitly.

## The pattern

```
event_1 → event_2 → ... → event_12          (seq + prev_event_hash chain)
                              │
                              ▼  log_root = event_12.event_hash
                    ┌────────────────────────────┐
                    │ checkpoint preimage          │
                    │  domain, log_scope,          │  JCS + SHA-256
                    │  first/last_seq, count,      │ ───────────────▶ checkpoint_hash
                    │  log_root, prev_ckpt_root,   │
                    │  signer_type, signer_id      │  (signing-trust-ref.md vocabulary)
                    └────────────────────────────┘
                              │
              ┌───────────────┴────────────────┐
              ▼                                 ▼
   detached Ed25519 signature          AnchorRegistry.anchor(checkpoint_hash)
   (kept OUTSIDE the preimage,          Anchored(ref, anchor_submitter, time)
    avoids circularity)                 anchor_submitter tracked separately
                                         from signer_id
              │
              ▼
   signer_record {signer_id, key_id, key_source,
     public_key_hash, signature_input_hash,
     verification_result, key_resolution_time, ...}
   per verifier-key-source-ref-v1.md
   (key_source = embedded -> recomputable, not anchored)
```

## What's here

| Path | What it is |
|---|---|
| `scripts/generate_log.py` | Builds the synthetic 12-event hash-chained log. |
| `scripts/build_checkpoint.py` | Generates the Ed25519 sample key, builds the checkpoint preimage (`signing-trust-ref.md` vocabulary), computes `checkpoint_hash`, produces the detached signature and the `signer_record` (`verifier-key-source-ref-v1.md` shape). |
| `scripts/anchor.sh` | Equivalent `cast` command to anchor `checkpoint_hash`. |
| `verifier/verify.py` | Independent, from-scratch verifier: recomputes the log chain, recomputes `checkpoint_hash`, verifies the signature, checks `signer_record` against `verifier-key-source-ref-v1.md`'s invariants, and (once anchored) re-fetches the `Anchored` event directly from Base mainnet RPC and reports `anchor_submitter` as a role separate from `signer_id`. Also carries `recheck_inclusion()` and `recheck_inclusion_multi_rpc()` — see "Trust boundaries of the on-chain check" below. |
| `artifacts/` | `log.json`, `checkpoint.json`, `checkpoint_hash.json`, `signature.json`, `signer_record.json`, and (once anchored) `anchor.json`. |
| `scripts/generate_negative_fixtures.py` / `fixtures/negative/` / `verifier/verify_negative.py` | Seven deliberately broken artifact sets + a from-scratch verifier that asserts each is rejected with its own reason code. See below. |
| `verifier/verify_recheck.py` / `verifier/verify_recheck_multi.py` | Test the two freshness/trust-boundary modes described below against the real anchor tx. |
| `PROVENANCE.md` | Full honesty statement, including the convergence claim with exact commit hashes/dates — read it. |

## Trust boundaries of the on-chain check

`verify_anchor()`'s on-chain check — and `recheck_inclusion()`, which
re-verifies it later — are **trusted-RPC verification**: they prove what
one configured RPC endpoint reports about `chain_id` and the block hash
at a given height, not independently that this endpoint's view is
canonical. osr21 named this explicitly (`coinbase/agentkit#1141`, round
13, 2026-11-05): *"matching chain_id and a block hash from one endpoint
proves what that endpoint reports, not independently that the view is
canonical."*

`recheck_inclusion_multi_rpc()` corroborates the same observation using
**explicitly configured operator IDs**, not URL counts. Its policy lives in
`verifier/rpc_quorum.py` (standard library only) and remains available from
`verify.py`. Configure `(safe_alias, operator_id, query_fn)` triples:

```python
endpoints = [
    ("base-primary", "base", query_base),
    ("provider-a-primary", "provider-a", query_provider_a),
    ("provider-a-backup", "provider-a", query_provider_a_backup),
]
result = recheck_inclusion_multi_rpc(
    block_number, recorded_block_hash, recorded_chain_id,
    endpoints, min_endpoints=2,
)
```

`min_endpoints` retains its existing name but counts **distinct qualifying
operators**. IDs are trimmed, casefolded ASCII slugs containing letters,
digits, `.`, `_`, or `-`. `Provider-A` and ` provider-a ` are one operator.
Missing/blank/invalid IDs and the reserved ID `unknown` (after trimming and
casefolding) contribute **zero**, not one shared "unknown" vote. A longer ID
such as `unknown-provider` is not reserved. Legacy `(alias, query_fn)` pairs
remain callable but have no operator
identity; two such entries plus one identified operator do not make a
two-operator quorum. Migrate those callers to explicit triples.

Unreachable, wrong-chain and malformed responses are excluded. All
qualifying chain-view observations must agree **before operator
deduplication**, including unknown-operator observations: a conflicting
response from one operator's second URL must not disappear through a
"first URL wins" shortcut. Disagreement returns `unknown`; this is not
majority voting. Matching client versions/block hashes neither establish
identity nor merge different configured operator IDs.

The result separates `endpoints_queried`, `endpoints_qualifying`, and
`operators_qualifying`, exposes `operator_ids_qualifying`, and sets
`quorum_operator_ids` only when a verdict is reached. `reports` lists safe
aliases, normalized IDs and exclusion codes such as `query_error`,
`wrong_chain_id`, `invalid_block_hash`, and `operator_identity_unknown`.
When `operator_id_format="v1"` is passed, the old
``operator_identity_unknown`` is split into ``operator_id_missing`` (no
identity supplied: legacy 2‑tuple, ``None``, empty/whitespace-only after
trim) and ``operator_id_invalid`` (identity supplied but rejected:
non‑string type, non‑ASCII, fails the 1‑64‑character slug rule, or
reserved word ``unknown``).  Credit for the format and the
missing/invalid distinction:
[osr21](https://github.com/osr21).
Use non-secret aliases; URL-like labels are replaced with positional
aliases, and raw exception messages are not echoed because RPC errors
can contain API credentials.

**Trust boundary:** `assurance="configured-operator-corroboration"` means
agreement under the supplied identity mapping, not authenticated provider
identities, proven operational independence, chain finality, collusion
resistance, or light-client/proof verification. Giving one backend two
different IDs remains a configuration error this verifier cannot detect.

Deterministic regression coverage (no network, signature dependencies or
onchain transactions):

```bash
python3 -m unittest discover -s verifier -p 'test_rpc_quorum.py' -v
```

`verifier/verify_recheck_multi.py` retains the separately labeled live-RPC
example and synthetic scenarios, updated to explicit operator IDs.

## Negative fixtures

osr21 reviewed this worked example and asked (`coinbase/agentkit#1141`,
2026-11-01) for packaged negative cases, fail-closed with a reason code
each — not a single pass/fail boolean, same style as argentum-core's own
negative conformance vectors (`action-ref-v1-domain-negative/`,
`near-miss-v1/`). `verifier/verify_negative.py` recomputes each one from
scratch (never trusts a cached field — `key_substitution`'s own
`signer_record.verification_result` says `"pass"`; the point is that a real
verifier must not read that):

| Case | Reason code | What's broken |
|---|---|---|
| `key_substitution` | `SIGNATURE_KEY_MISMATCH` | `signer_id`/`signer_record` both claim key A; the signature was produced by a different key B. |
| `sequence_gap` | `LOG_SEQUENCE_GAP` | Hash chain is fully valid (every `prev_event_hash` correctly links); the `seq` labels have a hole (`1,2,3,5,6`). |
| `sequence_reorder` | `LOG_SEQUENCE_REORDERED` | Hash chain is fully valid; the `seq` labels are non-monotonic (`1,2,4,3,5,6`). |
| `wrong_log_root` | `CHECKPOINT_LOG_ROOT_MISMATCH` | Checkpoint's `log_root` points at an earlier event's hash, not the log's real tip. |
| `anchor_tx_reverted` | `ANCHOR_TX_REVERTED` | A synthetic captured receipt (`status: "0x0"`) — labeled as synthetic in the fixture itself; nothing was deliberately reverted on-chain to produce this. |
| `anchor_wrong_event` | `ANCHOR_EVENT_MISMATCH` | Reuses this repo's real, already-anchored tx (`artifacts/anchor.json`) but checks it against a `checkpoint_hash` it did *not* anchor — the chain data is real, the fixture's expectation is deliberately wrong. |
| `coordinated_key_signer_substitution` | `ANCHOR_CHECKPOINT_MISMATCH` | A fresh key B, `signer_id = key B`, signed by key B — every local field is internally consistent. See below. |

`sequence_gap` and `sequence_reorder` are built so the hash chain itself
stays valid (every link positionally correct) — isolating "the claimed
numbering has a hole / goes backwards" from "the chain was tampered with",
which is a different failure (`LOG_CHAIN_BREAK` / `LOG_EVENT_HASH_MISMATCH`,
also implemented, just not one of the seven named cases here).

### `coordinated_key_signer_substitution` — osr21's follow-up (7th case, 6th round)

osr21's exact ask, quoted: *"replace the embedded public key and re-sign
the checkpoint with that key, while keeping the claimed signer_id and
other fields unchanged."* Not a signature-only swap (`key_substitution`
already covers that) — here key, `signer_id`, and signature are all
replaced *together*, consistently. Running the local checks alone
(`key_source_declared`, `public_key_hash_matches`, `signer_identity_bound`,
`signature_input_bound`, the recomputed Ed25519 verification) gives **all
pass** — `verifier/verify_negative.py` prints this explicitly before
checking anything on-chain. Nothing about the record alone distinguishes
it from a legitimate signer.

It only breaks against the real, already-anchored tx
(`0x1dbff7b7b183b9cf3496646fa4aac52b3267bcfd3982f40847e268ec05f8fbb4`,
reused, not re-anchored): that tx's `Anchored` log carries a different
`checkpoint_hash` — this one was never anchored by it. This is exactly the
three scenarios osr21 named, demonstrated in one fixture:

1. **`key_source = "embedded"`** — self-consistent by construction, proves
   nothing about identity on its own. This fixture's local-checks pass is
   the demonstration.
2. **Fingerprint committed in an anchored preimage** — breaks the match
   the moment the claim is checked against what was actually anchored.
   This fixture's `ANCHOR_CHECKPOINT_MISMATCH` is the demonstration.
3. **`key_source = "pinned_registry"`** — not implemented in this worked
   example (no independent registry exists here to pin against); named as
   a future case, not built. A real deployment wanting this third
   guarantee would need that registry as a fourth party, which this
   worked example doesn't have.

```bash
python3 scripts/generate_negative_fixtures.py
python3 verifier/verify_negative.py
```

**Already resolved by design, not new work for this request:** osr21 also
raised separating "signature verifies" from "key is bound to a known
identity." `verify.py` already keeps these apart —
`verification_result_recomputed` (line 94) is the raw Ed25519 check,
independent of any key-authority claim, and lines 161–168 print this
explicitly:

```
GUARANTEE TYPE (verifier-key-source-ref-v1.md vocabulary):
  key_source = 'embedded'
  -> Recomputable: yes -- public key ships inside this record, no external fetch.
  -> Anchored: NO -- this key was chosen by whoever produced this checkpoint.
```

## Reproduce

```bash
python3 scripts/generate_log.py artifacts/log.json
python3 scripts/build_checkpoint.py artifacts/log.json artifacts
python3 verifier/verify.py artifacts                      # local checks only
bash scripts/anchor.sh                                     # anchor on Base mainnet
python3 verifier/verify.py artifacts <anchor_tx_hash>       # + on-chain check
```

## This instance

- `signer_type` / `signer_id`: see `artifacts/checkpoint.json`
- `checkpoint_hash`: see `artifacts/checkpoint_hash.json`
- Anchor status: see `artifacts/anchor.json` (once anchored)

## License

MIT — see `LICENSE`.
