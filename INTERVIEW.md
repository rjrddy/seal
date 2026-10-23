# Seal interview

## Two-minute pitch

Seal is a Rust append-only log and proof verifier. Each canonical record commits to its sequence, previous digest and payload. Periodic Merkle roots become Ed25519-signed checkpoints. Inclusion proofs bind an entry to a signed root; consistency proofs show that a newer committed tree preserves an older prefix. The primitives come from established libraries; the log format, tree algorithms, storage and viewer are my implementation.

The important design decision is independent trust. A proof cannot authorize its own public key, and a valid old signature cannot reveal rollback without a newer retained head. The benchmark demonstrates both the detected rollback and the old-prefix negative control. Detection results apply to a finite injected corpus, not every imaginable attack or a formal cryptographic review.

Default appends acknowledge OS fsync; checkpoints are a separate file and there is no cross-file atomic transaction. An incomplete record fails closed without deleting bytes. Tests exercise actual file changes, process writer fencing and SIGKILL/restart. The viewer runs browser WebCrypto verification and cross-checks Rust, with caller-pinned fields and explicitly public synthetic keys. Browser automation caught an editor/load race; I retained the failure and fixed stale verdict/input handling. The README is generated from raw measurements, including the slower durability mode and full proof-bundle costs. Hosting and Tally integration remain unactivated.

## Ten-minute walkthrough

Start with the threat model: an attacker edits stored entries or presents a stale head. Show the separate expected public key, log identity and retained signed checkpoint. Explain why initial trust and observation of a newer head cannot be invented by a verifier.

Open `lib.rs`: entry domain separation, explicit payload length, canonical hex/JSON, signature message and strict key checks. Demonstrate the difference between validating an entry's own hash and auditing its link to its predecessor. Full-log verification checks every sequence/link plus the caller's pinned size/root/head.

Walk through `merkle.rs`: unbalanced tree split, leaf/internal hash domains, inclusion path order, consistency prefix reconstruction and strict empty/equal/shrinking cases. Show the exhaustive small-size/prefix tests and independent stack-based root constructor. The algorithms follow the cited RFC's tree shape, but the signature/log wire format is original.

Then `storage.rs`: an exclusive OS writer fence, validate-before-append, canonical JSONL, per-entry fsync, periodic checkpoints and explicit sealing. There is a crash gap between the files. Complete unsigned entries may be sealed later; incomplete tails are preserved and rejected. OS acknowledgement does not prove every storage controller survives power loss.

Use the CLI's random key generation and explicit verify arguments; do not expose a real seed on-screen. Then demonstrate the public-key synthetic viewer: valid inclusion, payload mutation, missing/reordered path node, consistency, wrong expected key, append and downloaded proof. Browser and Rust must agree before a positive verdict; neither creates an independent witness or trustworthy JavaScript distribution automatically.

Finish with raw append/proof/mutation results, the actual rejected dependency lock, compiler/browser failures and fresh-clone/container evidence. Explain exactly what verification timings include, why batched durability is a separate workload, and what an isolated valid fork or older signed prefix cannot reveal.

## Five tradeoffs

- Canonical JSONL is inspectable and rejects byte representation edits, but hex payloads and metadata add storage overhead.
- A hash chain makes full audit simple; a Merkle tree adds compact proofs at the cost of additional algorithms and checkpoint work.
- Per-entry fsync makes acknowledgement scope clear but is slower than batched syncing; neither is a measured hardware power-failure guarantee.
- Recomputing trees/checkpoints keeps the implementation understandable but is unsuitable for large sustained histories without indexing/frontiers.
- Failing closed preserves suspicious/torn bytes but requires explicit operator recovery instead of automatically resuming after every crash.

## Five failure modes

- Payload byte edit, entry deletion or reordering: full audit rejects the canonical chain or pinned checkpoint root/size/head.
- Tail rollback: a newer retained head exposes it; an isolated old valid head does not. The negative control is deliberately retained.
- Wrong key, identity or forged signature: strict verification rejects before accepting the Merkle claim.
- Incomplete entry/checkpoint after crash: reject startup/append without silently truncating. Restore a verified snapshot through operator tooling, which is not yet automated.
- Async viewer data replacement: controls lock during operations, inputs clear old verdicts and snapshots reject stale completions; trust fields are not overwritten on refresh.

## Fifteen likely questions

1. **What does append-only mean here?** The API appends, while verification detects changes to previously committed history against retained anchors. File permissions do not make physical edits impossible.
2. **Why both a chain and a Merkle tree?** The chain checks ordered predecessor links during full audit; the tree enables compact inclusion and prefix consistency proofs.
3. **Why is serialization part of correctness?** Different encodings must not ambiguously identify a signed leaf. Canonical records also make representation-level file edits detectable.
4. **What is signed?** A domain-separated version, identity, size, root and chain head with fixed-width binary fields, not an ambiguous concatenated JSON string.
5. **Can a bundle carry its own trusted key?** It can carry untrusted data, but the verifier requires an independently expected public key and log identity.
6. **Can old signed data hide deletion?** Yes, without a newer retained head. Against a pinned newer head, a shorter log fails size/root/head checks.
7. **Can the signer equivocate?** Yes. A trusted prior head lets clients reject inconsistent extensions, but independent witnesses/gossip are needed to expose isolated forks.
8. **Is this Certificate Transparency?** It uses the referenced Merkle shape/proof algorithms but has an original log/checkpoint format and no CT network protocol claim.
9. **Does consistency check every new chain link?** No. It proves the committed Merkle prefix. Full audit is a separate operation.
10. **What survives process death?** An acknowledged append has completed OS fsync; actual SIGKILL/restart is tested. An interrupted write can leave a rejected incomplete tail.
11. **Why no automatic truncation?** It could discard evidence or hide corruption. Recovery must be explicit and use a trusted snapshot; operator tooling remains Next.
12. **How are proof costs measured?** Timed verification includes signature/entry/path checks but excludes parsing, network and proof construction. Raw sibling bytes and full compact bundle bytes are reported separately.
13. **Why is the viewer key public?** The web app is a synthetic proof demonstration, not production signing custody. CLI keygen separately supports caller-managed random keys.
14. **How was browser correctness checked?** Valid and altered native bundles, both proof types, large fixtures, independent WebCrypto/Rust agreement, downloads, pinned-key preservation, responsive layouts and network recovery.
15. **Why not integrate Tally immediately?** The user requires independent acceptance and explicit approval for kept-project changes. A proposal is present; no outbox or source changes were made.

## What I would do with three more months

Obtain an independent cryptographic review, add witness/gossip protocols and key rotation/custody, implement indexed/frontier proof construction and retention, and build verified backup/operator recovery tools. Add production authentication, proxy/time/resource limits and deployment tests before any durable hosted claim. If approved and both projects pass their checks, implement a small Tally outbox bridge with stable event IDs and explicit at-least-once reconciliation rather than false cross-system atomicity.
