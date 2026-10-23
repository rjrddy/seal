# Design: commitments need an independently retained head

The hard part is not hashing a file. It is defining which history a verifier trusts, preserving a stable serialization, and proving that a later commitment includes the same earlier prefix. A signature authenticates a statement by a key; it does not tell a client that an older valid statement was replayed. Seal requires the caller to pin a public key, log identity and trusted checkpoint independently.

## Format and domain separation

An entry is canonical compact JSON with fixed fields: sequence, previous hash, hex payload and entry hash. Its hash covers a versioned entry-domain prefix, big-endian unsigned sequence, previous digest, explicit payload length and payload bytes. Hex must be lowercase, fields must match the schema, and records use exactly one LF terminator. The file reader reserializes each parsed record and compares its bytes, so edits to whitespace, field order or escape representation are rejected too. A torn tail is an error, never silently discarded.

The Merkle leaf hashes a leaf-domain byte and canonical entry bytes. Internal nodes hash a different domain byte and their ordered children. Empty-tree and non-power-of-two split rules follow RFC 9162. The checkpoint signature covers a separate versioned checkpoint domain, log identity, tree size, root and chain head using fixed binary field widths. Ed25519 signing/verifying uses ed25519-dalek; SHA-256 uses sha2. This is an original format, not the Certificate Transparency network protocol.

The public library exposes immutable in-memory entry verification, tree roots and proof generation/verification. It does not implement elliptic-curve primitives or claim formal cryptographic review. Strict signature checks and weak-key rejection are explicit. JSON schemas deny unknown fields; hex, size and proof-path limits reject malformed inputs.

## Inclusion and consistency

Inclusion recomputes an entry's own hash, its Merkle leaf, the ordered path and the signed root. It proves membership in that committed tree; it does not audit every predecessor link or establish that the event actually occurred in the world.

Consistency compares independently trusted old and new signed heads and an RFC-shaped Merkle consistency path. It rejects shrinking trees, equal-size forks, missing/extra nodes and mismatched roots. Empty-prefix consistency is vacuous but the empty root/head must be valid. Consistency proves unchanged committed Merkle leaves, not correct semantics of every newly appended hash-chain link or correctness of arbitrary signed metadata. Full-log audit recomputes every entry link and compares root, size and chain head to the pinned head.

Proof generation currently rebuilds tree/subtree hashes from entries rather than maintaining an indexed frontier. Paths are logarithmic in hash count, but generation and checkpoint reconstruction can scan the log. Measurements distinguish raw binary sibling bytes from full compact JSON bundles and exclude parsing/proof generation from timed verification. Browser verification uses safe JavaScript integer sizes; the native format supports unsigned sizes.

## Trust and rollback

Clients supply their expected key and log identity separately from proof bundles. Verifying a key carried only inside an untrusted bundle would be circular, so bundles do not supply an authoritative key. The CLI's verify-log command also requires a checkpoint supplied by the caller. Full audit against a newer retained head detects tail removal. A valid old prefix against its own valid old head passes: this is measured as a negative control, not hidden as an implementation exception.

A compromised signing key can sign conflicting histories. Comparing them with an existing trusted head exposes a fork, but an isolated new client can be shown a fresh valid fork. There is no gossip, witness, timestamp authority, key rotation protocol or externally reviewed custody system. Intermediate checkpoint-file records are not themselves a separate tamper-evident log; retaining client heads is essential. Removing an old checkpoint artifact can break proof retrieval without changing the committed entry log.

The viewer is deliberately synthetic and uses a deterministic public demo key. It says so prominently. Its initial trust fields come from the local demo server, so they are not independent trust establishment. Once populated, refresh/append does not silently replace them. Real users must obtain anchors independently and trust the verifier implementation/distribution. A malicious host could replace delivered JavaScript; the independent CLI remains important. No hosted production signing service is implied.

## Storage and crash boundary

A file lock serializes cooperating writers across processes. Each append validates the current canonical chain and retained checkpoints before writing. Acknowledged default appends have completed OS fsync, and automatic checkpoints occur at the configured fixed interval. Explicit checkpoint signs the current tail; the viewer explicitly checkpoints each demonstration append. A library batch mode amortizes fsync and has different intermediate durability semantics, so its throughput is reported separately.

Entries and checkpoints live in separate append-only files. There is no atomic multi-file transaction. If a process dies between an entry append and a checkpoint, the file may contain a complete unsigned tail or a partial record. A complete valid tail can subsequently be sealed; incomplete records or checkpoint tails reject startup/append without truncation. Operators must recover from an independently trusted backup/snapshot and preserve rejected bytes for investigation. No automatic recovery or power-failure certification is claimed. OS fsync completion is not a measured guarantee about every storage controller.

The writer lock fences cooperating processes; it does not prevent an attacker with file permissions from editing data. Concurrent uncooperative file mutation is outside the snapshot guarantee. Audit a stable copy or take the writer lock; the service holds it while collecting its proof/state snapshots. The default loader rebuilds records/checkpoints and can be expensive as histories grow. Files, records, payloads, entry counts and paths are bounded for this small local scope. Payloads are not encrypted or automatically classified/redacted.

## Viewer and independent primitives

The buildless viewer uses original CSS/SVG and browser WebCrypto SHA-256/Ed25519. It reconstructs the same entry/signature encodings and Merkle paths, then cross-checks its verdict against the Rust service. A positive verdict requires both. This is an implementation cross-check, not an external witness or a proof that all implementations are independent. Native larger fixtures and deliberately altered bundles are exercised by actual browser automation.

An initial browser run exposed an asynchronous load/editor race: a pending load could replace edited proof data. The retained failure led to locking controls during requests, clearing verdict state on edits/new checks and rejecting stale asynchronous results. A pinned key survives append/refresh. Downloaded proofs are checked as real JSON rather than decorative receipts.

The Rust HTTP service defaults to loopback and rejects unexpected Host/Origin values. Non-loopback binding requires an environment token; the UI retains it only in memory. Bodies are bounded, API parse errors are generic, and logs contain only event/status metadata. This is a local development viewer, not a hardened multitenant HTTP gateway: production reverse-proxy timeouts, authentication/authorization, limits and key custody would require separate work. The prepared hosting image still serves public-key synthetic data, and free-plan files are ephemeral.

## Evidence and limitations

The benchmark mutates entries at every position in a finite synthetic corpus: payload-byte change, deletion and adjacent swap. A separate small physical-file fixture tests every bit at every byte position, including canonical JSON punctuation. Each case is checked against a retained complete signed head. The observed detection rate applies to those cases, not an empirical quantification of cryptographic collision resistance or all attacks.

A separate [adversarial control](results/rehashed-fork-control.txt) rewrites payloads, recomputes a valid chain and even creates a validly signed fork: the retained commitment still rejects it.

The test suite covers every small tree size/prefix, an independent stack-based root constructor, wrong keys/identities, invalid signatures, extra/corrupt proof nodes, actual file edits/torn tails, OS writer fencing, real HTTP requests and actual SIGKILL/restart. CI executes a real nonroot Docker image, acknowledges an append, kills/restarts it, verifies the same checkpoint, then intentionally tears a tail and requires startup rejection. Raw timings, errors, browser artifacts, tool versions and machine details are retained. No benchmark is reported as hosted performance.

References: [RFC 9162 cryptographic components](https://www.rfc-editor.org/rfc/rfc9162.html), [dalek strict verification API](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.VerifyingKey.html), [Certificate Transparency trust roles](https://certificate.transparency.dev/howctworks/). They inform the algorithms and distinctions; Seal is not CT-compliant infrastructure.
