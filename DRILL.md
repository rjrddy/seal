# Hard follow-ups

1. **Why doesn't fsync make this tamper-proof?** It concerns acknowledged persistence, not malicious mutation or proof of immutable storage.
2. **What does the retained newer head add?** An external commitment to the later size/root/head; without it an older valid signed prefix can be replayed.
3. **What if the attacker changes whitespace only?** Canonical file parsing compares serialized record bytes, so representation edits are rejected too. Proof JSON transport itself need not be byte-canonical.
4. **Why separate hash domains?** Entry, leaf, internal node and signing-message contexts must not be confused by concatenation.
5. **Why length-prefix the payload?** The signed/hash preimage has an unambiguous byte structure rather than relying on textual field separators.
6. **Why are empty trees special?** They have a defined empty root and zero chain head; consistency from an empty prefix is vacuous but must not accept malformed empty metadata.
7. **What is an equal-size consistency proof?** An empty path with identical roots and matching chain heads; differing commitments at the same size are a fork.
8. **How do non-power-of-two trees work?** Split at the largest smaller power of two. Tests cover every small size/prefix and an independent root implementation.
9. **Why reject extra proof nodes?** A proof must consume exactly the structure implied by its index/sizes; accepting trailing nodes can hide malformed logic.
10. **Does a valid entry hash prove its predecessor is present?** No. Inclusion proves membership; full chain audit verifies predecessor links.
11. **Can a log commit nonsense events?** Yes. A signature commits bytes, not real-world truth or semantic validity.
12. **Are signatures timestamps?** No. There is no trusted clock, timestamp authority or independently witnessed publication time.
13. **What if the signing key is stolen?** Valid new signatures may be forged. Prior independently retained heads constrain detectable rewrites, while isolated forks require witnesses/gossip and custody controls.
14. **Why check the key separately from the bundle?** Otherwise an attacker can invent both the payload and its self-authorizing signing identity.
15. **Are viewer trust fields independent?** The initial synthetic defaults come from the local demo, so no. They illustrate a caller input and are not silently replaced later.
16. **Why use both browser and Rust verifiers?** It cross-checks format/path/signature implementations using platform/library primitives. It is not a formal proof or an external witness.
17. **What if JavaScript numbers cannot represent a size exactly?** The browser rejects unsafe integer sizes. The native verifier has an unsigned integer format; these boundaries are explicit.
18. **What happens after a torn tail?** The process fails closed and preserves bytes. No automatic truncation or blanket crash-recovery claim exists.
19. **Are per-entry and batched append rates comparable?** Only with their different acknowledgement/durability scopes stated; the raw samples retain separate modes.
20. **Can a Tally audit receipt be exactly-once across systems?** Not just by appending to Seal. A crash between log append and outbox acknowledgement requires stable IDs and reconciliation; the proposed bridge claims no cross-system transaction.
