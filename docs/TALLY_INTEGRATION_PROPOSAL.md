# Proposal only: Tally audit receipts into Seal

No integration is implemented or approved. The user requires both sides to pass independently, and Tally retains gaps; this document does not bypass that gate. It also requires explicit approval for any kept-project change.

A small future bridge could consume a transactional Tally outbox containing stable synthetic audit-event IDs and canonical payload hashes. It would append an envelope to Seal, obtain a signed checkpoint plus inclusion evidence and record a receipt. It must not reinterpret Seal append as a monetary ledger effect or a cross-system transaction.

Crash after append but before outbox acknowledgement can produce duplicate log envelopes. Preserve a stable source event ID and reconcile receipt identity; do not claim exactly-once delivery. Tally must retain authoritative financial semantics, and Seal only commits audit evidence. Do not send private financial records; use hashes and synthetic test data for development, with a reviewed disclosure policy before any real data.

A separately reviewable change would add only the outbox/export adapter, explicit configuration, duplicate/restart/failure tests and receipt viewing. It would not replace Tally's engine, rewrite its UI or activate live hosting. Scope, identity/key custody, checkpoint retention and recovery would need approval before implementation.
