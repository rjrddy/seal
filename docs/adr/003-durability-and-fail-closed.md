# Acknowledge OS fsync and reject incomplete tails

Accepted. Default append syncs each entry; periodic or explicit checkpoints sync a separate file. A batched library mode has separate acknowledgement/durability scope and separately labelled throughput. Cross-file atomicity and hardware power-loss guarantees are absent. An incomplete record/checkpoint rejects further operations; no automatic truncation discards forensic evidence. Recovery tooling is Next.
