use ed25519_dalek::SigningKey;
use seal_log::{
    Checkpoint, Consistency, Entry, Inclusion, Result, hash_from, merkle,
    storage::{Store, read_entries},
    verify_log,
};
use serde_json::json;
use std::{fs, path::Path, time::Instant};
fn entries(n: usize) -> Vec<Entry> {
    let mut out: Vec<Entry> = vec![];
    for i in 0..n {
        let previous = out
            .last()
            .map(|e| hash_from(&e.hash).unwrap())
            .unwrap_or([0; 32]);
        out.push(
            Entry::new(
                i as u64,
                previous,
                format!("synthetic-event-{i:04}").as_bytes(),
            )
            .unwrap(),
        );
    }
    out
}
fn median(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}
pub fn run(out: &Path) -> Result<()> {
    fs::create_dir_all(out)?;
    let key = SigningKey::from_bytes(&[0x42; 32]);
    let id = [0x19; 32];
    let e = entries(257);
    let cp = Checkpoint::unsigned(id, &e)?.sign(&key)?;
    let public = key.verifying_key();
    let mut attacks = vec![];
    for index in 0..e.len() {
        let mut changed = e.clone();
        let mut bytes = hex::decode(&changed[index].payload).unwrap();
        bytes[0] ^= 1;
        changed[index].payload = hex::encode(bytes);
        attacks.push(json!({"kind":"flip_payload_byte","index":index,"detected":verify_log(&changed,&cp,&public,id).is_err()}));
        let mut deleted = e.clone();
        deleted.remove(index);
        attacks.push(json!({"kind":"delete_entry","index":index,"detected":verify_log(&deleted,&cp,&public,id).is_err()}));
        if index + 1 < e.len() {
            let mut reordered = e.clone();
            reordered.swap(index, index + 1);
            attacks.push(json!({"kind":"swap_adjacent","index":index,"detected":verify_log(&reordered,&cp,&public,id).is_err()}));
        }
    }
    assert!(attacks.iter().all(|r| r["detected"] == true));
    let reference = Checkpoint::unsigned(id, &e[..128])?.sign(&key)?;
    let rollback_without_pin = verify_log(&e[..128], &reference, &public, id).is_ok();
    let rollback_with_pin = verify_log(&e[..128], &cp, &public, id).is_err();
    let mut throughput = vec![];
    for mode in ["per_entry_fsync", "checkpoint_batch_fsync"] {
        for trial in 0..3 {
            let folder = std::env::temp_dir().join(format!(
                "seal-bench-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            let store = Store::create(&folder, key.clone(), id)?;
            let payloads = (0..512)
                .map(|i| {
                    format!(
                        "{{\"event\":\"synthetic\",\"index\":{i:04},\"padding\":\"{}\"}}",
                        "x".repeat(64)
                    )
                    .into_bytes()
                })
                .collect::<Vec<_>>();
            let start = Instant::now();
            let rows = store.append_many(&payloads, mode == "per_entry_fsync")?;
            let sealed = store.checkpoint()?;
            let elapsed = start.elapsed().as_secs_f64();
            verify_log(&rows, &sealed, &public, id)?;
            throughput.push(json!({"mode":mode,"trial":trial,"entries":rows.len(),"seconds":elapsed,"entries_per_second":rows.len() as f64/elapsed,"checkpoint_interval":seal_log::storage::INTERVAL}));
            fs::remove_dir_all(folder)?;
        }
    }
    let large = entries(4097);
    let new = Checkpoint::unsigned(id, &large)?.sign(&key)?;
    let old = Checkpoint::unsigned(id, &large[..2049])?.sign(&key)?;
    let inclusion = Inclusion::create(&large, 2048, new.clone())?;
    let consistency = Consistency::create(&large, old, new)?;
    let mut inclusion_times = vec![];
    let mut consistency_times = vec![];
    for _ in 0..500 {
        let start = Instant::now();
        inclusion.verify(&public, id)?;
        inclusion_times.push(start.elapsed().as_secs_f64() * 1e6);
        let start = Instant::now();
        consistency.verify(&public, id)?;
        consistency_times.push(start.elapsed().as_secs_f64() * 1e6);
    }
    let inclusion_median = median(&mut inclusion_times.clone());
    let consistency_median = median(&mut consistency_times.clone());
    fs::write(
        out.join("inclusion.json"),
        serde_json::to_vec_pretty(&inclusion)?,
    )?;
    fs::write(
        out.join("consistency.json"),
        serde_json::to_vec_pretty(&consistency)?,
    )?;
    fs::write(
        out.join("tamper.json"),
        serde_json::to_vec_pretty(&attacks)?,
    )?;
    // Real file byte mutations: canonical encoding rejects whitespace/representation edits too.
    let folder = std::env::temp_dir().join(format!("seal-bytes-{}", rand::random::<u64>()));
    fs::create_dir_all(&folder)?;
    let file = folder.join("entries.jsonl");
    let small = entries(3);
    let pinned = Checkpoint::unsigned(id, &small)?.sign(&key)?;
    let mut original = vec![];
    for entry in &small {
        original.extend(entry.wire());
        original.push(b'\n');
    }
    let mut byte_checks = 0;
    for offset in 0..original.len() {
        for bit in 0..8 {
            let mut changed = original.clone();
            changed[offset] ^= 1 << bit;
            fs::write(&file, &changed)?;
            let detected = read_entries(&file)
                .and_then(|rows| verify_log(&rows, &pinned, &public, id))
                .is_err();
            assert!(detected, "undetected byte/bit mutation {offset}:{bit}");
            byte_checks += 1;
        }
    }
    fs::remove_dir_all(folder)?;
    let result = json!({"scope":"local synthetic finite corpus; trusted public key, identity and retained signed head",
        "tamper":{"injected":attacks.len(),"detected":attacks.iter().filter(|r|r["detected"]==true).count(),"file_bit_flips":byte_checks,"file_bit_flips_detected":byte_checks},
        "rollback":{"valid_older_prefix_verifies_without_newer_pin":rollback_without_pin,"newer_pin_detects_tail_removal":rollback_with_pin},
        "append_trials":throughput,"proofs":{"tree_size":large.len(),"old_size":2049,
          "inclusion_hashes":inclusion.path.len(),"inclusion_hash_bytes":inclusion.path.len()*32,"inclusion_bundle_json_bytes":serde_json::to_vec(&inclusion)?.len(),
          "consistency_hashes":consistency.path.len(),"consistency_hash_bytes":consistency.path.len()*32,"consistency_bundle_json_bytes":serde_json::to_vec(&consistency)?.len(),
          "inclusion_verify_median_us":inclusion_median,"consistency_verify_median_us":consistency_median,
          "inclusion_samples_us":inclusion_times,"consistency_samples_us":consistency_times},
        "merkle_empty_root":hex::encode(merkle::root(&[])),"public_key":hex::encode(public.to_bytes()),"log_id":hex::encode(id)});
    fs::write(out.join("bench.json"), serde_json::to_vec_pretty(&result)?)?;
    println!("{}", result);
    Ok(())
}
