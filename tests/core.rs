use ed25519_dalek::SigningKey;
use seal_log::{merkle::*, *};
fn entries(n: usize) -> Vec<Entry> {
    let mut out: Vec<Entry> = vec![];
    for i in 0..n {
        let prev = out
            .last()
            .map(|e| hash_from(&e.hash).unwrap())
            .unwrap_or([0; 32]);
        out.push(Entry::new(i as u64, prev, format!("synthetic-{i}").as_bytes()).unwrap());
    }
    out
}
#[test]
fn empty_and_chain_mutations() {
    let e = entries(7);
    verify_chain(&e).unwrap();
    let key = SigningKey::from_bytes(&[7; 32]);
    let id = [4; 32];
    let cp = Checkpoint::unsigned(id, &e).unwrap().sign(&key).unwrap();
    verify_log(&e, &cp, &key.verifying_key(), id).unwrap();
    for i in 0..e.len() {
        let mut bad = e.clone();
        bad[i].payload = hex::encode(b"changed");
        assert!(verify_log(&bad, &cp, &key.verifying_key(), id).is_err());
        let mut bad = e.clone();
        bad.remove(i);
        assert!(verify_log(&bad, &cp, &key.verifying_key(), id).is_err());
    }
    let old = Checkpoint::unsigned(id, &e[..3])
        .unwrap()
        .sign(&key)
        .unwrap();
    // A valid older signed prefix alone cannot expose rollback; the retained newer head does.
    verify_log(&e[..3], &old, &key.verifying_key(), id).unwrap();
    assert!(verify_log(&e[..3], &cp, &key.verifying_key(), id).is_err());
    let mut empty = Checkpoint::unsigned(id, &[]).unwrap().sign(&key).unwrap();
    empty.root = hex::encode([1; 32]);
    empty = empty.sign(&key).unwrap();
    assert!(empty.verify(&key.verifying_key(), id).is_err());
}
#[test]
fn every_small_tree_inclusion_and_consistency() {
    let e = entries(80);
    let all = e.iter().map(Entry::leaf).collect::<Vec<_>>();
    for n in 1..=80 {
        let leaves = &all[..n];
        let r = root(leaves);
        for i in 0..n {
            let path = inclusion(leaves, i).unwrap();
            verify_inclusion(leaves[i], i as u64, n as u64, &path, r).unwrap();
            let mut extra = path.clone();
            extra.push([0; 32]);
            assert!(verify_inclusion(leaves[i], i as u64, n as u64, &extra, r).is_err());
            if !path.is_empty() {
                let mut bad = path.clone();
                bad[0][0] ^= 1;
                assert!(verify_inclusion(leaves[i], i as u64, n as u64, &bad, r).is_err());
            }
        }
        for m in 0..=n {
            let proof = consistency(leaves, m).unwrap();
            verify_consistency(m as u64, n as u64, root(&leaves[..m]), r, &proof).unwrap();
            let mut extra = proof.clone();
            extra.push([0; 32]);
            assert!(verify_consistency(m as u64, n as u64, root(&leaves[..m]), r, &extra).is_err());
            if !proof.is_empty() {
                let mut bad = proof.clone();
                bad[0][0] ^= 1;
                assert!(
                    verify_consistency(m as u64, n as u64, root(&leaves[..m]), r, &bad).is_err()
                );
            }
        }
    }
    assert!(verify_consistency(1, 0, all[0], root(&[]), &[]).is_err());
    assert!(verify_consistency(0, 0, root(&[]), [2; 32], &[]).is_err());
}
#[test]
fn signed_bundles_trust_anchor_and_malformed_bounds() {
    let e = entries(19);
    let key = SigningKey::from_bytes(&[3; 32]);
    let id = [8; 32];
    let cp = Checkpoint::unsigned(id, &e).unwrap().sign(&key).unwrap();
    let old = Checkpoint::unsigned(id, &e[..7])
        .unwrap()
        .sign(&key)
        .unwrap();
    let bundle = Inclusion::create(&e, 18, cp.clone()).unwrap();
    bundle.verify(&key.verifying_key(), id).unwrap();
    assert!(
        bundle
            .verify(&SigningKey::from_bytes(&[4; 32]).verifying_key(), id)
            .is_err()
    );
    assert!(bundle.verify(&key.verifying_key(), [9; 32]).is_err());
    let mut bad = bundle.clone();
    bad.entry.seq = u64::MAX;
    assert!(bad.verify(&key.verifying_key(), id).is_err());
    let mut bad = bundle.clone();
    bad.checkpoint.signature = hex::encode([0; 64]);
    assert!(bad.verify(&key.verifying_key(), id).is_err());
    let mut bad = bundle.clone();
    bad.checkpoint.signature = bad.checkpoint.signature.to_uppercase();
    assert!(bad.verify(&key.verifying_key(), id).is_err());
    let proof = Consistency::create(&e, old, cp).unwrap();
    proof.verify(&key.verifying_key(), id).unwrap();
    let mut bad = proof;
    bad.new.root = hex::encode([0; 32]);
    assert!(bad.verify(&key.verifying_key(), id).is_err());
}
#[test]
fn independent_reference_tree_matches() {
    // Iterative largest-complete-subtree stack, unlike the recursive implementation.
    let e = entries(127);
    let leaves = e.iter().map(Entry::leaf).collect::<Vec<_>>();
    for n in 1..=127 {
        let mut stack: Vec<(usize, Hash)> = vec![];
        for leaf in &leaves[..n] {
            let mut width = 1;
            let mut hash = *leaf;
            while stack.last().is_some_and(|(w, _)| *w == width) {
                let (_, left) = stack.pop().unwrap();
                hash = node(&left, &hash);
                width *= 2;
            }
            stack.push((width, hash));
        }
        let mut hash = stack.pop().unwrap().1;
        while let Some((_, left)) = stack.pop() {
            hash = node(&left, &hash);
        }
        assert_eq!(hash, root(&leaves[..n]));
    }
}
#[test]
fn payload_limits_and_canonical_hex() {
    assert!(Entry::new(0, [0; 32], &vec![0; MAX_PAYLOAD + 1]).is_err());
    assert!(hash_from(&"AB".repeat(32)).is_err());
    assert!(hash_from("00").is_err());
    let e = Entry::new(0, [0; 32], b"").unwrap();
    e.validate().unwrap();
}
