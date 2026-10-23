//! RFC 9162 tree shape and paths; not a Certificate Transparency wire protocol.
use crate::{Hash, Result, require};
use sha2::{Digest, Sha256};

pub fn leaf(bytes: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0]);
    h.update(bytes);
    h.finalize().into()
}
pub fn node(a: &Hash, b: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([1]);
    h.update(a);
    h.update(b);
    h.finalize().into()
}
fn split(n: usize) -> usize {
    1usize << ((usize::BITS - 1) - (n - 1).leading_zeros())
}
pub fn root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => Sha256::digest([]).into(),
        1 => leaves[0],
        n => {
            let k = split(n);
            node(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}
pub fn inclusion(leaves: &[Hash], index: usize) -> Result<Vec<Hash>> {
    require(index < leaves.len(), "inclusion index out of range")?;
    if leaves.len() == 1 {
        return Ok(vec![]);
    }
    let k = split(leaves.len());
    if index < k {
        let mut path = inclusion(&leaves[..k], index)?;
        path.push(root(&leaves[k..]));
        Ok(path)
    } else {
        let mut path = inclusion(&leaves[k..], index - k)?;
        path.push(root(&leaves[..k]));
        Ok(path)
    }
}
pub fn verify_inclusion(
    hash: Hash,
    index: u64,
    size: u64,
    path: &[Hash],
    expected: Hash,
) -> Result<()> {
    require(
        size > 0 && index < size && path.len() <= 64,
        "invalid inclusion bounds",
    )?;
    let mut f = index;
    let mut s = size - 1;
    let mut acc = hash;
    for sibling in path {
        require(s > 0, "extra inclusion node")?;
        if f & 1 == 1 || f == s {
            acc = node(sibling, &acc);
            while f != 0 && f & 1 == 0 {
                f >>= 1;
                s >>= 1;
            }
        } else {
            acc = node(&acc, sibling);
        }
        f >>= 1;
        s >>= 1;
    }
    require(s == 0 && acc == expected, "inclusion root mismatch")
}
fn subproof(m: usize, leaves: &[Hash], complete: bool) -> Vec<Hash> {
    if m == leaves.len() {
        return if complete { vec![] } else { vec![root(leaves)] };
    }
    let k = split(leaves.len());
    if m <= k {
        let mut p = subproof(m, &leaves[..k], complete);
        p.push(root(&leaves[k..]));
        p
    } else {
        let mut p = subproof(m - k, &leaves[k..], false);
        p.push(root(&leaves[..k]));
        p
    }
}
pub fn consistency(leaves: &[Hash], old: usize) -> Result<Vec<Hash>> {
    require(old <= leaves.len(), "shrinking tree")?;
    Ok(if old == 0 || old == leaves.len() {
        vec![]
    } else {
        subproof(old, leaves, true)
    })
}
pub fn verify_consistency(old: u64, new: u64, a: Hash, b: Hash, proof: &[Hash]) -> Result<()> {
    require(
        old <= new && proof.len() <= 65,
        "invalid consistency bounds",
    )?;
    if old == 0 {
        return require(
            a == root(&[]) && (new != 0 || b == a) && proof.is_empty(),
            "invalid empty prefix",
        );
    }
    if old == new {
        return require(a == b && proof.is_empty(), "equal-size fork");
    }
    require(!proof.is_empty(), "missing consistency path")?;
    let mut f = old - 1;
    let mut s = new - 1;
    while f & 1 == 1 {
        f >>= 1;
        s >>= 1;
    }
    let (mut fr, mut sr, start) = if old.is_power_of_two() {
        (a, a, 0)
    } else {
        (proof[0], proof[0], 1)
    };
    for c in &proof[start..] {
        require(s > 0, "extra consistency node")?;
        if f & 1 == 1 || f == s {
            fr = node(c, &fr);
            sr = node(c, &sr);
            while f != 0 && f & 1 == 0 {
                f >>= 1;
                s >>= 1;
            }
        } else {
            sr = node(&sr, c);
        }
        f >>= 1;
        s >>= 1;
    }
    require(fr == a && sr == b && s == 0, "consistency root mismatch")
}
