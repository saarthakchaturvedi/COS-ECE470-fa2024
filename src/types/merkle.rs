/// A Merkle tree.
use super::hash::{Hashable, H256};
use sha2::{Digest, Sha256};

/// A Merkle tree.
#[derive(Debug, Default)]
pub struct MerkleTree {
    root: H256,
    leaves: Vec<H256>,
    layers: Vec<Vec<H256>>,
}

impl MerkleTree {
    pub fn new<T>(data: &[T]) -> Self 
    where T: Hashable {
        let mut leaves: Vec<H256> = Vec::new();

        // Hash each piece of data and add it to the leaves
        for item in data {
            leaves.push(item.hash());
        }

        let mut layers = vec![leaves.clone()];
        let mut curr = leaves.clone();

        while curr.len() > 1 {
            if curr.len() % 2 != 0 {
                curr.push(curr.last().copied().unwrap()); // Duplicate the last element if odd number of nodes
            }
            
            let mut next = Vec::new();
            for step in curr.chunks(2) {
                let mut hash = Sha256::new();
                hash.update(step[0].as_ref());
                hash.update(step[1].as_ref());
                let parent_hash = H256(hash.finalize().into());
                next.push(parent_hash);
            }

            layers.push(next.clone());
            curr = next;
        }

        let root = curr[0];

        MerkleTree { root, leaves, layers }
    }

    pub fn root(&self) -> H256 {
        self.root
    }

    pub fn proof(&self, index: usize) -> Vec<H256> {
        let mut proof = Vec::new();
        let mut idx = index;

        for layer in &self.layers {
            if idx % 2 == 0 && idx + 1 < layer.len() {
                proof.push(layer[idx + 1]);
            } else if idx % 2 == 1 {
                proof.push(layer[idx - 1]);
            }
            idx /= 2;
        }

        proof
    }
}


/// Verify that the datum hash with a vector of proofs will produce the Merkle root. Also need the
/// index of datum and `leaf_size`, the total number of leaves.
pub fn verify(root: &H256, datum: &H256, proof: &[H256], index: usize, leaf_size: usize) -> bool {
    let mut hash = *datum;
    let mut indexval = index;

    for x in proof{
        let mut hasher = Sha256::new();
        if indexval%2==0{
            hasher.update(hash.as_ref());
            hasher.update(x.as_ref());
        }
        else{
            hasher.update(x.as_ref());
            hasher.update(hash.as_ref());
        }

        hash = H256(hasher.finalize().into());
        indexval = indexval/2;
    }

    return &hash==root;
}
// DO NOT CHANGE THIS COMMENT, IT IS FOR AUTOGRADER. BEFORE TEST

#[cfg(test)]
mod tests {
    use crate::types::hash::H256;
    use super::*;

    macro_rules! gen_merkle_tree_data {
        () => {{
            vec![
                (hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d")).into(),
                (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
            ]
        }};
    }

    #[test]
    fn merkle_root() {
        let input_data: Vec<H256> = gen_merkle_tree_data!();
        let input_data: Vec<H256> = gen_merkle_tree_data!();
    println!("Input Data: {:?}", input_data);
        let merkle_tree = MerkleTree::new(&input_data);
        let root = merkle_tree.root();
        assert_eq!(
            root,
            (hex!("6b787718210e0b3b608814e04e61fde06d0df794319a12162f287412df3ec920")).into()
        );
        // "b69566be6e1720872f73651d1851a0eae0060a132cf0f64a0ffaea248de6cba0" is the hash of
        // "0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d"
        // "965b093a75a75895a351786dd7a188515173f6928a8af8c9baa4dcff268a4f0f" is the hash of
        // "0101010101010101010101010101010101010101010101010101010101010202"
        // "6b787718210e0b3b608814e04e61fde06d0df794319a12162f287412df3ec920" is the hash of
        // the concatenation of these two hashes "b69..." and "965..."
        // notice that the order of these two matters
    }

    #[test]
    fn merkle_proof() {
        let input_data: Vec<H256> = gen_merkle_tree_data!();
        let merkle_tree = MerkleTree::new(&input_data);
        let proof = merkle_tree.proof(0);
        assert_eq!(proof,
                   vec![hex!("965b093a75a75895a351786dd7a188515173f6928a8af8c9baa4dcff268a4f0f").into()]
        );
        // "965b093a75a75895a351786dd7a188515173f6928a8af8c9baa4dcff268a4f0f" is the hash of
        // "0101010101010101010101010101010101010101010101010101010101010202"
    }

    #[test]
    fn merkle_verifying() {
        let input_data: Vec<H256> = gen_merkle_tree_data!();
        let merkle_tree = MerkleTree::new(&input_data);
        let proof = merkle_tree.proof(0);
        assert!(verify(&merkle_tree.root(), &input_data[0].hash(), &proof, 0, input_data.len()));
    }
}

// DO NOT CHANGE THIS COMMENT, IT IS FOR AUTOGRADER. AFTER TEST