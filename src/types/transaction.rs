use serde::{Serialize,Deserialize};
use ring::signature::{Ed25519KeyPair, Signature, UnparsedPublicKey, ED25519};
use rand::Rng;
use crate::types::address::Address;
use bincode;

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Transaction {
    sender: Address,
    receiver: Address,
    value: i32,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SignedTransaction {
    transaction: Transaction,
    signature: u8,
    public_key: u8,
}

/// Create digital signature of a transaction
pub fn sign(t: &Transaction, key: &Ed25519KeyPair) -> Signature {
    let serialized: Vec<u8> = bincode::serialize(t).unwrap();
    key.sign(&serialized)
}

/// Verify digital signature of a transaction, using public key instead of secret key
pub fn verify(t: &Transaction, public_key: &[u8], signature: &[u8]) -> bool {
    // let serialized = bincode::serialize(t).expect("Failed");
    let serialized: Vec<u8> = bincode::serialize(t).unwrap();

    // Use an unparsed public key to verify the signature
    let public = UnparsedPublicKey::new(&ED25519, public_key);

    // Verify the signature. Return true if valid, false otherwise.
    public.verify(&serialized, signature).is_ok()
}

#[cfg(any(test, test_utilities))]
pub fn generate_random_transaction() -> Transaction {
    let test_key = hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d");
    let addr = Address::from_public_key_bytes(&test_key);
    let mut rng = rand::thread_rng();
    let random_value = rng.gen_range(1..100);
    Transaction {
        sender: addr,
        receiver: addr,
        value: random_value,
    }
}

// DO NOT CHANGE THIS COMMENT, IT IS FOR AUTOGRADER. BEFORE TEST

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::key_pair;
    use ring::signature::KeyPair;


    #[test]
    fn sign_verify() {
        let t = generate_random_transaction();
        let key = key_pair::random();
        let signature = sign(&t, &key);
        assert!(verify(&t, key.public_key().as_ref(), signature.as_ref()));
    }
    #[test]
    fn sign_verify_two() {
        let t = generate_random_transaction();
        let key = key_pair::random();
        let signature = sign(&t, &key);
        let key_2 = key_pair::random();
        let t_2 = generate_random_transaction();
        assert!(!verify(&t_2, key.public_key().as_ref(), signature.as_ref()));
        assert!(!verify(&t, key_2.public_key().as_ref(), signature.as_ref()));
    }
}

// DO NOT CHANGE THIS COMMENT, IT IS FOR AUTOGRADER. AFTER TEST