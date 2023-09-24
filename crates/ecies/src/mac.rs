use ethereum_types::H256;
use sha3::{Digest, Keccak256};

#[derive(Debug)]
pub struct MAC {
    secret: H256,
    hasher: Keccak256,
}

impl MAC {
    pub fn new(secret: H256) -> Self {
        Self { secret, hasher: Keccak256::new() }
    }
}
