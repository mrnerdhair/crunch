use rustls::crypto::hash;
use sha2::{Digest, Sha256};

use crate::hash_reporter::HashReporters;

#[derive(Debug, Default)]
pub struct HashSha256(HashReporters);

impl HashSha256 {
    pub fn new(hash_reporters: HashReporters) -> Self {
        Self(hash_reporters)
    }
}

impl hash::Hash for HashSha256 {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(HashSha256Context(Sha256::new(), self.0.clone()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&Sha256::digest(data)[..])
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::SHA256
    }

    fn output_len(&self) -> usize {
        32
    }
}

struct HashSha256Context(Sha256, HashReporters);

impl hash::Context for HashSha256Context {
    fn fork_finish(&self) -> hash::Output {
        let out: [u8; 32] = self.0.clone().finalize().into();
        // println!("fork-finalizing hash {}", hex::encode(out.as_ref()));
        self.1.report(out);
        hash::Output::new(&out[..])
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(HashSha256Context(self.0.clone(), self.1.clone()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        let out = hash::Output::new(&self.0.finalize()[..]);
        // println!("finalizing hash {}", hex::encode(out.as_ref()));
        out
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}
