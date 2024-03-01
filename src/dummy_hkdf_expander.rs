use std::vec;

use rustls::crypto::tls13::{HkdfExpander, OkmBlock, OutputLengthError};
use zeroize::Zeroize;

#[derive(Zeroize)]
struct DummyHkdfExpanderValue {
    info: Vec<u8>,
    output: Vec<u8>,
}

#[derive(Zeroize)]
pub struct DummyHkdfExpander {
    hashlen: usize,
    values: Vec<DummyHkdfExpanderValue>,
}

impl HkdfExpander for DummyHkdfExpander {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        for value in self.values.iter() {
            if info.iter().map(|x| x.iter()).flatten().eq(value.info.iter()) {
                if output.len() > value.output.len() {
                    return Err(OutputLengthError)
                } else {
                    output.copy_from_slice(&value.output[..output.len()]);
                    return Ok(())
                }
            }
        }

        panic!("DummyHkdfExpander asked to expand unexpected info");
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut out = vec![0; self.hashlen];
        self.expand_slice(info, &mut out).unwrap();
        OkmBlock::new(&out)
    }

    fn hash_len(&self) -> usize { self.hashlen }
}

impl DummyHkdfExpander {
    pub fn new(hash_len: usize) -> Self {
        Self {
            hashlen: hash_len,
            values: vec![],
        }
    }

    pub fn add_value(&mut self, info: &[u8], output: &[u8]) {
        assert!(output.len() % self.hash_len() == 0);
        self.values.push(DummyHkdfExpanderValue {
            info: info.to_vec(),
            output: output.to_vec(),
        })
    }
}
