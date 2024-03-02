use std::{sync::{Arc, RwLock}, vec};

use rustls::crypto::tls13::{HkdfExpander, OkmBlock, OutputLengthError};

#[derive(Debug, PartialEq)]
pub enum DummyHkdfIkm {
    ZeroIkm {
        salt: Option<Vec<u8>>,
    },
    Secret {
        salt: Option<Vec<u8>>,
        secret: Vec<u8>,
    },
    Okm {
        okm: Vec<u8>,
    }
}

#[derive(Debug)]
pub struct DummyHkdfExpanderValue {
    ikm: DummyHkdfIkm,
    info: Vec<u8>,
    output: Vec<u8>,
}

impl DummyHkdfExpanderValue {
    pub fn new(ikm: DummyHkdfIkm, info: &[u8], output: &[u8]) -> Self {
        Self {
            ikm,
            info: info.to_vec(),
            output: output.to_vec(),
        }
    }
}

#[derive(Debug)]
pub struct DummyHkdfExpander {
    ikm: DummyHkdfIkm,
    values: Arc<RwLock<Vec<DummyHkdfExpanderValue>>>,
}

fn collect_info(info: &[&[u8]]) -> Vec<u8> {
    info.iter().map(|x| x.iter()).flatten().map(|x| *x).collect()
}

impl HkdfExpander for DummyHkdfExpander {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        let info: Vec<u8> = collect_info(info);

        for value in self.values.read().unwrap().iter() {
            if self.ikm == value.ikm && info.len() >= value.info.len() && &info[..value.info.len()] == &value.info {
                if output.len() > value.output.len() {
                    return Err(OutputLengthError)
                } else {
                    output.copy_from_slice(&value.output[..output.len()]);
                    return Ok(())
                }
            }
        }

        panic!("DummyHkdfExpander asked to expand unexpected ikm/info: {:x?} {}", self.ikm, hex::encode(info));
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut out = vec![0; 32];
        self.expand_slice(info, &mut out).unwrap();
        OkmBlock::new(&out)
    }

    fn hash_len(&self) -> usize { 32 }
}

impl<'a> DummyHkdfExpander {
    pub fn new(ikm: DummyHkdfIkm, values: Arc<RwLock<Vec<DummyHkdfExpanderValue>>>) -> Self {
        let out = Self {
            ikm,
            values,
        };

        out
    }
}
