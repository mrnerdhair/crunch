use std::{sync::{atomic::{AtomicBool, Ordering}, Arc, OnceLock, RwLock}, vec};

use rustls::crypto::{hmac::Hmac, tls13::{HkdfExpander, OkmBlock, OutputLengthError}};
#[cfg(feature = "uncrunch")]
use sha2::Sha256;

use crate::{hash_reporter::HashReporters, hmac_sha256::HmacSha256};

#[derive(Debug, PartialEq, Clone)]
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

impl DummyHkdfIkm {
    #[cfg_attr(not(feature = "uncrunch"), allow(dead_code))]
    pub fn as_bytes(&self) -> Vec<u8> {
        match &self {
            DummyHkdfIkm::ZeroIkm{ salt } => {
                HmacSha256.with_key(&salt.as_ref().unwrap_or(&vec![0u8; 32])).sign(&[&[0u8; 32]]).as_ref().to_vec()
            },
            DummyHkdfIkm::Secret { salt, secret } => {
                let zero_salt = vec![0u8; 32];
                let salt = salt.as_ref().unwrap_or(&zero_salt);
                let (secret, salt) = (salt, secret);
                HmacSha256.with_key(salt).sign(&[secret]).as_ref().to_vec()
            },
            DummyHkdfIkm::Okm { okm } => {
                okm.to_vec()
            },
        }
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
    hash_reporters: HashReporters,
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

        #[cfg(debug_assertions)]
        eprintln!("DummyHkdfExpander expanding ikm/info: {:x?} {}", self.ikm, hex::encode(&info));

        if info.len() == 54 && &info[11..21] == b"hs traffic" {
            let _ = self.hash_reporters.report_ch_sh_transcript_hash(info[22..].try_into().unwrap());
        }

        if info.len() == 54 && &info[11..21] == b"ap traffic" {
            let _ = self.hash_reporters.report_ch_sf_transcript_hash(info[22..].try_into().unwrap());
        }

        #[cfg(not(feature = "uncrunch"))]
        panic!("DummyHkdfExpander asked to expand unexpected ikm/info: {:x?} {}", self.ikm, hex::encode(&info));

        #[cfg(feature = "uncrunch")]
        hkdf::Hkdf::<Sha256>::from_prk(&self.ikm.as_bytes()).or(Err(())).and_then(|x| x.expand(&info, output).or(Err(()))).or_else(|_| Err(OutputLengthError))
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut out = vec![0; 32];
        self.expand_slice(info, &mut out).unwrap();
        OkmBlock::new(&out)
    }

    fn hash_len(&self) -> usize { 32 }
}

impl<'a> DummyHkdfExpander {
    pub fn new(ikm: DummyHkdfIkm, values: &Arc<RwLock<Vec<DummyHkdfExpanderValue>>>, hash_reporters: &HashReporters) -> Self {
        Self {
            ikm,
            values: Arc::clone(values),
            hash_reporters: hash_reporters.clone(),
        }
    }
}
