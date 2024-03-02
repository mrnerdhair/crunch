use std::sync::{Arc, OnceLock, RwLock};

use rustls::crypto::{hmac::{self, Hmac}, tls13::{Hkdf, HkdfExpander, OkmBlock}, ActiveKeyExchange};

use crate::{dummy_crypto_provider::{DUMMY_TLS13_CLIENT_FINISHED_KEY, DUMMY_TLS13_SERVER_FINISHED_KEY, DummyKeys}, dummy_hkdf_expander::{DummyHkdfExpander, DummyHkdfExpanderValue, DummyHkdfIkm}, hmac_sha256::HmacSha256};

#[derive(Debug)]
pub struct DummyHkdf {
    shared_secret: Vec<u8>,

    ch_sh_transcript_hash_reporter: Arc<OnceLock<[u8; 32]>>,
    ch_sf_transcript_hash_reporter: Arc<OnceLock<[u8; 32]>>,

    dummy_hkdf_expander_values: Arc<RwLock<Vec<DummyHkdfExpanderValue>>>,
    #[cfg(not(feature = "uncrunch"))]
    dummy_keys: Arc<DummyKeys>,
}

impl DummyHkdf {
    #[cfg(feature = "uncrunch")]
    pub fn new(shared_secret: &[u8], ch_sh_transcript_hash_reporter: &Arc<OnceLock<[u8; 32]>>, ch_sf_transcript_hash_reporter: &Arc<OnceLock<[u8; 32]>>) -> Self {
        Self {
            shared_secret: shared_secret.to_vec(),
            dummy_hkdf_expander_values: Default::default(),
            ch_sh_transcript_hash_reporter: Arc::clone(ch_sh_transcript_hash_reporter),
            ch_sf_transcript_hash_reporter: Arc::clone(ch_sf_transcript_hash_reporter),
        }
    }

    #[cfg(not(feature = "uncrunch"))]
    pub fn new(shared_secret: &[u8], ch_sh_transcript_hash_reporter: &Arc<OnceLock<[u8; 32]>>, ch_sf_transcript_hash_reporter: &Arc<OnceLock<[u8; 32]>>, dummy_keys: &Arc<DummyKeys>) -> Self {
        Self {
            shared_secret: shared_secret.to_vec(),
            dummy_hkdf_expander_values: Default::default(),
            dummy_keys: Arc::clone(dummy_keys),
            ch_sh_transcript_hash_reporter: Arc::clone(ch_sh_transcript_hash_reporter),
            ch_sf_transcript_hash_reporter: Arc::clone(ch_sf_transcript_hash_reporter),
        }
    }
}

impl Hkdf for DummyHkdf {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        Box::new(DummyHkdfExpander::new(DummyHkdfIkm::ZeroIkm {
            salt: salt.map(|x| x.to_vec()),
        }, &self.dummy_hkdf_expander_values, &self.ch_sh_transcript_hash_reporter, &self.ch_sf_transcript_hash_reporter))
    }

    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander> {
        Box::new(DummyHkdfExpander::new(DummyHkdfIkm::Secret {
            salt: salt.map(|x| x.to_vec()),
            secret: secret.to_vec(),
        },  &self.dummy_hkdf_expander_values, &self.ch_sh_transcript_hash_reporter, &self.ch_sf_transcript_hash_reporter))
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        Box::new(DummyHkdfExpander::new(DummyHkdfIkm::Okm {
            okm: okm.as_ref().to_vec(),
        },  &self.dummy_hkdf_expander_values, &self.ch_sh_transcript_hash_reporter, &self.ch_sf_transcript_hash_reporter))
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> hmac::Tag {
        let key: &[u8; 32] = key.as_ref().try_into().unwrap();

        #[cfg(debug_assertions)]
        eprintln!("DummyHkdf: signing {} with key {}", hex::encode(message), hex::encode(key.as_ref()));

        #[cfg(not(feature = "uncrunch"))]
        match key {
            &DUMMY_TLS13_SERVER_FINISHED_KEY => hmac::Tag::new(self.dummy_keys.server_finished_key.get().expect("server finished key unavailable")),
            &DUMMY_TLS13_CLIENT_FINISHED_KEY => hmac::Tag::new(self.dummy_keys.client_finished_key.get().expect("client finished key unavailable")),
            _ => panic!("DummyHkdf asked to hmac_sign {} with unexpected key {}", hex::encode(message), hex::encode(key.as_ref())),
            // _ => HmacSha256.with_key(key).sign(&[message]),
        }

        #[cfg(feature = "uncrunch")]
        HmacSha256.with_key(key).sign(&[message])
    }

    fn extract_from_kx_shared_secret(
            &self,
            salt: Option<&[u8]>,
            _kx: Box<dyn ActiveKeyExchange>,
            _peer_pub_key: &[u8],
        ) -> Result<Box<dyn HkdfExpander>, rustls::Error> {
        // assert_eq!(TypeId::of::<DummyActiveKeyExchange>(), (*kx).type_id());
        Ok(Box::new(DummyHkdfExpander::new(DummyHkdfIkm::Secret {
            salt: Some(self.shared_secret.clone()),
            secret: salt.map(|x| x.to_vec()).unwrap_or_else(|| vec![0u8; 32]),
        }, &self.dummy_hkdf_expander_values, &self.ch_sh_transcript_hash_reporter, &self.ch_sf_transcript_hash_reporter)))
    }
}

impl DummyHkdf {
    pub fn add_value(&mut self, value: DummyHkdfExpanderValue) {
        self.dummy_hkdf_expander_values.write().unwrap().push(value)
    }
}
