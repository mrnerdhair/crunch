use std::sync::{Arc, RwLock};

use rustls::crypto::{hmac, tls13::{Hkdf, HkdfExpander, OkmBlock}, ActiveKeyExchange};

use crate::{dummy_crypto_provider::DUMMY_ECDHE_SHARED_SECRET, dummy_hkdf_expander::{DummyHkdfExpander, DummyHkdfExpanderValue, DummyHkdfIkm}};

#[derive(Debug, Default)]
pub struct DummyHkdf {
    dummy_hkdf_expander_values: Arc<RwLock<Vec<DummyHkdfExpanderValue>>>
}

impl Hkdf for DummyHkdf {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        Box::new(DummyHkdfExpander::new(DummyHkdfIkm::ZeroIkm {
            salt: salt.map(|x| x.to_vec()),
        }, Arc::clone(&self.dummy_hkdf_expander_values)))
    }

    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander> {
        Box::new(DummyHkdfExpander::new(DummyHkdfIkm::Secret {
            salt: salt.map(|x| x.to_vec()),
            secret: secret.to_vec(),
        },  Arc::clone(&self.dummy_hkdf_expander_values)))
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        Box::new(DummyHkdfExpander::new(DummyHkdfIkm::Okm {
            okm: okm.as_ref().to_vec(),
        },  Arc::clone(&self.dummy_hkdf_expander_values)))
    }

    fn hmac_sign(&self, _key: &OkmBlock, _message: &[u8]) -> hmac::Tag {
        todo!()
        // self.hmac.with_key(key.as_ref()).sign(&[message])
    }

    fn extract_from_kx_shared_secret(
            &self,
            salt: Option<&[u8]>,
            _kx: Box<dyn ActiveKeyExchange>,
            _peer_pub_key: &[u8],
        ) -> Result<Box<dyn HkdfExpander>, rustls::Error> {
        // assert_eq!(TypeId::of::<DummyActiveKeyExchange>(), (*kx).type_id());
        Ok(Box::new(DummyHkdfExpander::new(DummyHkdfIkm::Secret {
            salt: Some(DUMMY_ECDHE_SHARED_SECRET.to_vec()),
            secret: salt.map(|x| x.to_vec()).unwrap_or_else(|| vec![0u8; 32]),
        }, Arc::clone(&self.dummy_hkdf_expander_values))))
    }
}

impl DummyHkdf {
    pub fn add_value(&mut self, value: DummyHkdfExpanderValue) {
        self.dummy_hkdf_expander_values.write().unwrap().push(value)
    }
}
