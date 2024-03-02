use std::sync::{Arc, RwLock};

use rustls::crypto::{hmac, tls13::{Hkdf, HkdfExpander, OkmBlock}, ActiveKeyExchange};

use crate::{dummy_crypto_provider::{DUMMY_ECDHE_SHARED_SECRET, DUMMY_TLS13_CLIENT_FINISHED_KEY, DUMMY_TLS13_SERVER_FINISHED_KEY}, dummy_hkdf_expander::{DummyHkdfExpander, DummyHkdfExpanderValue, DummyHkdfIkm}};

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

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> hmac::Tag {
        let key: &[u8; 32] = key.as_ref().try_into().unwrap();
        match key {
            &DUMMY_TLS13_SERVER_FINISHED_KEY => hmac::Tag::new(&hex::decode("9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718").unwrap()),
            &DUMMY_TLS13_CLIENT_FINISHED_KEY => hmac::Tag::new(&hex::decode("a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61").unwrap()),
            _ => panic!("DummyHkdf asked to hmac_sign {} with unexpected key {}", hex::encode(message), hex::encode(key.as_ref())),
        }
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
