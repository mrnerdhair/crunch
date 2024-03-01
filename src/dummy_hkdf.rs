use std::any::{Any, TypeId};

use rustls::crypto::{hmac::Hmac, tls13::{Hkdf, HkdfExpander, HkdfUsingHmac, OkmBlock}};

use crate::{dummy_active_key_exchange::DummyActiveKeyExchange, dummy_hkdf_expander::DummyHkdfExpander};

pub struct DummyHkdf {
    hmac: Box<dyn Hmac>,
}

impl Hkdf for DummyHkdf {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        let zeroes = vec![0u8; self.hmac.hash_output_len()];
        self.extract_from_secret(salt, &zeroes)
    }

    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander> {
        // todo: add things
        Box::new(DummyHkdfExpander::new(self.hmac.hash_output_len()))
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        HkdfUsingHmac(self.hmac.as_ref()).expander_for_okm(okm)
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> rustls::crypto::hmac::Tag {
        self.hmac.with_key(key.as_ref()).sign(&[message])
    }

    fn extract_from_kx_shared_secret(
            &self,
            salt: Option<&[u8]>,
            kx: Box<dyn rustls::crypto::ActiveKeyExchange>,
            peer_pub_key: &[u8],
        ) -> Result<Box<dyn HkdfExpander>, rustls::Error> {
        assert_eq!(TypeId::of::<DummyActiveKeyExchange>(), kx.type_id());
        let mut expander = DummyHkdfExpander::new(self.hmac.hash_output_len());
        // expander.add_value(info, output);
        Ok(Box::new(expander))
    }
}

impl DummyHkdf {
    pub fn new<T: Hmac + 'static>(hmac: T) -> Self {
        Self {
            hmac: Box::new(hmac),
        }
    }
}
