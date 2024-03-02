use std::sync::Arc;

use aes_gcm::{AeadInPlace, KeyInit};
use rustls::{crypto::cipher::{make_tls13_aad, AeadKey, BorrowedPlainMessage, Iv, MessageDecrypter, MessageEncrypter, OpaqueMessage, PlainMessage, Tls13AeadAlgorithm, UnsupportedOperationError}, ConnectionTrafficSecrets};

use crate::dummy_crypto_provider::{self, DummyKeys};

#[derive(Debug, Default)]
pub struct AeadAes128Gcm {
    #[cfg(not(feature = "uncrunch"))]
    dummy_keys: Arc<DummyKeys>,
}

impl AeadAes128Gcm {
    #[cfg(not(feature = "uncrunch"))]
    pub fn new(dummy_keys: Arc<DummyKeys>) -> Self {
        Self {
            dummy_keys,
        }
    }

    #[cfg(feature = "uncrunch")]
    fn sub_dummy_keys(&self, _key: &mut [u8; 16], _iv: &mut [u8; 12]) {}

    #[cfg(not(feature = "uncrunch"))]
    fn sub_dummy_keys(&self, key: &mut [u8; 16], iv: &mut [u8; 12]) {
        let mut padded_key = key.to_vec();
        padded_key.resize(32, 0);
        let padded_key: [u8; 32] = padded_key.try_into().unwrap();
        match padded_key {
            dummy_crypto_provider::DUMMY_TLS13_C_HS_TRAFFIC_KEY => key.copy_from_slice(self.dummy_keys.client_hs_traffic_key.get().expect("client_hs_traffic_key unavailable")),
            dummy_crypto_provider::DUMMY_TLS13_S_HS_TRAFFIC_KEY => key.copy_from_slice(self.dummy_keys.server_hs_traffic_key.get().expect("server_hs_traffic_key unavailable")),
            dummy_crypto_provider::DUMMY_TLS13_C_AP_TRAFFIC_KEY => key.copy_from_slice(self.dummy_keys.client_ap_traffic_key.get().expect("client_ap_traffic_key unavailable")),
            dummy_crypto_provider::DUMMY_TLS13_S_AP_TRAFFIC_KEY => key.copy_from_slice(self.dummy_keys.server_ap_traffic_key.get().expect("server_ap_traffic_key unavailable")),
            _ => (),
        }

        let mut padded_iv = iv.to_vec();
        padded_iv.resize(32, 0);
        let padded_iv: [u8; 32] = padded_iv.try_into().unwrap();
        match padded_iv {
            dummy_crypto_provider::DUMMY_TLS13_C_HS_TRAFFIC_IV => iv.copy_from_slice(self.dummy_keys.client_hs_traffic_iv.get().expect("client_hs_traffic_iv unavailable")),
            dummy_crypto_provider::DUMMY_TLS13_S_HS_TRAFFIC_IV => iv.copy_from_slice(self.dummy_keys.server_hs_traffic_iv.get().expect("server_hs_traffic_iv unavailable")),
            dummy_crypto_provider::DUMMY_TLS13_C_AP_TRAFFIC_IV => iv.copy_from_slice(self.dummy_keys.client_ap_traffic_iv.get().expect("client_ap_traffic_iv unavailable")),
            dummy_crypto_provider::DUMMY_TLS13_S_AP_TRAFFIC_IV => iv.copy_from_slice(self.dummy_keys.server_ap_traffic_iv.get().expect("server_ap_traffic_iv unavailable")),
            _ => (),
        }
    }
}

impl Tls13AeadAlgorithm for AeadAes128Gcm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        let mut key: [u8; 16] = key.as_ref().try_into().unwrap();
        let mut iv: [u8; 12] = iv.as_ref().try_into().unwrap();

        #[cfg(debug_assertions)]
        eprintln!("MessageEncrypter for {} / {}", hex::encode(&key), hex::encode(&iv));
        self.sub_dummy_keys(&mut key, &mut iv);

        Box::new(AeadAes128GcmMessageEncrypter{ key, iv })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        let mut key: [u8; 16] = key.as_ref().try_into().unwrap();
        let mut iv: [u8; 12] = iv.as_ref().try_into().unwrap();

        #[cfg(debug_assertions)]
        eprintln!("MessageDecrypter for {} / {}", hex::encode(&key), hex::encode(&iv));
        self.sub_dummy_keys(&mut key, &mut iv);

        Box::new(AeadAes128GcmMessageDecrypter{ key, iv })
    }

    fn key_len(&self) -> usize {
        16
    }

    fn extract_keys(
        &self,
        _key: AeadKey,
        _iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        unimplemented!()
    }
}

fn build_nonce(iv: [u8; 12], seq: u64) -> [u8; 12] {
    let mut padded_iv = [0u8; 12];
    (&mut padded_iv[4..]).clone_from_slice(&seq.to_be_bytes());
    
    let mut out = [0u8; 12];
    for i in 0..iv.len() { out[i] = iv[i] ^ padded_iv[i]; }

    out
}

pub struct AeadAes128GcmMessageEncrypter {
    key: [u8; 16],
    iv: [u8; 12],
}

impl MessageEncrypter for AeadAes128GcmMessageEncrypter {
    fn encrypt(&mut self, msg: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, rustls::Error> {
        let nonce = build_nonce(self.iv, seq);
        let mut buffer = msg.payload.to_vec();
        buffer.extend_from_slice(&[msg.typ.get_u8()]);

        #[cfg(debug_assertions)]
        eprintln!("encrypting {}", hex::encode(&buffer));

        let associated_data = make_tls13_aad(buffer.len() + 16);

        aes_gcm::Aes128Gcm::new(&self.key.into()).encrypt_in_place(&nonce.into(), &associated_data, &mut buffer).map_err(|_| rustls::Error::EncryptError)?;

        Ok(OpaqueMessage::new(rustls::ContentType::ApplicationData, rustls::ProtocolVersion::TLSv1_2, buffer))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len - 16
    }
}

pub struct AeadAes128GcmMessageDecrypter {
    key: [u8; 16],
    iv: [u8; 12],
}

impl MessageDecrypter for AeadAes128GcmMessageDecrypter {
    fn decrypt(&mut self, mut msg: OpaqueMessage, seq: u64) -> Result<PlainMessage, rustls::Error> {
        let nonce = build_nonce(self.iv, seq);
        let associated_data = make_tls13_aad(msg.payload().len());
        aes_gcm::Aes128Gcm::new(&self.key.into()).decrypt_in_place(&nonce.into(), &associated_data, msg.payload_mut()).map_err(|_| rustls::Error::DecryptError)?;
        msg.into_tls13_unpadded_message()
    }
}
