use aes_gcm::{AeadInPlace, KeyInit};
use rustls::{crypto::cipher::{make_tls13_aad, AeadKey, BorrowedPlainMessage, Iv, MessageDecrypter, MessageEncrypter, OpaqueMessage, PlainMessage, Tls13AeadAlgorithm, UnsupportedOperationError}, ConnectionTrafficSecrets};

pub struct AeadAes128Gcm;

impl Tls13AeadAlgorithm for AeadAes128Gcm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(AeadAes128GcmMessageEncrypter{
            key: key.as_ref().try_into().unwrap(),
            iv: iv.as_ref().try_into().unwrap(),
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(AeadAes128GcmMessageDecrypter{
            key: key.as_ref().try_into().unwrap(),
            iv: iv.as_ref().try_into().unwrap(),
        })
    }

    fn key_len(&self) -> usize {
        16
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv })
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
        let associated_data = make_tls13_aad(msg.payload.len());
        let mut buffer = msg.payload.to_vec();
        buffer.extend_from_slice(&[0u8; 16]);
        aes_gcm::Aes128Gcm::new(&self.key.into()).encrypt_in_place(&nonce.into(), &associated_data, &mut buffer).map_err(|_| rustls::Error::EncryptError)?;
        Ok(OpaqueMessage::new(rustls::ContentType::ApplicationData, rustls::ProtocolVersion::TLSv1_3, buffer))
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
