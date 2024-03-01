use std::{cell::OnceCell, sync::{Arc, RwLock}, vec};

use rustls::{crypto::{CipherSuiteCommon, CryptoProvider}, CipherSuite, NamedGroup, SupportedCipherSuite, Tls13CipherSuite};

use crate::{aead_aes_128_gcm::AeadAes128Gcm, dummy_hkdf::DummyHkdf, dummy_key_provider::DummyKeyProvider, dummy_secure_random::DummySecureRandom, dummy_supported_kx_group::DummySupportedKxGroup, hash_sha256::HashSha256, hmac_sha256::HmacSha256, verify};

const HASH_SHA256: OnceCell<&'static HashSha256> = OnceCell::new();
const AEAD_AES_128_GCM: OnceCell<&'static AeadAes128Gcm> = OnceCell::new();
const DUMMY_HKDF_SHA256: OnceCell<&'static DummyHkdf> = OnceCell::new();
const DUMMY_TLS13_CIPHERSUITE: OnceCell<&'static Tls13CipherSuite> = OnceCell::new();
const DUMMY_KEY_PROVIDER: OnceCell<&'static DummyKeyProvider> = OnceCell::new();

pub fn get_dummy_crypto_provider(dummy_random_data: &Arc<RwLock<Vec<u8>>>, dummy_pubkey: &Arc<Vec<u8>>) -> CryptoProvider {
    let dummy_secure_random = Box::leak(Box::new(DummySecureRandom::new(dummy_random_data)));
    let dummy_supported_kx_group = Box::leak(Box::new(DummySupportedKxGroup::new(NamedGroup::X25519, dummy_pubkey)));

    CryptoProvider {
        cipher_suites: vec![SupportedCipherSuite::Tls13(DUMMY_TLS13_CIPHERSUITE.get_or_init(|| {
            Box::leak(Box::new(Tls13CipherSuite {
                common: CipherSuiteCommon {
                    suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                    hash_provider: *HASH_SHA256.get_or_init(|| {
                        Box::leak(Box::new(HashSha256))
                    }),
                    confidentiality_limit: 1 << 23,
                    integrity_limit: 1 << 52,
                },
                hkdf_provider: *DUMMY_HKDF_SHA256.get_or_init(|| {
                    Box::leak(Box::new(DummyHkdf::new(HmacSha256)))
                }),
                aead_alg: *AEAD_AES_128_GCM.get_or_init(|| {
                    Box::leak(Box::new(AeadAes128Gcm))
                }),
                quic: None,
            }))
        }))],
        kx_groups: vec![
            dummy_supported_kx_group,
        ],
        signature_verification_algorithms: verify::ALGORITHMS,
        secure_random: dummy_secure_random,
        key_provider: *DUMMY_KEY_PROVIDER.get_or_init(|| {
            Box::leak(Box::new(DummyKeyProvider::default()))
        }),
    }
}
