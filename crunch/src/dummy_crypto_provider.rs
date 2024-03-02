use std::{sync::{Arc, RwLock}, vec};

use rustls::{crypto::{CipherSuiteCommon, CryptoProvider, SupportedKxGroup, WebPkiSupportedAlgorithms}, CipherSuite, NamedGroup, SupportedCipherSuite, Tls13CipherSuite};

use crate::{aead_aes_128_gcm::AeadAes128Gcm, dummy_hkdf::DummyHkdf, dummy_hkdf_expander::{DummyHkdfExpanderValue, DummyHkdfIkm}, dummy_key_provider::DummyKeyProvider, dummy_secure_random::DummySecureRandom, dummy_supported_kx_group::DummySupportedKxGroup, hash_sha256::HashSha256, verify};

pub const DUMMY_ECDHE_SHARED_SECRET: [u8; 32] = *b"ECDHE_SHARED_SECRET\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
// 6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba
pub const DUMMY_HANDSHAKE_SECRET_IKM: [u8; 32] = *b"HANDSHAKE_SECRET_IKM\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
pub const DUMMY_MASTER_SECRET_IKM: [u8; 32] = *b"MASTER_SECRET_IKM\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
pub const DUMMY_TLS13_C_HS_TRAFFIC: [u8; 32] = *b"TLS13_C_HS_TRAFFIC\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
pub const DUMMY_TLS13_C_HS_TRAFFIC_KEY: [u8; 32] = *b"C_HS_TRAFFIC_KEY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
pub const DUMMY_TLS13_C_HS_TRAFFIC_IV: [u8; 32] = *b"C_HS_IV\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
pub const DUMMY_TLS13_S_HS_TRAFFIC: [u8; 32] = *b"TLS13_S_HS_TRAFFIC\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
pub const DUMMY_TLS13_S_HS_TRAFFIC_KEY: [u8; 32] = *b"S_HS_TRAFFIC_KEY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
pub const DUMMY_TLS13_S_HS_TRAFFIC_IV: [u8; 32] = *b"S_HS_IV\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
pub const DUMMY_TLS13_C_AP_TRAFFIC: [u8; 32] = *b"TLS13_C_AP_TRAFFIC\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
pub const DUMMY_TLS13_C_AP_TRAFFIC_KEY: [u8; 32] = *b"C_AP_TRAFFIC_KEY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
pub const DUMMY_TLS13_C_AP_TRAFFIC_IV: [u8; 32] = *b"C_AP_IV\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
pub const DUMMY_TLS13_S_AP_TRAFFIC: [u8; 32] = *b"TLS13_S_AP_TRAFFIC\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
pub const DUMMY_TLS13_S_AP_TRAFFIC_KEY: [u8; 32] = *b"S_AP_TRAFFIC_KEY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
pub const DUMMY_TLS13_S_AP_TRAFFIC_IV: [u8; 32] = *b"S_AP_IV\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
pub const DUMMY_TLS13_SERVER_FINISHED_KEY: [u8; 32] = *b"SERVER_FINISHED_KEY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
pub const DUMMY_TLS13_CLIENT_FINISHED_KEY: [u8; 32] = *b"CLIENT_FINISHED_KEY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
pub const DUMMY_TLS13_EXP_MASTER: [u8; 32] = *b"EXP_MASTER\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
pub const DUMMY_TLS13_RES_MASTER: [u8; 32] = *b"RES_MASTER\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
pub const DUMMY_TLS13_RESUMPTION_PSK: [u8; 32] = *b"RESUMPTION_PSK\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
const INFO_PREFIX_TLS13_DERIVED: [u8; 17] = *b"\x00\x20\x0D\x74\x6c\x73\x31\x33\x20\x64\x65\x72\x69\x76\x65\x64\x20";
const INFO_PREFIX_TLS13_C_HS_TRAFFIC: [u8; 22] = *b"\x00\x20\x12\x74\x6c\x73\x31\x33\x20\x63\x20\x68\x73\x20\x74\x72\x61\x66\x66\x69\x63\x20";
const INFO_PREFIX_TLS13_S_HS_TRAFFIC: [u8; 22] = *b"\x00\x20\x12\x74\x6c\x73\x31\x33\x20\x73\x20\x68\x73\x20\x74\x72\x61\x66\x66\x69\x63\x20";
const INFO_PREFIX_TLS13_C_AP_TRAFFIC: [u8; 22] = *b"\x00\x20\x12\x74\x6c\x73\x31\x33\x20\x63\x20\x61\x70\x20\x74\x72\x61\x66\x66\x69\x63\x20";
const INFO_PREFIX_TLS13_S_AP_TRAFFIC: [u8; 22] = *b"\x00\x20\x12\x74\x6c\x73\x31\x33\x20\x73\x20\x61\x70\x20\x74\x72\x61\x66\x66\x69\x63\x20";
const INFO_PREFIX_TLS13_EXP_MASTER: [u8; 20] = *b"\x00\x20\x10\x74\x6C\x73\x31\x33\x20\x65\x78\x70\x20\x6D\x61\x73\x74\x65\x72\x20";
const INFO_PREFIX_TLS13_RES_MASTER: [u8; 20] = *b"\x00\x20\x10\x74\x6C\x73\x31\x33\x20\x72\x65\x73\x20\x6D\x61\x73\x74\x65\x72\x20";
const INFO_TLS13_KEY: [u8; 13] = *b"\x00\x10\x09\x74\x6c\x73\x31\x33\x20\x6b\x65\x79\x00";
const INFO_TLS13_IV: [u8; 12] = *b"\x00\x0c\x08\x74\x6c\x73\x31\x33\x20\x69\x76\x00";
const INFO_TLS13_FINISHED: [u8; 18] = *b"\x00\x20\x0e\x74\x6c\x73\x31\x33\x20\x66\x69\x6e\x69\x73\x68\x65\x64\x00";
const INFO_TLS13_RESUMPTION: [u8; 22] = *b"\x00\x20\x10\x74\x6c\x73\x31\x33\x20\x72\x65\x73\x75\x6d\x70\x74\x69\x6f\x6e\x02\x00\x00";

pub struct DummyCryptoProvider {
    signature_verification_algorithms: WebPkiSupportedAlgorithms,
    dummy_secure_random: DummySecureRandom,
    dummy_supported_kx_groups: Vec<DummySupportedKxGroup>,
    hash_sha256: HashSha256,
    aead_aes_128_gcm: AeadAes128Gcm,
    dummy_hkdf: DummyHkdf,
    dummy_key_provider: DummyKeyProvider,
    tls13_ciphersuites: Vec<Tls13CipherSuite>,
    crypto_provider: Option<Arc<CryptoProvider>>,
}

impl DummyCryptoProvider {
    pub fn new_leak(dummy_random_data: &Arc<RwLock<Vec<u8>>>, dummy_pubkey: &Arc<Vec<u8>>) -> &'static Self {
        let mut dummy_hkdf = DummyHkdf::default();

        dummy_hkdf.add_value(DummyHkdfExpanderValue::new(
            DummyHkdfIkm::ZeroIkm { salt: None },
            &INFO_PREFIX_TLS13_DERIVED,
            &DUMMY_HANDSHAKE_SECRET_IKM,
        ));

        dummy_hkdf.add_value(DummyHkdfExpanderValue::new(
            DummyHkdfIkm::Secret {
                salt: Some(DUMMY_ECDHE_SHARED_SECRET.to_vec()),
                secret: DUMMY_HANDSHAKE_SECRET_IKM.to_vec(),
            },
            &INFO_PREFIX_TLS13_C_HS_TRAFFIC,
            &DUMMY_TLS13_C_HS_TRAFFIC,
        ));

        dummy_hkdf.add_value(DummyHkdfExpanderValue::new(
            DummyHkdfIkm::Secret {
                salt: Some(DUMMY_ECDHE_SHARED_SECRET.to_vec()),
                secret: DUMMY_HANDSHAKE_SECRET_IKM.to_vec(),
            },
            &INFO_PREFIX_TLS13_S_HS_TRAFFIC,
            &DUMMY_TLS13_S_HS_TRAFFIC,
        ));

        dummy_hkdf.add_value(DummyHkdfExpanderValue::new(
            DummyHkdfIkm::Secret {
                salt: Some(DUMMY_ECDHE_SHARED_SECRET.to_vec()),
                secret: DUMMY_HANDSHAKE_SECRET_IKM.to_vec(),
            },
            &INFO_PREFIX_TLS13_DERIVED,
            &DUMMY_MASTER_SECRET_IKM,
        ));

        dummy_hkdf.add_value(DummyHkdfExpanderValue::new(
            DummyHkdfIkm::ZeroIkm {
                salt: Some(DUMMY_MASTER_SECRET_IKM.to_vec()),
            },
            &INFO_PREFIX_TLS13_C_AP_TRAFFIC,
            &DUMMY_TLS13_C_AP_TRAFFIC,
        ));

        dummy_hkdf.add_value(DummyHkdfExpanderValue::new(
            DummyHkdfIkm::ZeroIkm {
                salt: Some(DUMMY_MASTER_SECRET_IKM.to_vec()),
            },
            &INFO_PREFIX_TLS13_S_AP_TRAFFIC,
            &DUMMY_TLS13_S_AP_TRAFFIC,
        ));

        dummy_hkdf.add_value(DummyHkdfExpanderValue::new(
            DummyHkdfIkm::ZeroIkm {
                salt: Some(DUMMY_MASTER_SECRET_IKM.to_vec()),
            },
            &INFO_PREFIX_TLS13_EXP_MASTER,
            &DUMMY_TLS13_EXP_MASTER,
        ));

        dummy_hkdf.add_value(DummyHkdfExpanderValue::new(
            DummyHkdfIkm::ZeroIkm {
                salt: Some(DUMMY_MASTER_SECRET_IKM.to_vec()),
            },
            &INFO_PREFIX_TLS13_RES_MASTER,
            &DUMMY_TLS13_RES_MASTER,
        ));

        dummy_hkdf.add_value(DummyHkdfExpanderValue::new(
            DummyHkdfIkm::Okm {
                okm: DUMMY_TLS13_C_HS_TRAFFIC.to_vec(),
            },
            &INFO_TLS13_KEY,
            &DUMMY_TLS13_C_HS_TRAFFIC_KEY,
        ));

        dummy_hkdf.add_value(DummyHkdfExpanderValue::new(
            DummyHkdfIkm::Okm {
                okm: DUMMY_TLS13_C_HS_TRAFFIC.to_vec(),
            },
            &INFO_TLS13_IV,
            &DUMMY_TLS13_C_HS_TRAFFIC_IV,
        ));

        dummy_hkdf.add_value(DummyHkdfExpanderValue::new(
            DummyHkdfIkm::Okm {
                okm: DUMMY_TLS13_S_HS_TRAFFIC.to_vec(),
            },
            &INFO_TLS13_KEY,
            &DUMMY_TLS13_S_HS_TRAFFIC_KEY,
        ));

        dummy_hkdf.add_value(DummyHkdfExpanderValue::new(
            DummyHkdfIkm::Okm {
                okm: DUMMY_TLS13_S_HS_TRAFFIC.to_vec(),
            },
            &INFO_TLS13_IV,
            &DUMMY_TLS13_S_HS_TRAFFIC_IV,
        ));

        dummy_hkdf.add_value(DummyHkdfExpanderValue::new(
            DummyHkdfIkm::Okm {
                okm: DUMMY_TLS13_C_AP_TRAFFIC.to_vec(),
            },
            &INFO_TLS13_KEY,
            &DUMMY_TLS13_C_AP_TRAFFIC_KEY,
        ));

        dummy_hkdf.add_value(DummyHkdfExpanderValue::new(
            DummyHkdfIkm::Okm {
                okm: DUMMY_TLS13_C_AP_TRAFFIC.to_vec(),
            },
            &INFO_TLS13_IV,
            &DUMMY_TLS13_C_AP_TRAFFIC_IV,
        ));

        dummy_hkdf.add_value(DummyHkdfExpanderValue::new(
            DummyHkdfIkm::Okm {
                okm: DUMMY_TLS13_S_AP_TRAFFIC.to_vec(),
            },
            &INFO_TLS13_KEY,
            &DUMMY_TLS13_S_AP_TRAFFIC_KEY,
        ));

        dummy_hkdf.add_value(DummyHkdfExpanderValue::new(
            DummyHkdfIkm::Okm {
                okm: DUMMY_TLS13_S_AP_TRAFFIC.to_vec(),
            },
            &INFO_TLS13_IV,
            &DUMMY_TLS13_S_AP_TRAFFIC_IV,
        ));

        dummy_hkdf.add_value(DummyHkdfExpanderValue::new(
            DummyHkdfIkm::Okm {
                okm: DUMMY_TLS13_S_HS_TRAFFIC.to_vec(),
            },
            &INFO_TLS13_FINISHED,
            &DUMMY_TLS13_SERVER_FINISHED_KEY,
        ));

        dummy_hkdf.add_value(DummyHkdfExpanderValue::new(
            DummyHkdfIkm::Okm {
                okm: DUMMY_TLS13_C_HS_TRAFFIC.to_vec(),
            },
            &INFO_TLS13_FINISHED,
            &DUMMY_TLS13_CLIENT_FINISHED_KEY,
        ));

        dummy_hkdf.add_value(DummyHkdfExpanderValue::new(
            DummyHkdfIkm::Okm {
                okm: DUMMY_TLS13_RES_MASTER.to_vec(),
            },
            &INFO_TLS13_RESUMPTION,
            &DUMMY_TLS13_RESUMPTION_PSK,
        ));

        let out = Box::leak(Box::new(Self {
            signature_verification_algorithms: verify::ALGORITHMS,
            dummy_secure_random: DummySecureRandom::new(dummy_random_data),
            dummy_supported_kx_groups: vec![
                DummySupportedKxGroup::new(NamedGroup::X25519, dummy_pubkey),
                DummySupportedKxGroup::new(NamedGroup::secp256r1, dummy_pubkey),
                DummySupportedKxGroup::new(NamedGroup::secp384r1, dummy_pubkey),
                DummySupportedKxGroup::new(NamedGroup::secp521r1, dummy_pubkey),
                DummySupportedKxGroup::new(NamedGroup::FFDHE2048, dummy_pubkey),
                DummySupportedKxGroup::new(NamedGroup::FFDHE3072, dummy_pubkey),
                DummySupportedKxGroup::new(NamedGroup::FFDHE4096, dummy_pubkey),
                DummySupportedKxGroup::new(NamedGroup::FFDHE6144, dummy_pubkey),
                DummySupportedKxGroup::new(NamedGroup::FFDHE8192, dummy_pubkey),
            ],
            hash_sha256: HashSha256::default(),
            dummy_hkdf,
            aead_aes_128_gcm: AeadAes128Gcm::default(),
            dummy_key_provider: DummyKeyProvider::default(),
            tls13_ciphersuites: vec![],
            crypto_provider: None,
        }));

        out.tls13_ciphersuites.push(Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                hash_provider: &out.hash_sha256,
                confidentiality_limit: 1 << 23,
                integrity_limit: 1 << 52,
            },
            hkdf_provider: &out.dummy_hkdf,
            aead_alg: &out.aead_aes_128_gcm,
            quic: None,
        });

        out.tls13_ciphersuites.push(Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                hash_provider: &out.hash_sha256,
                confidentiality_limit: 1 << 23,
                integrity_limit: 1 << 52,
            },
            hkdf_provider: &out.dummy_hkdf,
            aead_alg: &out.aead_aes_128_gcm,
            quic: None,
        });

        out.tls13_ciphersuites.push(Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
                hash_provider: &out.hash_sha256,
                confidentiality_limit: 1 << 23,
                integrity_limit: 1 << 52,
            },
            hkdf_provider: &out.dummy_hkdf,
            aead_alg: &out.aead_aes_128_gcm,
            quic: None,
        });

        out.crypto_provider = Some(Arc::new(CryptoProvider {
            cipher_suites: out.tls13_ciphersuites.iter().map(|x| SupportedCipherSuite::Tls13(x)).collect(),
            kx_groups: out.dummy_supported_kx_groups.iter().map(|x| {
                let x: &dyn SupportedKxGroup = x;
                x
            }).collect(),
            signature_verification_algorithms: out.signature_verification_algorithms,
            secure_random: &out.dummy_secure_random,
            key_provider: &out.dummy_key_provider,
        }));

        out
    }

    pub fn get_crypto_provider(&self) -> Arc<CryptoProvider> {
        Arc::clone(self.crypto_provider.as_ref().unwrap())
    }
}
