#![allow(unused_imports, dead_code, unused_variables, unused_mut)]

mod dummy_hkdf_expander;
mod dummy_hkdf;
mod dummy_supported_kx_group;
mod dummy_active_key_exchange;
mod dummy_crypto_provider;
mod hmac_sha256;
mod aead_aes_128_gcm;
mod hash_sha256;
mod verify;
mod dummy_secure_random;
mod dummy_key_provider;
mod dummy_server_cert_verifier;
mod println_key_log;
mod hash_reporter;
mod hdkf_from_intermediates;

use std::{io::{Read, Write}, sync::{Arc, OnceLock, RwLock}};

use crate::{dummy_crypto_provider::{DummyCryptoProvider, DummyCryptoProviderParams, DummyKeys, DUMMY_ECDHE_SHARED_SECRET, INFO_TLS13_IV, INFO_TLS13_KEY}, dummy_server_cert_verifier::ServerCertReport, hdkf_from_intermediates::hkdf_from_intermediates};
use hash_reporter::{HashReporter, HashReporters};
use rustls::{client::Resumption, quic, version::TLS13, ClientConfig, KeyLog, RootCertStore};
use sha2::{Digest, Sha256};
use webpki::types::ServerName;
use serde::{Serialize, Deserialize};

use crate::dummy_server_cert_verifier::DummyServerCertVerifier;

#[derive(Debug)]
pub enum Message<'a> {
    Client(&'a [u8]),
    Server(&'a [u8]),
}

#[derive(Debug)]
pub struct CrunchParams<'a> {
    server_name: String,
    client_random: [u8; 32],
    client_key_share: [u8; 32],
    #[cfg(feature = "uncrunch")]
    shared_secret: [u8; 32],
    #[cfg(feature = "uncrunch")]
    transcript_commitment: [u8; 32],
    client_request: &'a [u8],
    inputs: &'a [Message<'a>],
    #[cfg(not(feature = "uncrunch"))]
    dummy_keys: Arc<DummyKeys>,

    hash_reporters: HashReporters,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrunchOutput {
    pub server_response: Vec<u8>,
    pub server_cert_report: ServerCertReport,
    pub transcript_commitment: [u8; 32],
}

pub fn fake_main() -> CrunchOutput {
    #[cfg(not(feature = "uncrunch"))]
    let out = crunch_fake_main();
    #[cfg(feature = "uncrunch")]
    let out = uncrunch_fake_main();

    println!("{:?}", out);

    out
}

#[derive(Clone)]
struct Mpc(Arc<RwLock<Box<dyn Iterator<Item = Vec<u8>> + Send + Sync>>>);

impl Mpc {
    pub fn send(&self, input: &[u8]) -> Vec<u8> {
        self.0.write().unwrap().next().unwrap()
    }
}

fn fake_mpc() -> Mpc {
    Mpc(Arc::new(RwLock::new(Box::new([
        "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c", // client_key_share
        "2dde0fbb235022bd7d4af6a25f93247c046021696a6f5005bbd4bc40de2dd147", // tls_handshake_secret_derived_hmac_outer_intermediate
        "6faab530a4b8341ee76913cd3b134619ce21dc59760b71b307bba9e606ba6256", // tls_c_hs_traffic_secret_hmac_inner
        "3e1a86769f8437b19038add13882a97595558fe0f022e6c988fc6506326ab50a", // tls_s_hs_traffic_secret_hmac_inner
        "a23f7054b62c94d0affafe8228ba55cb",                                 // request_ciphertext
        "efacea42f914aa66bcab3f2b9819a8a5",                                 // request_ciphertext
        "b46b395bd54a9a20441e2b62974e1f5a",                                 // request_ciphertext
        "6292a200000000000000000000000000",                                 // request_ciphertext
        "977014bd1e3deae63aeebb21694915e4",                                 // auth_tag
        "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d", // shared_secret
        "e24733da83f6dc4996a0b92588083d8c18a22a82caba4aeb95ebac9e2df386b7", // transcript_commitment
    ].into_iter().map(|x| {
        hex::decode(x).unwrap()
    })))))
}

#[cfg(not(feature = "uncrunch"))]
fn make_ch_sh_hash_handler(dummy_keys: Arc<DummyKeys>, mpc: Mpc) -> impl FnOnce([u8; 32]) + 'static {
    move |ch_sh_transcript_hash| {
        println!("ch_sh_transcript_hash: {}", hex::encode(ch_sh_transcript_hash));

        let tls_handshake_secret_derived_hmac_outer_intermediate: [u8; 32] = mpc.send(&ch_sh_transcript_hash).try_into().unwrap();
        let tls_c_hs_traffic_secret_hmac_inner: [u8; 32] = mpc.send(&[]).try_into().unwrap();
        let tls_s_hs_traffic_secret_hmac_inner: [u8; 32] = mpc.send(&[]).try_into().unwrap();   

        dummy_keys.set_c_hs_secret(hkdf_from_intermediates(
            tls_handshake_secret_derived_hmac_outer_intermediate,
            tls_c_hs_traffic_secret_hmac_inner,
        ));

        dummy_keys.set_s_hs_secret(hkdf_from_intermediates(
            tls_handshake_secret_derived_hmac_outer_intermediate,
            tls_s_hs_traffic_secret_hmac_inner,
        ));
    }
}

#[cfg(not(feature = "uncrunch"))]
fn make_ch_sf_hash_handler(dummy_keys: Arc<DummyKeys>, mpc: Mpc) -> impl FnOnce([u8; 32]) + 'static {
    move |ch_sf_transcript_hash| {
        println!("ch_sf_transcript_hash: {}", hex::encode(ch_sf_transcript_hash));

        mpc.send(&ch_sf_transcript_hash);

        // let tls_master_secret_derived_hmac_outer_intermediate: [u8; 32] = mpc.send(&ch_sf_transcript_hash).try_into().unwrap();
        // let tls_c_ap_traffic_secret_hmac_inner: [u8; 32] = mpc.send().try_into().unwrap();

        let tls_master_secret_derived_hmac_outer_intermediate: [u8; 32] = hex::decode("635cd997c687b153a1e078d0cbfc124299f495ce2b0bec644b690bdd2c732ea1").unwrap().try_into().unwrap();
        let tls_c_ap_traffic_secret_hmac_inner: [u8; 32] = hex::decode("3b57774842c2cec88a41b7437d9eab64ae5965d8b39e7fb569b5d050da628527").unwrap().try_into().unwrap();
    
        dummy_keys.set_c_ap_secret(hkdf_from_intermediates(
            tls_master_secret_derived_hmac_outer_intermediate,
            tls_c_ap_traffic_secret_hmac_inner,
        ));

        dummy_keys.server_ap_traffic_key.set(hex::decode("9f02283b6c9c07efc26bb9f2ac92e356").unwrap()).unwrap();
        dummy_keys.server_ap_traffic_iv.set(hex::decode("cf782b88dd83549aadf1e984").unwrap()).unwrap();
    }
}

#[cfg(not(feature = "uncrunch"))]
pub fn crunch_fake_main() -> CrunchOutput {
    let mpc = fake_mpc();

    let server_name = "server";
    let client_random = hex::decode("cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7").unwrap();
    let client_request = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031").unwrap();

    let client_key_share: [u8; 32] = mpc.send(&[]).try_into().unwrap();

    let dummy_keys = Arc::new(DummyKeys::default());

    let ch_sh_transcript_hash_reporter = HashReporter::new(make_ch_sh_hash_handler(Arc::clone(&dummy_keys), mpc.clone()));
    let ch_sf_transcript_hash_reporter = HashReporter::new(make_ch_sf_hash_handler(Arc::clone(&dummy_keys), mpc.clone()));

    crunch(CrunchParams {
        server_name: server_name.to_string(),
        client_random: client_random.try_into().unwrap(),
        client_key_share,
        client_request: &client_request,
        dummy_keys,
        inputs: &[
            Message::Client(include_bytes!("../rfc8448_sec3_01_clienthello.bin")),
            Message::Server(include_bytes!("../rfc8448_sec3_02b_serverfull.bin")),
            Message::Client(include_bytes!("../rfc8448_sec3_04_clienthandshake.bin")),
            Message::Server(include_bytes!("../rfc8448_sec3_05_serverhandshake2.bin")),
            Message::Client(include_bytes!("../rfc8448_sec3_06b_clientfull.bin")),
            Message::Server(include_bytes!("../rfc8448_sec3_07b_serverfull.bin")),
        ],
        hash_reporters: HashReporters::new(ch_sh_transcript_hash_reporter, ch_sf_transcript_hash_reporter),
    })
}

#[cfg(feature = "uncrunch")]
pub fn uncrunch_fake_main() -> CrunchOutput {
    let server_name = "server";
    let client_random = hex::decode("cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7").unwrap();
    let client_request = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031").unwrap();

    let client_key_share = hex::decode("99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c").unwrap();
    let shared_secret: [u8; 32] = hex::decode("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d").unwrap().try_into().unwrap();
    let transcript_commitment: [u8; 32] = hex::decode("e24733da83f6dc4996a0b92588083d8c18a22a82caba4aeb95ebac9e2df386b7").unwrap().try_into().unwrap();

    crunch(CrunchParams {
        server_name: server_name.to_string(),
        client_random: client_random.try_into().unwrap(),
        client_key_share: client_key_share.try_into().unwrap(),
        client_request: &client_request,
        shared_secret,
        transcript_commitment,
        inputs: &[
            Message::Client(include_bytes!("../rfc8448_sec3_01_clienthello.bin")),
            Message::Server(include_bytes!("../rfc8448_sec3_02b_serverfull.bin")),
            Message::Client(include_bytes!("../rfc8448_sec3_04_clienthandshake.bin")),
            Message::Server(include_bytes!("../rfc8448_sec3_05_serverhandshake2.bin")),
            Message::Client(include_bytes!("../rfc8448_sec3_06b_clientfull.bin")),
            Message::Server(include_bytes!("../rfc8448_sec3_07b_serverfull.bin")),
        ],
        hash_reporters: HashReporters::default(),
    })
}

pub fn crunch(params: CrunchParams) -> CrunchOutput {
    let dummy_random_data: Vec<u8> = [params.client_random.into_iter()].into_iter().flatten().collect();
    let dummy_random_data = Arc::new(RwLock::new(dummy_random_data));

    let dummy_pubkey = Arc::new(params.client_key_share.to_vec());

    let dummy_crypto_provider = DummyCryptoProvider::new_leak(DummyCryptoProviderParams {
        dummy_random_data,
        dummy_pubkey,
        hash_reporters: params.hash_reporters,
        #[cfg(feature = "uncrunch")]
        shared_secret: params.shared_secret.to_vec(),
        #[cfg(not(feature = "uncrunch"))]
        dummy_keys: Arc::clone(&params.dummy_keys),
    });

    let mut client_config = ClientConfig::builder_with_provider(dummy_crypto_provider.get_crypto_provider())
        .with_protocol_versions(&[&TLS13]).unwrap()
        .with_root_certificates(Arc::new(RootCertStore::empty()))
        .with_no_client_auth();

    client_config.resumption = Resumption::disabled();
    #[cfg(not(feature = "rfc8448"))]
    client_config.alpn_protocols.push("http/1.1".as_bytes().to_vec());

    #[cfg(feature = "uncrunch")]
    {
        client_config.key_log = Arc::new(println_key_log::PrintLnKeyLog::default());
    }

    let server_cert_reporter: Arc<OnceLock<ServerCertReport>> = Arc::new(OnceLock::<ServerCertReport>::new());
    client_config.dangerous().set_certificate_verifier(Arc::new(DummyServerCertVerifier::new(dummy_crypto_provider.get_crypto_provider(), Arc::clone(&server_cert_reporter))));

    let rc_config = Arc::new(client_config);
    let server_name: ServerName = params.server_name.try_into().unwrap();
    let mut client = rustls::ClientConnection::new(rc_config, server_name).expect("failed to create client connection");

    let mut sent_appdata = false;
    let mut transcript_commitment = Sha256::new();
    for input in params.inputs.iter() {
        if !client.is_handshaking() && !client.wants_write() && !sent_appdata {
            sent_appdata = true;
            client.writer().write(params.client_request).unwrap();
            client.send_close_notify();
        }
        match input {
            Message::Client(x) => {
                let mut buf = Vec::<u8>::new();
                client.write_tls(&mut buf).unwrap();
                transcript_commitment.update(&buf);
                if &buf != x {
                    panic!("expected to send {}, but sent {} instead", hex::encode(x), hex::encode(buf));
                }
            },
            Message::Server(mut x) => {
                transcript_commitment.update(&x);
                client.read_tls(&mut x).expect("read_tls failed");
                client.process_new_packets().expect("process_new_packets failed");
            },
        }
    }

    assert!(!client.wants_write());
    assert!(!client.wants_read());

    let mut plaintext = Vec::<u8>::new();
    client.reader().read_to_end(&mut plaintext).unwrap();

    let transcript_commitment: [u8; 32] = transcript_commitment.finalize().into();

    #[cfg(feature = "uncrunch")]
    assert_eq!(params.transcript_commitment, transcript_commitment);

    CrunchOutput {
        server_cert_report: server_cert_reporter.get().unwrap().clone(),
        server_response: plaintext,
        transcript_commitment,
    }
}
