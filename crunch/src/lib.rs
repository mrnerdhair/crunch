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

use std::{io::{Read, Write}, sync::{Arc, RwLock}};

use crate::dummy_crypto_provider::DummyCryptoProvider;
use rustls::{client::Resumption, version::TLS13, ClientConfig, KeyLog, RootCertStore};

use crate::dummy_server_cert_verifier::DummyServerCertVerifier;

#[derive(Debug, Default)]
struct PrintLnKeyLog;

impl KeyLog for PrintLnKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        println!("{}\t{}\t{}", label, hex::encode(client_random), hex::encode(secret));
    }
}

// #[test]
// fn test_hkdf_from_intermediates() {

// }

// const HMAC_OUTER_BLOCK_PADDING: [u8; 32] = [0x80, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0x03, 0x00];

// pub fn test_hkdf_from_intermediates(mut outer_intermediate: [u8; 32], inner: [u8; 32]) -> [u8; 32] {
//     let mut block = [0u8; 64];
//     block[..32].copy_from_slice(&inner);
//     block[32..].copy_from_slice(&HMAC_OUTER_BLOCK_PADDING);
    
//     let mut key = [
//         u32::from_be_bytes(&outer_intermediate[0..4].try_into().unwrap()),
//         u32::from_be_bytes(&outer_intermediate[4..8].try_into().unwrap()),
//         u32::from_be_bytes(&outer_intermediate[8..12].try_into().unwrap()),
//         u32::from_be_bytes(&outer_intermediate[12..16].try_into().unwrap()),
//         u32::from_be_bytes(&outer_intermediate[16..20].try_into().unwrap()),
//         u32::from_be_bytes(&outer_intermediate[20..24].try_into().unwrap()),
//         u32::from_be_bytes(&outer_intermediate[24..28].try_into().unwrap()),
//         u32::from_be_bytes(&outer_intermediate[24..32].try_into().unwrap()),
//     ];
//     sha2::compress256(&mut key, &[block.into()]);

//     outer_intermediate
// }

pub fn fake_main() {
    let client_random = hex::decode("cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7").unwrap();
    let session_id = hex::decode("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap();
    let client_key_share = hex::decode("99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c").unwrap();

    let dummy_random_data: Vec<u8> = [client_random.into_iter(), session_id.into_iter()].into_iter().flatten().collect();
    let dummy_random_data = Arc::new(RwLock::new(dummy_random_data));

    let dummy_pubkey = Arc::new(client_key_share);
    let dummy_crypto_provider = DummyCryptoProvider::new_leak(&dummy_random_data, &dummy_pubkey);
    let mut client_config = ClientConfig::builder_with_provider(dummy_crypto_provider.get_crypto_provider())
        .with_protocol_versions(&[&TLS13]).unwrap()
        .with_root_certificates(Arc::new(RootCertStore::empty()))
        .with_no_client_auth();

    client_config.resumption = Resumption::disabled();
    // client_config.alpn_protocols.push("http/1.1".as_bytes().to_vec());
    client_config.key_log = Arc::new(PrintLnKeyLog::default());
    client_config.dangerous().set_certificate_verifier(Arc::new(DummyServerCertVerifier::new(dummy_crypto_provider.get_crypto_provider())));

    let rc_config = Arc::new(client_config);
    let example_com = "server".try_into().unwrap();
    let mut client = rustls::ClientConnection::new(rc_config, example_com).expect("failed to create client connection");

    assert!(!client.wants_read());
    assert!(client.wants_write());

    let mut buf = Vec::<u8>::new();
    client.write_tls(&mut buf).unwrap();
    println!("sending: {}", hex::encode(buf));

    assert!(!client.wants_write());
    assert!(client.wants_read());

    let server_input = include_bytes!("../rfc8448_sec3_02_serverhello.bin").to_vec();
    let mut server_input = server_input.as_slice();
    client.read_tls(&mut server_input).unwrap();
    client.process_new_packets().unwrap();
    
    assert!(!client.wants_read());
    assert!(client.wants_write());

    let mut buf = Vec::<u8>::new();
    client.write_tls(&mut buf).unwrap();
    println!("sending: {}", hex::encode(buf));

    assert!(!client.wants_write());
    assert!(client.wants_read());

    let server_input = include_bytes!("../rfc8448_sec3_03_serverhandshake.bin").to_vec();
    let mut server_input = server_input.as_slice();
    client.read_tls(&mut server_input).unwrap();
    client.process_new_packets().unwrap();

    assert!(client.wants_write());
    // assert!(!client.wants_read());

    let mut buf = Vec::<u8>::new();
    client.write_tls(&mut buf).unwrap();
    println!("sending: {}", hex::encode(buf));

    assert!(!client.wants_write());
    assert!(client.wants_read());

    let server_input = include_bytes!("../rfc8448_sec3_05_serverhandshake2.bin").to_vec();
    let mut server_input = server_input.as_slice();
    client.read_tls(&mut server_input).unwrap();
    client.process_new_packets().unwrap();

    let mut out = [0u8; 50];
    for i in 0..50 { out[i] = i as u8 }
    client.writer().write(&out).unwrap();

    assert!(client.wants_write());
    // assert!(!client.wants_read());

    let mut buf = Vec::<u8>::new();
    client.write_tls(&mut buf).unwrap();
    println!("sending: {}", hex::encode(buf));

    assert!(!client.wants_write());
    // assert!(client.wants_read());

    let server_input = include_bytes!("../rfc8448_sec3_07_serverappdata.bin").to_vec();
    let mut server_input = server_input.as_slice();
    client.read_tls(&mut server_input).unwrap();
    client.process_new_packets().unwrap();

    client.send_close_notify();

    assert!(client.wants_write());
    let mut buf = Vec::<u8>::new();
    client.write_tls(&mut buf).unwrap();
    println!("sending: {}", hex::encode(buf));
    assert!(!client.wants_write());

    let server_input = include_bytes!("../rfc8448_sec3_09_serveralert.bin").to_vec();
    let mut server_input = server_input.as_slice();
    client.read_tls(&mut server_input).unwrap();
    client.process_new_packets().unwrap();

    assert!(!client.wants_read());
    assert!(!client.wants_write());

    let mut plaintext = Vec::<u8>::new();
    client.reader().read_to_end(&mut plaintext).unwrap();
    println!("received: {}", hex::encode(plaintext));
}
