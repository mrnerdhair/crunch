use std::{io::{Read, Write}, sync::{Arc, RwLock}};

use dummy_crypto_provider::DummyCryptoProvider;
use rustls::{client::Resumption, version::TLS13, ClientConfig, KeyLog, RootCertStore};

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
    
//     sha2::compress256(outer_intermediate.into(), &[block.into()]);
// }

fn main() {
    let mut root_store = RootCertStore::empty();
    root_store.extend(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned(),
    );

    let client_random = hex::decode("cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7").unwrap();
    let session_id = hex::decode("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap();
    let client_key_share = hex::decode("99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c").unwrap();

    let dummy_random_data: Vec<u8> = [client_random.into_iter(), session_id.into_iter()].into_iter().flatten().collect();
    let dummy_random_data = Arc::new(RwLock::new(dummy_random_data));

    let dummy_pubkey = Arc::new(client_key_share);
    let dummy_crypto_provider = DummyCryptoProvider::new_leak(&dummy_random_data, &dummy_pubkey);
    let mut client_config = ClientConfig::builder_with_provider(dummy_crypto_provider.get_crypto_provider())
        .with_protocol_versions(&[&TLS13]).unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    client_config.resumption = Resumption::disabled();
    client_config.alpn_protocols.push("http/1.1".as_bytes().to_vec());
    client_config.key_log = Arc::new(PrintLnKeyLog::default());

    #[cfg(debug_assertions)]
    eprintln!("{:?}", client_config);

    let rc_config = Arc::new(client_config);
    let example_com = "api.openai.com".try_into().unwrap();
    let mut client = rustls::ClientConnection::new(rc_config, example_com).expect("failed to create client connection");


    client.writer().write(b"GET / HTTP/1.0\r\n\r\n").unwrap();

    #[cfg(debug_assertions)]
    eprintln!("{:?}", client);
    assert!(!client.wants_read());
    assert!(client.wants_write());

    let mut buf = Vec::<u8>::new();
    client.write_tls(&mut buf).unwrap();

    println!("{}", hex::encode(buf));

    assert!(!client.wants_write() && client.wants_read());

    let serverhello = include_bytes!("../../crunch/serverhello.bin").to_vec();
    let mut serverhello = serverhello.as_slice();

    client.read_tls(&mut serverhello).unwrap();
    client.process_new_packets().unwrap();
    
    assert!(!client.wants_read());
    assert!(client.wants_write());

    let mut plaintext = Vec::<u8>::new();
    client.reader().read_to_end(&mut plaintext).unwrap();
    println!("{}", hex::encode(plaintext));
}
