use std::sync::{Arc, RwLock};

use dummy_crypto_provider::get_dummy_crypto_provider;
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

fn main() {
    let mut root_store = RootCertStore::empty();
    root_store.extend(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned(),
    );

    let dummy_random_data = Arc::new(RwLock::new(hex::decode("cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece799381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c").unwrap()));
    let dummy_pubkey = Arc::new(hex::decode("99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c").unwrap());
    let dummy_crypto_provider = Arc::new(get_dummy_crypto_provider(&dummy_random_data, &dummy_pubkey));
    let mut client_config = ClientConfig::builder_with_provider(dummy_crypto_provider)
        .with_protocol_versions(&[&TLS13]).unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    client_config.resumption = Resumption::disabled();
    client_config.alpn_protocols.push("http/1.1".as_bytes().to_vec());
    client_config.key_log = Arc::new(PrintLnKeyLog::default());

    println!("{:?}", client_config);

    let rc_config = Arc::new(client_config);
    let example_com = "api.openai.com".try_into().unwrap();
    let mut client = rustls::ClientConnection::new(rc_config, example_com).expect("failed to create client connection");

    println!("{:?}", client);
}
