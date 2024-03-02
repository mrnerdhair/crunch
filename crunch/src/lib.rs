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

use std::{io::{Read, Write}, sync::{Arc, OnceLock, RwLock}};

use crate::{dummy_crypto_provider::{DummyCryptoProvider, DummyCryptoProviderParams, DummyKeys, DUMMY_ECDHE_SHARED_SECRET}, dummy_server_cert_verifier::ServerCertReport};
use rustls::{client::Resumption, version::TLS13, ClientConfig, KeyLog, RootCertStore};
use webpki::types::ServerName;
use serde::{Serialize, Deserialize};

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
    client_request: &'a [u8],
    inputs: &'a [Message<'a>],
    #[cfg(not(feature = "uncrunch"))]
    dummy_keys: Arc<DummyKeys>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrunchOutput {
    pub server_response: Vec<u8>,
    pub server_cert_report: ServerCertReport,
}

pub fn fake_main() -> CrunchOutput {
    let client_random = hex::decode("cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7").unwrap();
    let client_key_share = hex::decode("99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c").unwrap();

    let mut client_request = [0u8; 50];
    for i in 0..50 { client_request[i] = i as u8 }
    let client_request = client_request.as_slice();

    #[cfg(not(feature = "uncrunch"))]
    let dummy_keys = Arc::new(DummyKeys::default());

    #[cfg(not(feature = "uncrunch"))]
    {
        dummy_keys.server_finished_key.set(hex::decode("9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718").unwrap()).unwrap();
        dummy_keys.client_finished_key.set(hex::decode("a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61").unwrap()).unwrap();

        dummy_keys.client_hs_traffic_key.set(hex::decode("dbfaa693d1762c5b666af5d950258d01").unwrap()).unwrap();
        dummy_keys.server_hs_traffic_key.set(hex::decode("3fce516009c21727d0f2e4e86ee403bc").unwrap()).unwrap();
        dummy_keys.client_ap_traffic_key.set(hex::decode("17422dda596ed5d9acd890e3c63f5051").unwrap()).unwrap();
        dummy_keys.server_ap_traffic_key.set(hex::decode("9f02283b6c9c07efc26bb9f2ac92e356").unwrap()).unwrap();

        dummy_keys.client_hs_traffic_iv.set(hex::decode("5bd3c71b836e0b76bb73265f").unwrap()).unwrap();
        dummy_keys.server_hs_traffic_iv.set(hex::decode("5d313eb2671276ee13000b30").unwrap()).unwrap();
        dummy_keys.client_ap_traffic_iv.set(hex::decode("5b78923dee08579033e523d9").unwrap()).unwrap();
        dummy_keys.server_ap_traffic_iv.set(hex::decode("cf782b88dd83549aadf1e984").unwrap()).unwrap();
    }

    let out = crunch(CrunchParams {
        server_name: "server".to_string(),
        client_random: client_random.try_into().unwrap(),
        client_key_share: client_key_share.try_into().unwrap(),
        client_request: &client_request,
        #[cfg(feature = "uncrunch")]
        shared_secret: hex::decode("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d").unwrap().try_into().unwrap(),
        inputs: &[
            Message::Client(include_bytes!("../rfc8448_sec3_01_clienthello.bin")),
            Message::Server(include_bytes!("../rfc8448_sec3_02b_serverfull.bin")),
            Message::Client(include_bytes!("../rfc8448_sec3_04_clienthandshake.bin")),
            Message::Server(include_bytes!("../rfc8448_sec3_05_serverhandshake2.bin")),
            Message::Client(include_bytes!("../rfc8448_sec3_06b_clientfull.bin")),
            Message::Server(include_bytes!("../rfc8448_sec3_07b_serverfull.bin")),
        ],
        #[cfg(not(feature = "uncrunch"))]
        dummy_keys,
    });

    println!("{:?}", out);

    out
}

pub fn crunch(params: CrunchParams) -> CrunchOutput {
    // let dummy_random_data: Vec<u8> = [client_random.into_iter(), session_id.into_iter()].into_iter().flatten().collect();
    let dummy_random_data: Vec<u8> = [params.client_random.into_iter()].into_iter().flatten().collect();
    let dummy_random_data = Arc::new(RwLock::new(dummy_random_data));

    let dummy_pubkey = Arc::new(params.client_key_share.to_vec());

    let dummy_crypto_provider = DummyCryptoProvider::new_leak(DummyCryptoProviderParams {
        dummy_random_data,
        dummy_pubkey,
        #[cfg(feature = "uncrunch")]
        shared_secret: params.shared_secret.to_vec(),
        #[cfg(not(feature = "uncrunch"))]
        shared_secret: DUMMY_ECDHE_SHARED_SECRET.to_vec(),
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
        client_config.key_log = Arc::new(PrintLnKeyLog::default());
    }

    let server_cert_reporter: Arc<OnceLock<ServerCertReport>> = Arc::new(OnceLock::<ServerCertReport>::new());
    client_config.dangerous().set_certificate_verifier(Arc::new(DummyServerCertVerifier::new(dummy_crypto_provider.get_crypto_provider(), Arc::clone(&server_cert_reporter))));

    let rc_config = Arc::new(client_config);
    let server_name: ServerName = params.server_name.try_into().unwrap();
    let mut client = rustls::ClientConnection::new(rc_config, server_name).expect("failed to create client connection");

    let mut sent_appdata = false;
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
                if &buf != x {
                    panic!("expected to send {}, but sent {} instead", hex::encode(x), hex::encode(buf));
                }
            },
            Message::Server(mut x) => {
                client.read_tls(&mut x).expect("read_tls failed");
                client.process_new_packets().expect("process_new_packets failed");
            },
        }
    }

    assert!(!client.wants_write());
    assert!(!client.wants_read());

    let mut plaintext = Vec::<u8>::new();
    client.reader().read_to_end(&mut plaintext).unwrap();

    CrunchOutput {
        server_cert_report: server_cert_reporter.get().unwrap().clone(),
        server_response: plaintext,
    }
}
