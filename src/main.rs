use std::env;

use aes_gcm::{AeadInPlace, Aes128Gcm, KeyInit};
use sha2::{Sha256, Digest};
use tls_parser::{parse_tls_encrypted, parse_tls_plaintext, parse_tls_record_with_header, TlsExtension, TlsMessage, TlsRecordHeader, TlsRecordType, TlsVersion};

#[cfg(debug_assertions)]
fn build_dummy_clienthello(hasher: Option<&mut Sha256>) -> Vec<u8> {
    let client_hello: Vec<u8> = include_bytes!("../clienthello.bin").to_vec();

    if let Some(hasher) = hasher {
        hasher.update(&client_hello[5..])
    }

    client_hello
}

fn build_clienthello(client_random: [u8; 32], client_keyshare: [u8; 32], servername: &str, hasher: Option<&mut Sha256>) -> Vec<u8> {
    let servername_len: u16 = servername.as_bytes().len().try_into().expect("servername too long");
    assert!(servername_len < u16::MAX - 5);
    let padding_len: u16 = (77+33-15) - servername_len;

    let parts = vec![
        hex::decode("16030300fb010000f70303").unwrap(),
        client_random.to_vec(),
        hex::decode("0000021301010000cc000a00040002001d003300260024001d0020").unwrap(),
        client_keyshare.to_vec(),
        hex::decode("002b0003020304000d001400120403050306030804080508060401050106010000").unwrap(),
        (servername_len + 5).to_be_bytes().to_vec(),
        (servername_len + 3).to_be_bytes().to_vec(),
        vec![0x00u8; 1],
        servername_len.to_be_bytes().to_vec(),
        servername.as_bytes().to_vec(),
        hex::decode("0010000b000908687474702f312e31").unwrap(),
        hex::decode("0015").unwrap(),
        padding_len.to_be_bytes().to_vec(),
        vec![0x00u8; padding_len as usize],
    ];

    let client_hello: Vec<u8> = parts.into_iter().flatten().collect();

    if let Some(hasher) = hasher {
        hasher.update(&client_hello[5..])
    }

    client_hello
}

#[test]
fn test_clienthello() {
    let client_random: [u8; 32] = hex::decode("cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7").unwrap().try_into().unwrap();
    let client_keyshare: [u8; 32] = hex::decode("99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c").unwrap().try_into().unwrap();
    let servername = "api.openai.com";

    let client_hello = build_clienthello(client_random, client_keyshare, servername, None);

    assert_eq!(client_hello.len(), 256);

    println!("{}", client_hello.len());
    println!("{}", hex::encode(&client_hello));

    let parsed = tls_parser::parse_tls_plaintext(&client_hello).expect("bad clienthello");
    assert_eq!(0, parsed.0.len());
    let parsed = parsed.1;


    println!("{:?}", parsed);

    assert_eq!(parsed.hdr.record_type, tls_parser::TlsRecordType::Handshake);
    assert_eq!(parsed.msg.len(), 1);
    let parsed = &parsed.msg[0];

    assert!(matches!(parsed, tls_parser::TlsMessage::Handshake(tls_parser::TlsMessageHandshake::ClientHello(_))));
    if let tls_parser::TlsMessage::Handshake(tls_parser::TlsMessageHandshake::ClientHello(contents)) = parsed {
        println!("{:?}", contents);
        assert!(matches!(contents.ext, Some(_)));
        let extensions = tls_parser::parse_tls_extensions(contents.ext.unwrap()).expect("unparsable extensions");
        assert_eq!(0, extensions.0.len());
        let extensions = extensions.1;
        println!("{:?}", extensions);
    }
}

fn do_mpc_setup() -> [u8; 32] {
    let client_keyshare: [u8; 32] = hex::decode("99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c").unwrap().try_into().unwrap();

    return client_keyshare
}

struct MpcHandshakeKeys {
    server_hs_traffic_key: aes_gcm::Key<Aes128Gcm>,
    server_hs_traffic_iv: aes_gcm::Nonce<typenum::U12>,
    client_hs_traffic_key: aes_gcm::Key<Aes128Gcm>,
    client_hs_traffic_iv: aes_gcm::Nonce<typenum::U12>,
}

// todo
fn do_mpc_keyschedule(keyshare: [u8; 32]) -> MpcHandshakeKeys {
    let server_hs_traffic_key: [u8; 16] = hex::decode("3fce516009c21727d0f2e4e86ee403bc").unwrap().try_into().unwrap();
    let server_hs_traffic_iv: [u8; 12] = hex::decode("5d313eb2671276ee13000b30").unwrap().try_into().unwrap();
    let client_hs_traffic_key: [u8; 16] = hex::decode("b1530806f4adfeac83f1413032bbfa82").unwrap().try_into().unwrap();
    let client_hs_traffic_iv: [u8; 12] = hex::decode("eb50c16be7654abf99dd06d9").unwrap().try_into().unwrap();

    MpcHandshakeKeys {
        server_hs_traffic_key: server_hs_traffic_key.into(),
        server_hs_traffic_iv: server_hs_traffic_iv.into(),
        client_hs_traffic_key: client_hs_traffic_key.into(),
        client_hs_traffic_iv: client_hs_traffic_iv.into(),
    }
}

#[test]
fn test_serverhello() {
    let mut hasher = Sha256::new();
    let (extra, keyshare) = parse_server_hello(include_bytes!("../serverhello.bin"), Some(&mut hasher));
    println!("{}", hex::encode(extra));
    println!("{}", hex::encode(keyshare));
}

#[test]
fn test_hashing() {
    let mut hasher = Sha256::new();

    let _ = build_dummy_clienthello(Some(&mut hasher));
    let (_, _) = parse_server_hello(include_bytes!("../serverhello2.bin"), Some(&mut hasher));

    let transcript_hash = hasher.clone().finalize().to_vec();

    assert_eq!("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8", hex::encode(transcript_hash));
}

fn build_iv(mut iv: [u8; 12], ctr: u64) -> [u8; 12] {
    let mut foo = [0u8; 12];
    (&mut foo[4..]).clone_from_slice(&ctr.to_be_bytes());
    
    for i in 0..iv.len() { iv[i] = iv[i] ^ foo[i]; }
    iv
}

#[test]
fn foo() {
    let input = include_bytes!("../server_handshake_records.bin").to_vec();

    let mut more: &[u8] = &input;
    let mut seq_num: u64 = 0;
    let mut recs = Vec::<(u8, Vec::<u8>)>::new();

    while more.len() > 0 {
        let (next_more, rec) = parse_tls_encrypted(&more).unwrap();

        let authdata = &more[0..5];

        let keys = do_mpc_keyschedule([0; 32]);
        let mut rec_blob = rec.msg.blob.to_vec();
        let nonce = build_iv(keys.server_hs_traffic_iv.into(), seq_num);

        Aes128Gcm::new(&keys.server_hs_traffic_key).decrypt_in_place(&nonce.into(), authdata, &mut rec_blob).expect("decrypt failed");

        while let Some(0) = rec_blob.last() {
            rec_blob.pop();
        }

        let record_type = rec_blob.pop().expect("expected plaintext to contain a record type");

        let synthetic_hdr = TlsRecordHeader {
            record_type: TlsRecordType(record_type),
            version: TlsVersion(0x0304),
            len: rec_blob.len().try_into().unwrap(),
        };

        println!("{:?}", synthetic_hdr);

        // let foo = parse_tls_record_with_header(&rec_blob, &synthetic_hdr).unwrap();
        // println!("{:?}", foo);

        recs.push((record_type, rec_blob));

        seq_num = seq_num + 1;
        more = next_more;
    }

    for rec in recs.iter() {
        println!("{:?}", rec);
    }
}

fn parse_server_hello(server_input: &[u8], hasher: Option<&mut Sha256>) -> (Vec<u8>, [u8; 32]) {
    let (extra, parsed) = tls_parser::parse_tls_plaintext(server_input).unwrap();
    println!("{:?}", parsed);

    if let Some(hasher) = hasher {
        let msg_only = &server_input[5..server_input.len() - extra.len()];
        println!("{}", hex::encode(msg_only));
        hasher.update(msg_only)
    }

    assert_eq!(parsed.hdr.record_type, tls_parser::TlsRecordType::Handshake);
    assert_eq!(parsed.msg.len(), 1);
    let parsed = &parsed.msg[0];

    assert!(matches!(parsed, tls_parser::TlsMessage::Handshake(tls_parser::TlsMessageHandshake::ServerHello(_))));
    if let tls_parser::TlsMessage::Handshake(tls_parser::TlsMessageHandshake::ServerHello(contents)) = parsed {
        println!("{:?}", contents);
        assert!(matches!(contents.ext, Some(_)));
        let extensions = tls_parser::parse_tls_extensions(contents.ext.unwrap()).expect("unparsable extensions");
        assert_eq!(0, extensions.0.len());
        let extensions = extensions.1;
        println!("{:?}", extensions);

        // let version_nego_ok = extensions.iter().fold(false, |a, x| a | matches!(x, TlsExtension::SupportedVersions(["Tls13"])));
        // assert!(version_nego_ok);

        let server_keyshare = extensions.iter().fold(None, |a, x| a.or_else(|| {
            if let TlsExtension::KeyShare(x) = x {
                assert_eq!(0x0024, x.len());
                assert_eq!(0x001d, u16::from_be_bytes(x[0..2].try_into().unwrap()));
                assert_eq!(0x0020, u16::from_be_bytes(x[2..4].try_into().unwrap()));
                let x: [u8; 32] = x[4..].try_into().unwrap();
                Some(x)
            } else { None }
        })).expect("missing server keyshare");


        return (extra.to_vec(), server_keyshare)
    } else {
        unreachable!();
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let servername = &args[1];
    let client_random: [u8; 32] = hex::decode("cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7").unwrap().try_into().unwrap();

    let mut transcript_hasher = Sha256::new();

    let client_keyshare= do_mpc_setup();
    let clienthello = build_clienthello(client_random, client_keyshare, servername, Some(&mut transcript_hasher));

    println!("{}", base64::encode(&clienthello));
}
