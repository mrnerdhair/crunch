use std::sync::{Arc, OnceLock};

use rustls::{client::{danger::{ServerCertVerified, ServerCertVerifier}, WebPkiServerVerifier}, crypto::CryptoProvider, RootCertStore};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCertReport {
    pub end_entity: Vec<u8>,
    pub intermediates: Vec<Vec<u8>>,
    pub server_name: String,
    pub ocsp_response: Vec<u8>,
    pub now: u64,
}

#[derive(Debug)]
pub struct DummyServerCertVerifier {
    verifier: Arc<WebPkiServerVerifier>,
    reporter: Arc<OnceLock<ServerCertReport>>,
}

impl<'a> DummyServerCertVerifier {
    pub fn new(provider: Arc<CryptoProvider>, reporter: Arc<OnceLock<ServerCertReport>>) -> Self {
        let mut root_store = RootCertStore::empty();
        root_store.extend(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned(),
        );

        Self {
            verifier: WebPkiServerVerifier::builder_with_provider(Arc::new(root_store), provider).build().unwrap(),
            reporter,
        }
    }
}

impl ServerCertVerifier for DummyServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &webpki::types::CertificateDer<'_>,
        intermediates: &[webpki::types::CertificateDer<'_>],
        server_name: &webpki::types::ServerName<'_>,
        ocsp_response: &[u8],
        now: webpki::types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.reporter.set(ServerCertReport {
            end_entity: end_entity.to_vec(),
            intermediates: intermediates.iter().map(|x| x.to_vec()).collect(),
            server_name: server_name.to_str().to_string(),
            ocsp_response: ocsp_response.to_owned(),
            now: now.as_secs(),
        }).expect("unable to report server certificate");
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &webpki::types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.verifier.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &webpki::types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.verifier.verify_tls13_signature(message, cert, dss)/*.or_else(|_| {
            println!("bad server cert signature; still proceeding");
            Ok(HandshakeSignatureValid::assertion())
        })*/
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}