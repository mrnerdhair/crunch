use std::sync::Arc;

use rustls::{client::{danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier}, WebPkiServerVerifier}, crypto::CryptoProvider, RootCertStore};

#[derive(Debug)]
pub struct DummyServerCertVerifier {
    verifier: Arc<WebPkiServerVerifier>,
}

impl DummyServerCertVerifier {
    pub fn new(provider: Arc<CryptoProvider>) -> Self {
        let mut root_store = RootCertStore::empty();
        root_store.extend(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned(),
        );

        Self {
            verifier: WebPkiServerVerifier::builder_with_provider(Arc::new(root_store), provider).build().unwrap(),
        }
    }
}

impl ServerCertVerifier for DummyServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &webpki::types::CertificateDer<'_>,
        _intermediates: &[webpki::types::CertificateDer<'_>],
        server_name: &webpki::types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: webpki::types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        println!("Server cert: {:?} {:?}", server_name, end_entity);
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
        self.verifier.verify_tls13_signature(message, cert, dss).or_else(|_| {
            println!("bad server cert signature; still proceeding");
            Ok(HandshakeSignatureValid::assertion())
        })
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}