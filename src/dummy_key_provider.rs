use rustls::crypto::KeyProvider;

#[derive(Debug, Default)]
pub struct DummyKeyProvider;

impl KeyProvider for DummyKeyProvider {
    fn load_private_key(
        &self,
        _key_der: webpki::types::PrivateKeyDer<'static>,
    ) -> Result<std::sync::Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        unimplemented!()
    }
}
