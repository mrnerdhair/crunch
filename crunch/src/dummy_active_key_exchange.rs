use rustls::{crypto::{ActiveKeyExchange, SharedSecret}, NamedGroup};
use zeroize::Zeroize;

#[derive(Zeroize)]
pub struct DummyActiveKeyExchange {
    #[zeroize(skip)]
    named_group: NamedGroup,
    pubkey: Vec<u8>,
}

impl ActiveKeyExchange for DummyActiveKeyExchange {
    fn group(&self) -> NamedGroup { self.named_group }
    fn pub_key(&self) -> &[u8] { &self.pubkey }
    fn complete(self: Box<Self>, _peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
        panic!("DummyActiveKeyExchange can't actually complete key exchange")
    }
}

impl DummyActiveKeyExchange {
    pub fn new(named_group: NamedGroup, pubkey: &[u8]) -> Self {
        Self {
            named_group,
            pubkey: pubkey.to_vec(),
        }
    }
}
