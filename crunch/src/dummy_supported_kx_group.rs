use std::sync::Arc;

use rustls::{crypto::{ActiveKeyExchange, SupportedKxGroup}, NamedGroup};

use crate::dummy_active_key_exchange::DummyActiveKeyExchange;

#[derive(Debug)]
pub struct DummySupportedKxGroup {
    named_group: NamedGroup,
    pubkey: std::sync::Weak<Vec<u8>>,
}

impl SupportedKxGroup for DummySupportedKxGroup {
    fn name(&self) -> NamedGroup { self.named_group }

    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let pubkey = self.pubkey.upgrade().expect("DummySupportedKxGroup pubkey not available");
        Ok(Box::new(DummyActiveKeyExchange::new(self.named_group, (*pubkey).as_ref())))
    }
}

impl DummySupportedKxGroup {
    pub fn new(named_group: NamedGroup, pubkey: &Arc<Vec<u8>>) -> Self {
        Self {
            named_group,
            pubkey: Arc::downgrade(pubkey),
        }
    }
}
