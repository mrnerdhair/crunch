use std::{ops::DerefMut, sync::{Arc, RwLock}};

use rustls::crypto::{GetRandomFailed, SecureRandom};

#[derive(Debug)]
pub struct DummySecureRandom {
    data: std::sync::Weak<RwLock<Vec<u8>>>,
}

impl SecureRandom for DummySecureRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        let data = self.data.upgrade().ok_or(GetRandomFailed)?;
        let mut data = data.write().unwrap();
        println!("{}", hex::encode(<Vec<u8> as AsRef<[u8]>>::as_ref(&data)));
        if data.len() < buf.len() {
            return Err(GetRandomFailed);
        }

        let mut remaining_data = data.split_off(buf.len());
        std::mem::swap(data.deref_mut(), &mut remaining_data);
        std::mem::drop(data);
        let data = remaining_data;

        buf.copy_from_slice(&data[0..buf.len()]);

        Ok(())
    }
}

impl DummySecureRandom {
    pub fn new(data: &Arc<RwLock<Vec<u8>>>) -> Self {
        Self {
            data: Arc::downgrade(data)
        }
    }
}
