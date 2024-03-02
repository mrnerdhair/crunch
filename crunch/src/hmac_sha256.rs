use rustls::crypto::hmac;
use sha2::{Digest, Sha256};
use ::hmac::Mac;

pub struct HmacSha256;

impl hmac::Hmac for HmacSha256 {
    fn with_key(&self, key: &[u8]) -> Box<dyn hmac::Key> {
        Box::new(HmacSha256Key(::hmac::Hmac::<Sha256>::new_from_slice(key).unwrap()))
    }

    fn hash_output_len(&self) -> usize {
        Sha256::output_size()
    }
}

struct HmacSha256Key(::hmac::Hmac<Sha256>);

impl hmac::Key for HmacSha256Key {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> hmac::Tag {
        let mut ctx = self.0.clone();
        ctx.update(first);
        for m in middle {
            ctx.update(m);
        }
        ctx.update(last);
        hmac::Tag::new(&ctx.finalize().into_bytes()[..])
    }

    fn tag_len(&self) -> usize {
        Sha256::output_size()
    }
}
