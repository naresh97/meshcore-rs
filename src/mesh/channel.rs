use sha2::{Digest, Sha256};

pub const CHANNEL_SECRET_SIZE: usize = 16;

pub struct ChannelIdentity {
    pub hash: u8,
    pub secret: [u8; CHANNEL_SECRET_SIZE],
}

impl ChannelIdentity {
    pub fn from_hashtag(name: &str) -> ChannelIdentity {
        let secret = Sha256::digest(name.as_bytes());
        let &secret = secret
            .first_chunk::<CHANNEL_SECRET_SIZE>()
            .expect("must exist");
        let &hash = Sha256::digest(secret).first().expect("must exist");
        Self { hash, secret }
    }
}
