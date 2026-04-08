use ed25519_dalek::{Signer, SigningKey};

pub const PRIVATE_KEY_SIZE: usize = 64;
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;

/// An identity created by this device, with private key known on this device.
pub struct LocalIdentity {
    pub private: [u8; PRIVATE_KEY_SIZE],
    pub public: [u8; PUBLIC_KEY_SIZE],
}
impl LocalIdentity {
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_SIZE] {
        let signing_key = SigningKey::from_bytes(
            &self.private[..32]
                .try_into()
                .expect("Cannot fail since private key is 64 bytes long."),
        );
        let signature = signing_key.sign(message);
        signature.to_bytes()
    }
}

pub struct RemoteIdentity {
    pub public: [u8; PUBLIC_KEY_SIZE],
}
