use crate::{
    error::EncryptionResult,
    mesh::identity::{LocalIdentity, PUBLIC_KEY_SIZE, RemoteIdentity, SIGNATURE_SIZE},
    utils::Writer,
};

pub const MAX_ADVERT_DATA_SIZE: usize = 32;
const MESSAGE_SIZE: usize = PUBLIC_KEY_SIZE + 4 + MAX_ADVERT_DATA_SIZE;

pub fn verify_signature(
    public_key: &[u8; PUBLIC_KEY_SIZE],
    signature: &[u8; SIGNATURE_SIZE],
    timestamp: u32,
    app_data: &[u8],
) -> Result<(), crate::error::EncryptionError> {
    let mut message = heapless::Vec::<u8, MESSAGE_SIZE>::new();
    message.extend_from_slice(public_key)?;
    message.extend_from_slice(&timestamp.to_le_bytes())?;
    message.extend_from_slice(app_data)?;
    let id = RemoteIdentity {
        public: *public_key,
    };
    id.verify(&message, signature)
}

pub fn sign(
    local_identity: &LocalIdentity,
    timestamp: u32,
    app_data: &[u8],
) -> EncryptionResult<[u8; 64]> {
    let mut message = Writer::<MESSAGE_SIZE>::new();
    message.put_slice(&local_identity.public)?;
    message.put_le_u32(timestamp)?;
    message.put_slice(app_data)?;
    let message = message.finish();
    local_identity.sign(message.as_slice())
}
