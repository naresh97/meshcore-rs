use crate::mesh::{
    identity::{PUBLIC_KEY_SIZE, RemoteIdentity, SIGNATURE_SIZE},
    packet::MAX_ADVERT_DATA_SIZE,
};

pub fn verify_signature(
    public_key: &[u8; PUBLIC_KEY_SIZE],
    signature: &[u8; SIGNATURE_SIZE],
    timestamp: u32,
    app_data: &[u8],
) -> Result<(), crate::error::EncryptionError> {
    const MESSAGE_SIZE: usize = PUBLIC_KEY_SIZE + 4 + MAX_ADVERT_DATA_SIZE;
    let mut message = heapless::Vec::<u8, MESSAGE_SIZE>::new();
    message.extend_from_slice(public_key);
    message.extend(timestamp.to_le_bytes());
    message.extend_from_slice(app_data);

    let id = RemoteIdentity {
        public: *public_key,
    };
    id.verify(&message, signature)
}
