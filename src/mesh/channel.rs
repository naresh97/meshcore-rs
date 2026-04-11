pub const CHANNEL_SECRET_SIZE: usize = 16;

pub struct ChannelIdentity {
    pub secret: [u8; 16],
}
