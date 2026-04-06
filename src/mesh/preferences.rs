pub const NODE_NAME_MAX_LENGTH: usize = 32;
pub struct Preferences {
    pub flood_advert_interval: usize,
    pub zero_hop_advert_interval: usize,
    pub node_name: Option<heapless::String<NODE_NAME_MAX_LENGTH>>,
}
