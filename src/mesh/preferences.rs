pub const NODE_NAME_MAX_LENGTH: usize = 32;
pub struct Preferences {
    pub flood_advert_interval: usize,
    pub zero_hop_advert_interval: usize,
    pub node_name: Option<heapless::String<NODE_NAME_MAX_LENGTH>>,
    pub radio_interference_threshold: isize,
    pub airtime_budget_factor: f32,
    pub agc_reset_interval_ms: usize,
}
