pub trait Platform {
    fn timestamp_ms() -> usize;
    fn on_after_transmit();
}
