use crate::mesh::packet::{payload::Payload, raw::MAX_PACKET_PAYLOAD};

pub struct PayloadSerializer {}
impl PayloadSerializer {
    pub fn serialize(&self, payload: &Payload) -> heapless::Vec<u8, MAX_PACKET_PAYLOAD> {
        todo!()
    }
}
