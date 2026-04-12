use crate::mesh::packet::{MAX_PACKET_PAYLOAD, payload::Payload};

pub struct PayloadSerializer {}
impl PayloadSerializer {
    pub fn serialize(&self, payload: &Payload) -> heapless::Vec<u8, MAX_PACKET_PAYLOAD> {
        todo!()
    }
}
