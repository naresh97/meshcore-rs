use core::{marker::PhantomData, time::Duration};

use crate::{mesh::packet::Packet, platform::Platform};

const QUEUE_SIZE: usize = 32;
pub struct PacketQueue<P: Platform> {
    /// Priority queue for packets, with `Min` specifying lower numbers as higher priority
    binary_heap: heapless::BinaryHeap<QueuedPacket, heapless::binary_heap::Min, QUEUE_SIZE>,

    _platform: PhantomData<P>,
}
impl<P: Platform> PacketQueue<P> {
    /// Queue up a packet
    pub fn push(&mut self, packet: Packet, priority: u8, delay: Duration) {
        let now = P::timestamp_ms();

        let _ = self.binary_heap.push(QueuedPacket {
            // silently drop packets if queue is full
            packet,
            priority,
            scheduled_for_ms: now + (delay.as_millis() as usize),
        });
    }

    pub fn pop(&mut self) -> Option<Packet> {
        self.binary_heap.pop().map(|q| q.packet)
    }
}

struct QueuedPacket {
    packet: Packet,
    priority: u8,
    scheduled_for_ms: usize,
}
impl core::cmp::Ord for QueuedPacket {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.priority.cmp(&other.priority)
    }
}
impl core::cmp::PartialOrd for QueuedPacket {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl core::cmp::PartialEq for QueuedPacket {
    fn eq(&self, other: &Self) -> bool {
        self.priority.eq(&other.priority)
    }
}
impl core::cmp::Eq for QueuedPacket {}
