mod contacts;
mod identity;
pub mod packet;
pub mod preferences;
pub mod queue;
mod tables;

use core::{
    marker::PhantomData,
    time::{self, Duration},
};

use heapless::mpmc::Queue;

use crate::{
    error::HardwareResult,
    mesh::{
        identity::LocalIdentity,
        packet::{AdvertiserType, Packet},
    },
    platform::Platform,
    sensor::GpsLocation,
};

pub struct Mesh<P: Platform> {
    last_flood_advert: usize,
    last_direct_advert: usize,

    identity: LocalIdentity,
    preferences: preferences::Preferences,
    tables: tables::Tables,

    tx_queue: queue::PacketQueue<P>,

    _p: PhantomData<P>,
}

impl<P: Platform> Mesh<P> {
    fn new() -> HardwareResult<Self> {
        todo!()
    }
    fn send_self_advertisement(&mut self, _delay: Duration, _flood: bool) -> HardwareResult<()> {
        todo!()
    }
    fn run(&mut self) {
        let timestamp = P::timestamp_ms();
        let since_last_flood_advert = timestamp - self.last_flood_advert;
        let since_last_zero_hop_advert = timestamp - self.last_direct_advert;

        if since_last_flood_advert > self.preferences.flood_advert_interval {
            let packet = self.self_advert_packet();
            self.send_flood(packet, Duration::ZERO);
            self.last_flood_advert = timestamp;
            self.last_direct_advert = timestamp;
        } else if since_last_zero_hop_advert > self.preferences.zero_hop_advert_interval {
            let packet = self.self_advert_packet();
            self.send_zero_hop(packet, Duration::ZERO);
            self.last_direct_advert = timestamp;
        }
    }

    fn send_flood(&mut self, mut packet: Packet, delay: Duration) {
        //packet.route_type = packet::RouteType::Flood;
        //self.tables.mark_as_seen(&packet);
        //let priority: u8 = match packet.payload_type {
        //    PayloadType::Advert => 2,
        //    PayloadType::Path => 3,
        //    _ => 1,
        //};
        //self.send_packet(packet, priority, delay);
    }

    fn send_zero_hop(&mut self, mut packet: Packet, delay: Duration) {
        //packet.route_type = RouteType::Direct;
        //self.tables.mark_as_seen(&packet);
        //self.send_packet(packet, 0, delay);
    }

    fn send_packet(&mut self, packet: Packet, priority: u8, delay: Duration) {
        self.tx_queue.push(packet, priority, delay);
    }

    fn advert_location(&self) -> Option<GpsLocation> {
        todo!()
    }

    fn self_advert_packet(&self) -> Packet {
        Packet::create_advert::<P>(
            &self.identity,
            AdvertiserType::Repeater,
            self.advert_location(),
            self.preferences.node_name.as_deref(),
        )
    }
}

impl<P: Platform> Mesh<P> {}
