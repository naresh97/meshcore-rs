mod payload;
mod raw;

use core::time;

use bilge::{
    bitsize,
    prelude::{Integer, u2, u4},
};
use bitflags::bitflags;

use crate::{
    mesh::{
        identity::{LocalIdentity, PUBLIC_KEY_SIZE},
        packet::raw::MAX_PACKET_PAYLOAD,
    },
    platform::Platform,
    sensor::GpsLocation,
};

pub struct Packet {
    //payload: [u8; MAX_PACKET_PAYLOAD],
}

const MAX_ADVERT_DATA_SIZE: usize = 32;

impl Packet {
    pub fn create_advert<P: Platform>(
        identity: &LocalIdentity,
        advert_type: AdvertiserType,
        location: Option<GpsLocation>,
        name: Option<&str>,
    ) -> Self {
        let mut data: heapless::Vec<u8, MAX_ADVERT_DATA_SIZE> = heapless::Vec::new();

        let feature_flags = {
            let mut f = advert_type.into_advert_flags();
            if location.is_some() {
                f |= AdvertHeaderFlags::HasLocation;
            }
            if name.is_some() {
                f |= AdvertHeaderFlags::HasName;
            }
            f
        };
        data.push(feature_flags.bits());
        if let Some(location) = location {
            data.extend(location.latitude.to_le_bytes());
            data.extend(location.longitude.to_le_bytes());
        }
        if let Some(name) = name {
            data.extend_from_slice(name.as_bytes());
        }

        let mut payload: heapless::Vec<u8, MAX_PACKET_PAYLOAD> = heapless::Vec::new();
        payload.extend_from_slice(&identity.private);
        let timestamp: u32 = P::timestamp_ms().try_into().unwrap_or_default();
        let timestamp = timestamp.to_le_bytes();
        payload.extend_from_slice(&timestamp);

        let signature = {
            const MESSAGE_CAPACITY: usize = PUBLIC_KEY_SIZE + 4 + MAX_ADVERT_DATA_SIZE;
            let mut message: heapless::Vec<u8, MESSAGE_CAPACITY> = heapless::Vec::new();
            message.extend_from_slice(&identity.public);
            message.extend_from_slice(&timestamp);
            message.extend_from_slice(&data);
            identity.sign(&message)
        };
        payload.extend(signature);
        payload.extend(data);
        payload.resize_default(MAX_PACKET_PAYLOAD);
        //let payload = payload
        //    .into_array()
        //    .expect("Cannot panic since already resized");
        Packet {
            //payload_type: PayloadType::Advert,
            //payload,
            //route_type: RouteType::default(),
        }
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        let header = raw::Header::from(*data.first()?);
        if header.version().as_usize() > 0 {
            return None;
        }
        let has_transport_codes = matches!(
            header.route_type(),
            raw::RouteType::TransportFlood | raw::RouteType::TransportDirect
        );

        todo!()
    }
}

enum AdvertLocationPolicy {
    None,
    Share,
    Preset,
}

bitflags! {
    struct PacketHeaders : u8 {
        const AdvertType = 0x10;
    }
}

bitflags! {
    pub struct AdvertHeaderFlags : u8{
        const NoneType = 0;
        const ChatType = 1;
        const RepeaterType = 2;
        const RoomType = 3;
        const SensorType = 4;

        const HasLocation = 0x10;
        const Feature1 = 0x20;
        const Feature2 = 0x40;
        const HasName = 0x80;
    }
}

pub enum AdvertiserType {
    Chat,
    Repeater,
    Room,
    Sensor,
}
impl AdvertiserType {
    fn into_advert_flags(self) -> AdvertHeaderFlags {
        match self {
            AdvertiserType::Chat => AdvertHeaderFlags::ChatType,
            AdvertiserType::Repeater => AdvertHeaderFlags::RepeaterType,
            AdvertiserType::Room => AdvertHeaderFlags::RoomType,
            AdvertiserType::Sensor => AdvertHeaderFlags::SensorType,
        }
    }
}
