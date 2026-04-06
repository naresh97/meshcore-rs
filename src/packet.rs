use core::{time, u32};

use bitflags::bitflags;

use crate::{LocalIdentity, identity::PUBLIC_KEY_SIZE, platform::Platform, sensor::GpsLocation};

#[repr(C)]
struct PacketInner {
    pub header: u8,
    pub payload_length: u16,
    pub path_length: u16,
    pub transport_codes: [u16; 2],
    pub path: [u8; MAX_PATH_SIZE],
    pub payload: [u8; MAX_PACKET_PAYLOAD],
    pub snr: i8,
}

pub struct Packet {
    pub route_type: RouteType,
    pub payload_type: PayloadType,
    payload: [u8; MAX_PACKET_PAYLOAD],
}

const MAX_PATH_SIZE: usize = 64;
const MAX_PACKET_PAYLOAD: usize = 182;
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
            let mut f = advert_type.to_advert_flags();
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
        let payload = payload
            .into_array()
            .expect("Cannot panic since already resized");
        Packet {
            payload_type: PayloadType::Advert,
            payload,
            route_type: Default::default(),
        }
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
    fn to_advert_flags(&self) -> AdvertHeaderFlags {
        match self {
            AdvertiserType::Chat => AdvertHeaderFlags::ChatType,
            AdvertiserType::Repeater => AdvertHeaderFlags::RepeaterType,
            AdvertiserType::Room => AdvertHeaderFlags::RoomType,
            AdvertiserType::Sensor => AdvertHeaderFlags::SensorType,
        }
    }
}

pub enum PayloadType {
    Request,
    Response,
    TextMessage,
    Ack,
    Advert,
    GroupText,
    GroupData,
    AnonymousRequest,
    Path,
    Trace,
    MultiPart,
    Control,
}

#[derive(Default)]
pub enum RouteType {
    #[default]
    Flood,
    TransportFlood,
    Direct,
    TransportDirect,
}
