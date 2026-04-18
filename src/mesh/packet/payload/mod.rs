mod parser;
pub use parser::PayloadParser;

use crate::{
    mesh::{
        channel::ChannelIdentity,
        contacts::Contacts,
        identity::{LocalIdentity, RemoteIdentity, SIGNATURE_SIZE},
        packet::{
            MAX_PACKET_PAYLOAD, MAX_PATH_SIZE, PayloadType, RouteType,
            encryption::decrypt,
            node::{NodeType, NodeTypeSet},
            path::Path,
        },
        telemetry::TelemetryPermissions,
    },
    sensor::GpsLocation,
};
use bilge::prelude::*;

#[derive(Debug, Clone)]
pub enum Payload {
    Trace {
        trace_tag: u32,
        auth_code: u32,
        flags: u8,
        path: Path,
    },
    Control(ControlData),
    Ack {
        crc: u32,
    },
    MultiPart {
        remaining_packets: u8,
        payload_type: PayloadType,
        payload: heapless::Vec<u8, MAX_PACKET_PAYLOAD>,
    },
    Undecryptable,
    Path {
        source_hash: u8,
        path: heapless::Vec<u8, MAX_PATH_SIZE>,
        extra_type: u8,
        extra: heapless::Vec<u8, MAX_PACKET_PAYLOAD>,
    },
    Request(RequestData),
    TextMessage {
        text_message_type: TextMessageType,
        text: heapless::String<MAX_PACKET_PAYLOAD>,
    },
    Response {
        tag: u32,
        payload: heapless::Vec<u8, MAX_PACKET_PAYLOAD>,
    },
    AnonRequest(AnonRequestData),
    GroupText {
        channel: ChannelIdentity,
        timestamp: u32,
        message: heapless::String<MAX_PACKET_PAYLOAD>,
        text_message_type: TextMessageType,
    },
    Advert {
        id: RemoteIdentity,
        timestamp: u32,
        signature: [u8; SIGNATURE_SIZE],
        advert_type: AdvertType,
        location: Option<GpsLocation>,
        name: Option<heapless::String<MAX_PACKET_PAYLOAD>>,
        extra_1: Option<u16>,
        extra_2: Option<u16>,
    },
}

#[derive(Debug, Clone)]
pub enum ControlData {
    DiscoverRequest {
        filter: NodeTypeSet,
        tag: u32,
        only_prefix: bool,
        since: Option<u32>,
    },
    DiscoverResponse {
        tag: u32,
        node_type: NodeType,
        identity: RemoteIdentity,
    },
}

#[derive(Debug, Clone)]
pub enum RequestData {
    GetStatus,
    GetTelemetryData(TelemetryPermissions),
    GetAccessList,
    GetNeighbours {
        count: u8,
        offset: u16,
        order_by: NeighbourOrdering,
        pubkey_trimmed_length: u8,
    },
    GetOwnerInfo,
    KeepAlive,
}

#[bitsize(8)]
#[derive(Debug, TryFromBits, Clone)]
pub enum NeighbourOrdering {
    NewestToOldest = 0,
    OldestToNewest = 1,
    StrongestToWeakest = 2,
    WeakestToStrongest = 3,
}

#[bitsize(8)]
#[derive(Debug, TryFromBits, Clone)]
pub enum TextMessageType {
    Plain = 0,
    CliData = 1,
    SignedPlain = 2,
}

#[derive(Debug, Clone)]
pub enum AnonRequestData {
    Login {
        password: heapless::String<MAX_PACKET_PAYLOAD>,
    },
    LoginNoPassword,
    Regions {
        reply_path: Path,
    },
    Owner {
        reply_path: Path,
    },
    Basic {
        reply_path: Path,
    },
}

#[bitsize(4)]
#[derive(Debug, FromBits, Clone)]
pub enum AdvertType {
    #[fallback]
    None,
    Chat,
    Repeater,
    Room,
    Sensor,
}
