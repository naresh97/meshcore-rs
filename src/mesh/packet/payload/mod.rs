mod parser;

use crate::mesh::{
    contacts::Contacts,
    identity::{LocalIdentity, RemoteIdentity},
    packet::{
        encryption::decrypt,
        node::{NodeType, NodeTypeSet},
        path::Path,
        raw::{MAX_PACKET_PAYLOAD, MAX_PATH_SIZE, PayloadType, RouteType},
    },
    telemetry::TelemetryPermissions,
};
use bilge::prelude::*;

#[derive(Debug)]
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
}

#[derive(Debug)]
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

#[derive(Debug)]
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
#[derive(Debug, TryFromBits)]
pub enum NeighbourOrdering {
    NewestToOldest = 0,
    OldestToNewest = 1,
    StrongestToWeakest = 2,
    WeakestToStrongest = 3,
}

#[bitsize(8)]
#[derive(Debug, TryFromBits)]
pub enum TextMessageType {
    Plain = 0,
    CliData = 1,
    SignedPlain = 2,
}
