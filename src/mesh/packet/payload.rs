use bilge::prelude::*;

use crate::mesh::packet::raw::{PayloadType, RouteType};

enum Payload {
    Trace {
        trace_tag: u32,
        auth_code: u32,
        flags: u8,
        path_hash_size: u8,
        path_length: usize,
    },
    Control {
        control_type: ControlType,
        type_filter: TypeFilter,
        tag: u32,
        since: Option<u32>,
    },
}

impl Payload {
    pub fn parse(
        data: &[u8],
        route_type: RouteType,
        payload_type: PayloadType,
        packet_path_length: usize,
    ) -> Option<Self> {
        if route_type.is_direct() && matches!(payload_type, PayloadType::Trace) {
            let (trace_tag, rest) = data.split_at_checked(4)?;
            let trace_tag = u32::from_le_bytes(trace_tag.try_into().ok()?);
            let (auth_code, rest) = rest.split_at_checked(4)?;
            let auth_code = u32::from_le_bytes(auth_code.try_into().ok()?);
            let (&flags, rest) = rest.split_first()?;
            let path_hash_size = flags & 0x03;
            let path_length = rest.len();
            return Some(Payload::Trace {
                trace_tag,
                auth_code,
                flags,
                path_hash_size,
                path_length,
            });
        }

        if route_type.is_direct() && matches!(payload_type, PayloadType::Control) {}

        None
    }
}

#[bitsize(8)]
#[derive(FromBits)]
struct ControlType {
    is_prefix_only: bool,
    reserved: u3,
    control_kind: ControlKind,
}

#[bitsize(4)]
#[derive(FromBits)]
enum ControlKind {
    DiscoverRequest = 0x8,
    DiscoverResponse = 0x9,
    #[fallback]
    Unknown,
}

#[bitsize(8)]
#[derive(FromBits)]
struct TypeFilter {
    is_none: bool,
    is_chat: bool,
    is_repeater: bool,
    is_room: bool,
    is_sensor: bool,
    reserved: u3,
}
