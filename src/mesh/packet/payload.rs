use bilge::prelude::*;

use crate::mesh::packet::{
    path::Path,
    raw::{PayloadType, RouteType},
};

enum Payload {
    Trace {
        trace_tag: u32,
        auth_code: u32,
        flags: u8,
        path: Path,
    },
    Control {
        control_type: ControlType,
        type_filter: TypeFilter,
        tag: u32,
        since: Option<u32>,
    },
}

impl Payload {
    pub fn parse(data: &[u8], payload_type: PayloadType) -> Option<Self> {
        let payload = match payload_type {
            PayloadType::Trace => {
                let (trace_tag, rest) = data.split_at_checked(4)?;
                let trace_tag = u32::from_le_bytes(trace_tag.try_into().ok()?);
                let (auth_code, rest) = rest.split_at_checked(4)?;
                let auth_code = u32::from_le_bytes(auth_code.try_into().ok()?);
                let (&flags, rest) = rest.split_first()?;
                let path_hash_size = flags & 0x03;
                let path = match path_hash_size {
                    0 => Path::from_1_byte_slice(rest),
                    1 => Path::from_2_byte_slice(rest),
                    2 => Path::from_3_byte_slice(rest),
                    _ => None,
                }?;
                Payload::Trace {
                    trace_tag,
                    auth_code,
                    flags,
                    path,
                }
            }
            PayloadType::Control => {
                todo!()
            }
            PayloadType::Request => todo!(),
            PayloadType::Response => todo!(),
            PayloadType::TextMessage => todo!(),
            PayloadType::Ack => todo!(),
            PayloadType::Advert => todo!(),
            PayloadType::GroupText => todo!(),
            PayloadType::GroupData => todo!(),
            PayloadType::AnonymousRequest => todo!(),
            PayloadType::Path => todo!(),
            PayloadType::MultiPart => todo!(),
            PayloadType::RawCustom => todo!(),
        };
        Some(payload)
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_trace() {
        let payload = "4864DE9B0000000001FDA6899884988998FDA6";
        let payload = hex::decode(payload).unwrap();
        let Payload::Trace {
            trace_tag,
            auth_code,
            flags,
            path,
        } = Payload::parse(&payload, PayloadType::Trace).unwrap()
        else {
            panic!()
        };
        assert_eq!(hex::decode("4864DE9B").unwrap(), trace_tag.to_le_bytes());
        assert_eq!(0, auth_code);
        assert_eq!(0x01, flags);
        let Path::Hash2(path) = path else { panic!() };
        assert_eq!(
            [
                [0xFD, 0xA6],
                [0x89, 0x98],
                [0x84, 0x98],
                [0x89, 0x98],
                [0xFD, 0xA6]
            ],
            path
        );
    }
}
