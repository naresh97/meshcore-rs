use bilge::prelude::*;

use crate::mesh::{
    identity::RemoteIdentity,
    packet::{
        node::{NodeType, NodeTypeSet},
        path::Path,
        raw::{PayloadType, RouteType},
    },
};

enum Payload {
    Trace {
        trace_tag: u32,
        auth_code: u32,
        flags: u8,
        path: Path,
    },
    Control(ControlData),
}

enum ControlData {
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
                let (&header, rest) = data.split_first()?;
                let (&filter, rest) = rest.split_first()?;
                let filter = NodeTypeSet::from(filter);
                let (tag, rest) = rest.split_at_checked(4)?;
                let tag = u32::from_le_bytes(tag.try_into().ok()?);

                let control_type = ControlType::from(u4::new(header >> 4));
                let control_data = match control_type {
                    ControlType::DiscoverRequest => {
                        let only_prefix = (header & 1) == 1;
                        let since = rest.split_at_checked(4).and_then(|(since, _)| {
                            let since = u32::from_le_bytes(since.try_into().ok()?);
                            Some(since)
                        });

                        Some(ControlData::DiscoverRequest {
                            filter,
                            tag,
                            only_prefix,
                            since,
                        })
                    }
                    ControlType::DiscoverResponse => {
                        let node_type = NodeType::from_index(header & (0b1111))?;
                        let identity = RemoteIdentity {
                            public: rest.try_into().ok()?,
                        };
                        Some(ControlData::DiscoverResponse {
                            tag,
                            node_type,
                            identity,
                        })
                    }
                    _ => None,
                }?;
                Self::Control(control_data)
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

#[bitsize(4)]
#[derive(FromBits)]
enum ControlType {
    DiscoverRequest = 0x8,
    DiscoverResponse = 0x9,
    #[fallback]
    Unknown,
}

#[cfg(test)]
mod tests {
    use std::process::id;

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
    #[test]
    fn parse_control_discover_response() {
        let payload =
            "92D071650845287E613F77754F51DD72848A5A5A35DC23AAE3D49B743E296B247AA9F29202FD";
        let payload = hex::decode(payload).unwrap();
        let Payload::Control(ControlData::DiscoverResponse {
            tag,
            node_type,
            identity,
        }) = Payload::parse(&payload, PayloadType::Control).unwrap()
        else {
            panic!();
        };
        assert!(matches!(node_type, NodeType::Repeater));
        assert_eq!(hex::decode("71650845").unwrap(), tag.to_le_bytes());
        assert_eq!(
            hex::decode("287E613F77754F51DD72848A5A5A35DC23AAE3D49B743E296B247AA9F29202FD")
                .unwrap(),
            identity.public
        );
    }

    #[test]
    fn parse_control_discover_request() {
        let payload = "800476501AE400000000";
        let payload = hex::decode(payload).unwrap();
        let Payload::Control(ControlData::DiscoverRequest {
            filter,
            tag,
            only_prefix,
            since: Some(since),
        }) = Payload::parse(&payload, PayloadType::Control).unwrap()
        else {
            panic!()
        };
        assert!(!only_prefix);
        assert_eq!(0, since);
        assert_eq!(hex::decode("76501AE4").unwrap(), tag.to_le_bytes());
        assert!(filter.contains(NodeType::Repeater));
        assert!(!filter.contains(NodeType::Chat));
        assert!(!filter.contains(NodeType::Room));
        assert!(!filter.contains(NodeType::Sensor));
    }
}
