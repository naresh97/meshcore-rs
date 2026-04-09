use bilge::prelude::*;

use crate::mesh::{
    contacts::Contacts,
    identity::{LocalIdentity, RemoteIdentity},
    packet::{
        encryption::decrypt,
        node::{NodeType, NodeTypeSet},
        path::Path,
        raw::{MAX_PACKET_PAYLOAD, MAX_PATH_SIZE, PayloadType, RouteType},
    },
};

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

pub struct PayloadParser {
    identity: LocalIdentity,
    contacts: Contacts,
}

impl PayloadParser {
    pub fn parse(&self, data: &[u8], payload_type: PayloadType) -> Option<Payload> {
        let payload = match payload_type {
            PayloadType::Trace => {
                let (&trace_tag, rest) = data.split_first_chunk::<4>()?;
                let trace_tag = u32::from_le_bytes(trace_tag);
                let (&auth_code, rest) = rest.split_first_chunk::<4>()?;
                let auth_code = u32::from_le_bytes(auth_code);
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
                let (&tag, rest) = rest.split_first_chunk::<4>()?;
                let tag = u32::from_le_bytes(tag);

                let control_type = ControlType::from(u4::new(header >> 4));
                let control_data = match control_type {
                    ControlType::DiscoverRequest => {
                        let only_prefix = (header & 1) == 1;
                        let since = rest
                            .split_first_chunk::<4>()
                            .map(|(&since, _)| u32::from_le_bytes(since));

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
                    ControlType::Unknown => None,
                }?;
                Payload::Control(control_data)
            }
            PayloadType::Ack => {
                let (&crc, _) = data.split_first_chunk::<4>()?;
                let crc = u32::from_le_bytes(crc);
                Payload::Ack { crc }
            }
            PayloadType::MultiPart => {
                let (&header, rest) = data.split_first()?;
                let remaining_packets = header >> 4;
                let payload_type = PayloadType::from(u4::new(header & 0b1111));
                let payload = rest;
                Payload::MultiPart {
                    remaining_packets,
                    payload_type,
                    payload: heapless::Vec::from_slice(payload).ok()?,
                }
            }
            PayloadType::Path
            | PayloadType::Request
            | PayloadType::Response
            | PayloadType::TextMessage => {
                let (&destination_hash, rest) = data.split_first()?;
                if destination_hash != self.identity.public[0] {
                    return Some(Payload::Undecryptable);
                }

                let (&source_hash, rest) = rest.split_first()?;
                let ciphertext = rest;
                let Some(plaintext) = self
                    .contacts
                    .get_matches_hash(source_hash)
                    .map(|id| self.identity.get_shared_key(&id))
                    .flat_map(|shared| decrypt(&shared, ciphertext))
                    .next()
                else {
                    return Some(Payload::Undecryptable);
                };
                let data = plaintext.as_slice();

                match payload_type {
                    PayloadType::Path => {
                        let (&path_length, rest) = data.split_first()?;
                        let (path, rest) = rest.split_at_checked(path_length.into())?;
                        let path = heapless::Vec::from_slice(path).ok()?;
                        let (&extra_type, rest) = rest.split_first()?;
                        let extra = heapless::Vec::from_slice(rest).ok()?;
                        Some(Payload::Path {
                            source_hash,
                            path,
                            extra_type,
                            extra,
                        })
                    }
                    PayloadType::Request => {
                        let (&timestamp, rest) = data.split_first_chunk::<4>()?;
                        let timestamp = u32::from_le_bytes(timestamp);
                        let (&request_type, rest) = rest.split_first()?;
                        let request_type = RequestType::try_from(request_type).ok()?;
                        todo!()
                    }
                    _ => None,
                }?
            }
            PayloadType::Advert => todo!(),
            PayloadType::GroupText => todo!(),
            PayloadType::GroupData => todo!(),
            PayloadType::AnonymousRequest => todo!(),
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

#[bitsize(8)]
#[derive(TryFromBits)]
enum RequestType {
    GetStatus = 0x01,
    KeepAlive = 0x02,
    GetTelemetryData = 0x03,
    GetAccessList = 0x05,
    GetNeighbours = 0x06,
    GetOwnerInfo = 0x07,
}

#[cfg(test)]
mod tests {
    use std::{os::linux::net::TcpStreamExt, process::id};

    fn test_parser() -> PayloadParser {
        PayloadParser {
            identity: LocalIdentity::from_private_key(
                &hex::decode("104B70BC64F3FDBDEC6E9A9189C40C7B6A64E5D3A91B75D423EDF879C4C082605F852A0F473307596502D95238CE1FEC32C4BEBD7D119AE73974C2BFA650A1B3").unwrap().try_into().unwrap(),
            ),
            contacts: Contacts {},
        }
    }

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
        } = test_parser().parse(&payload, PayloadType::Trace).unwrap()
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
        }) = test_parser().parse(&payload, PayloadType::Control).unwrap()
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
        }) = test_parser().parse(&payload, PayloadType::Control).unwrap()
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

    #[test]
    fn parse_multipart() {
        let payload = "284D0EB1C4C82936AEA94F00E39D27B628579A769F668AB266F85D188A56834C041E957C5CC533A91DA26DCED3DEF2856AD883BBB064AB7F11DEB2FC3AD4FA03642ACF23435820E7AD35D7A75C64BDED6E3444E3D75B238B3E5F158FAD2B7856F515";
        let payload = hex::decode(payload).unwrap();
        let _payload = test_parser()
            .parse(&payload, PayloadType::MultiPart)
            .unwrap();
    }
}
