mod tests;

use crate::mesh::{
    contacts::Contacts,
    identity::{LocalIdentity, RemoteIdentity},
    packet::{
        encryption::decrypt,
        node::{NodeType, NodeTypeSet},
        path::Path,
        payload::{ControlData, Payload},
        raw::PayloadType,
    },
};
use bilge::prelude::*;

pub struct PayloadParser {
    pub(crate) identity: LocalIdentity,
    pub(crate) contacts: Contacts,
}

impl PayloadParser {
    pub fn parse(&self, data: &[u8], payload_type: PayloadType) -> Option<Payload> {
        let payload = match payload_type {
            PayloadType::Trace => Self::parse_trace(data)?,
            PayloadType::Control => Self::parse_control(data)?,
            PayloadType::Ack => Self::parse_ack(data)?,
            PayloadType::MultiPart => Self::parse_multipart(data)?,
            PayloadType::Path
            | PayloadType::Request
            | PayloadType::Response
            | PayloadType::TextMessage => self.parse_encrypted(data, payload_type)?,
            PayloadType::Advert => todo!(),
            PayloadType::GroupText => todo!(),
            PayloadType::GroupData => todo!(),
            PayloadType::AnonymousRequest => todo!(),
            PayloadType::RawCustom => todo!(),
        };
        Some(payload)
    }

    fn parse_encrypted(&self, data: &[u8], payload_type: PayloadType) -> Option<Payload> {
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
        }
    }
    fn parse_multipart(data: &[u8]) -> Option<Payload> {
        let (&header, rest) = data.split_first()?;
        let remaining_packets = header >> 4;
        let payload_type = PayloadType::from(u4::new(header & 0b1111));
        let payload = rest;
        Some(Payload::MultiPart {
            remaining_packets,
            payload_type,
            payload: heapless::Vec::from_slice(payload).ok()?,
        })
    }

    fn parse_ack(data: &[u8]) -> Option<Payload> {
        let (&crc, _) = data.split_first_chunk::<4>()?;
        let crc = u32::from_le_bytes(crc);
        Some(Payload::Ack { crc })
    }

    fn parse_control(data: &[u8]) -> Option<Payload> {
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
        Some(Payload::Control(control_data))
    }

    fn parse_trace(data: &[u8]) -> Option<Payload> {
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
        Some(Payload::Trace {
            trace_tag,
            auth_code,
            flags,
            path,
        })
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
