mod tests;
mod util;

use crate::{
    error::{ParserError, ParserResult},
    mesh::{
        contacts::Contacts,
        identity::{LocalIdentity, PUBLIC_KEY_SIZE, RemoteIdentity},
        packet::{
            encryption::decrypt,
            node::{NodeType, NodeTypeSet},
            path::Path,
            payload::{ControlData, Payload, parser::util::Reader},
            raw::PayloadType,
        },
    },
};
use bilge::prelude::*;

pub struct PayloadParser {
    pub(crate) identity: LocalIdentity,
    pub(crate) contacts: Contacts,
}

impl PayloadParser {
    pub fn parse(&self, data: &[u8], payload_type: PayloadType) -> ParserResult<Payload> {
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
        Ok(payload)
    }

    fn parse_encrypted(&self, data: &[u8], payload_type: PayloadType) -> ParserResult<Payload> {
        let mut reader = Reader::new(data);
        let destination_hash = reader.take_u8()?;
        if destination_hash != self.identity.public[0] {
            return Ok(Payload::Undecryptable);
        }
        let source_hash = reader.take_u8()?;
        let ciphertext = reader.rest();
        let Some(plaintext) = self
            .contacts
            .get_matches_hash(source_hash)
            .map(|id| self.identity.get_shared_key(&id))
            .flat_map(|shared| decrypt(&shared, ciphertext))
            .next()
        else {
            return Ok(Payload::Undecryptable);
        };
        let mut reader = Reader::new(plaintext.as_slice());
        match payload_type {
            PayloadType::Path => {
                let path_length = reader.take_u8()?;
                let path = reader.take_slice(path_length.into())?;
                let path = heapless::Vec::from_slice(path)?;
                let extra_type = reader.take_u8()?;
                let extra = heapless::Vec::from_slice(reader.rest())?;
                Ok(Payload::Path {
                    source_hash,
                    path,
                    extra_type,
                    extra,
                })
            }
            PayloadType::Request => {
                let timestamp = reader.take_le_u32()?;
                let request_type = reader.take_u8()?;
                let request_type = RequestType::try_from(request_type)?;
                todo!()
            }
            _ => Err(ParserError::InvalidInput),
        }
    }
    fn parse_multipart(data: &[u8]) -> ParserResult<Payload> {
        let mut reader = Reader::new(data);
        let header = reader.take_u8()?;
        let remaining_packets = header >> 4;
        let payload_type = PayloadType::from(u4::new(header & 0b1111));
        let payload = reader.rest();
        Ok(Payload::MultiPart {
            remaining_packets,
            payload_type,
            payload: heapless::Vec::from_slice(payload)?,
        })
    }

    fn parse_ack(data: &[u8]) -> ParserResult<Payload> {
        let crc = Reader::new(data).take_le_u32()?;
        Ok(Payload::Ack { crc })
    }

    fn parse_control(data: &[u8]) -> ParserResult<Payload> {
        let mut reader = Reader::new(data);
        let header = reader.take_u8()?;
        let filter = reader.take_u8()?;
        let filter = NodeTypeSet::from(filter);
        let tag = reader.take_le_u32()?;
        let control_type = ControlType::from(u4::new(header >> 4));
        let control_data = match control_type {
            ControlType::DiscoverRequest => {
                let only_prefix = (header & 1) == 1;
                let since = reader.take_le_u32().ok();
                ControlData::DiscoverRequest {
                    filter,
                    tag,
                    only_prefix,
                    since,
                }
            }
            ControlType::DiscoverResponse => {
                let node_type =
                    NodeType::from_index(header & (0b1111)).ok_or(ParserError::InvalidInput)?;
                let public = reader.take_chunk::<PUBLIC_KEY_SIZE>()?;
                let identity = RemoteIdentity { public };
                ControlData::DiscoverResponse {
                    tag,
                    node_type,
                    identity,
                }
            }
            ControlType::Unknown => return Err(ParserError::InvalidInput),
        };
        Ok(Payload::Control(control_data))
    }

    fn parse_trace(data: &[u8]) -> ParserResult<Payload> {
        let mut reader = Reader::new(data);
        let trace_tag = reader.take_le_u32()?;
        let auth_code = reader.take_le_u32()?;
        let flags = reader.take_u8()?;
        let path_hash_size = flags & 0x03;
        let rest = reader.rest();
        let path = match path_hash_size {
            0 => Path::from_1_byte_slice(rest),
            1 => Path::from_2_byte_slice(rest),
            2 => Path::from_3_byte_slice(rest),
            _ => None,
        }
        .ok_or(ParserError::InvalidInput)?;
        Ok(Payload::Trace {
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
