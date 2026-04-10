mod tests;
mod util;

use core::ffi::CStr;
use util::Reader;

use crate::{
    error::{ParserError, ParserResult},
    mesh::{
        contacts::Contacts,
        identity::{LocalIdentity, PUBLIC_KEY_SIZE, RemoteIdentity},
        packet::{
            encryption::decrypt,
            node::{NodeType, NodeTypeSet},
            path::Path,
            payload::{ControlData, NeighbourOrdering, Payload, RequestData, TextMessageType},
            raw::{MAX_PACKET_PAYLOAD, PayloadType},
        },
        telemetry::TelemetryPermissions,
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
            PayloadType::Path => Self::parse_path(source_hash, reader),
            PayloadType::Request => Self::parse_request(reader),
            PayloadType::TextMessage => Self::parse_text_message(reader),
            PayloadType::Response => {
                let tag = reader.take_le_u32()?;
                let payload = reader.rest();
                let payload = heapless::Vec::from_slice(payload)?;
                Ok(Payload::Response { tag, payload })
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
    fn parse_path(source_hash: u8, mut reader: Reader<'_>) -> Result<Payload, ParserError> {
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
    fn parse_request(mut reader: Reader<'_>) -> Result<Payload, ParserError> {
        let timestamp = reader.take_le_u32()?;
        let request_type = reader.take_u8()?;
        let request_type = RequestType::try_from(request_type)?;
        let request_data = match request_type {
            RequestType::GetStatus => RequestData::GetStatus,
            RequestType::GetTelemetryData => {
                let permissions = reader.take_u8()?;
                let permissions = TelemetryPermissions::from(!permissions);
                RequestData::GetTelemetryData(permissions)
            }
            RequestType::GetAccessList => {
                let _reserved = reader.take_chunk::<2>()?;
                RequestData::GetAccessList
            }
            RequestType::GetNeighbours => {
                let version = reader.take_u8()?;
                match version {
                    0 => {
                        let count = reader.take_u8()?;
                        let offset = reader.take_le_u16()?;
                        let order_by = NeighbourOrdering::try_from(reader.take_u8()?)?;
                        let pubkey_trimmed_length = reader.take_u8()?;
                        let _random_bytes = reader.take_chunk::<4>()?;
                        RequestData::GetNeighbours {
                            count,
                            offset,
                            order_by,
                            pubkey_trimmed_length,
                        }
                    }
                    _ => return Err(ParserError::VersionMismatch),
                }
            }
            RequestType::GetOwnerInfo => RequestData::GetOwnerInfo,
            RequestType::KeepAlive => RequestData::KeepAlive,
        };
        Ok(Payload::Request(request_data))
    }
    fn parse_text_message(mut reader: Reader<'_>) -> Result<Payload, ParserError> {
        let timestamp = reader.take_le_u32()?;
        let flags = reader.take_u8()?;
        let text_message_type = TextMessageType::try_from(flags >> 2)?;
        let rest = reader.rest();
        let mut text = [0u8; MAX_PACKET_PAYLOAD];
        text[0..(rest.len())].copy_from_slice(rest);
        let text = CStr::from_bytes_until_nul(&text)
            .ok()
            .and_then(|text| text.to_str().ok())
            .ok_or(ParserError::InvalidInput)?;
        let text: heapless::String<MAX_PACKET_PAYLOAD> = text.try_into()?;
        Ok(Payload::TextMessage {
            text_message_type,
            text,
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

#[bitsize(8)]
#[derive(TryFromBits)]
enum ResponseType {
    RepeaterLoginOk,
}
