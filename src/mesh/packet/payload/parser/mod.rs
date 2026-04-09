mod tests;

use crate::{
    error::{ParserError, ParserResult},
    mesh::{
        contacts::Contacts,
        identity::{LocalIdentity, RemoteIdentity},
        packet::{
            encryption::decrypt,
            node::{NodeType, NodeTypeSet},
            path::Path,
            payload::{ControlData, Payload},
            raw::{MAX_PACKET_PAYLOAD, MAX_PATH_SIZE, PayloadType},
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
        let (&destination_hash, rest) = data.split_first().ok_or(ParserError::UnexpectedEnd(
            "encrypted",
            "destination_hash",
            1,
        ))?;
        if destination_hash != self.identity.public[0] {
            return Ok(Payload::Undecryptable);
        }
        let (&source_hash, rest) =
            rest.split_first()
                .ok_or(ParserError::UnexpectedEnd("encrypted", "source_hash", 1))?;
        let ciphertext = rest;
        let Some(plaintext) = self
            .contacts
            .get_matches_hash(source_hash)
            .map(|id| self.identity.get_shared_key(&id))
            .flat_map(|shared| decrypt(&shared, ciphertext))
            .next()
        else {
            return Ok(Payload::Undecryptable);
        };
        let data = plaintext.as_slice();
        match payload_type {
            PayloadType::Path => {
                const CONTEXT_NAME: &str = "encrypted->path";
                let (&path_length, rest) = data.split_first().ok_or(ParserError::UnexpectedEnd(
                    CONTEXT_NAME,
                    "path_length",
                    1,
                ))?;
                let (path, rest) =
                    rest.split_at_checked(path_length.into())
                        .ok_or(ParserError::UnexpectedEnd(
                            CONTEXT_NAME,
                            "path",
                            path_length.into(),
                        ))?;
                let path = heapless::Vec::from_slice(path).map_err(|_| {
                    ParserError::ExceedsCapacity(CONTEXT_NAME, "path", MAX_PATH_SIZE)
                })?;
                let (&extra_type, rest) = rest.split_first().ok_or(ParserError::UnexpectedEnd(
                    CONTEXT_NAME,
                    "extra_type",
                    1,
                ))?;
                let extra = heapless::Vec::from_slice(rest).map_err(|_| {
                    ParserError::ExceedsCapacity("encrypted->path", "extra", MAX_PACKET_PAYLOAD)
                })?;
                Ok(Payload::Path {
                    source_hash,
                    path,
                    extra_type,
                    extra,
                })
            }
            PayloadType::Request => {
                const CONTEXT_NAME: &str = "encrypted->request";
                let (&timestamp, rest) = data
                    .split_first_chunk::<4>()
                    .ok_or(ParserError::UnexpectedEnd(CONTEXT_NAME, "timestamp", 4))?;
                let timestamp = u32::from_le_bytes(timestamp);
                let (&request_type, rest) = rest
                    .split_first()
                    .ok_or(ParserError::UnexpectedEnd(CONTEXT_NAME, "request_type", 1))?;
                let request_type = RequestType::try_from(request_type)
                    .map_err(|_| ParserError::BitParsingError(CONTEXT_NAME, "request_type"))?;
                todo!()
            }
            _ => Err(ParserError::UndefinedPayload),
        }
    }
    fn parse_multipart(data: &[u8]) -> ParserResult<Payload> {
        let (&header, rest) = data.split_first()?;
        let remaining_packets = header >> 4;
        let payload_type = PayloadType::from(u4::new(header & 0b1111));
        let payload = rest;
        Ok(Payload::MultiPart {
            remaining_packets,
            payload_type,
            payload: heapless::Vec::from_slice(payload).ok()?,
        })
    }

    fn parse_ack(data: &[u8]) -> ParserResult<Payload> {
        let (&crc, _) = data.split_first_chunk::<4>()?;
        let crc = u32::from_le_bytes(crc);
        Ok(Payload::Ack { crc })
    }

    fn parse_control(data: &[u8]) -> ParserResult<Payload> {
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
        Ok(Payload::Control(control_data))
    }

    fn parse_trace(data: &[u8]) -> ParserResult<Payload> {
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
