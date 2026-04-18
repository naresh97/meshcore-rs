mod serialize;
mod tests;

use bilge::prelude::*;
use core::ffi::CStr;

use crate::{
    error::{ParserError, ParserResult},
    mesh::{
        contacts::{self, Contacts},
        identity::{LocalIdentity, PUBLIC_KEY_SIZE, RemoteIdentity, SIGNATURE_SIZE},
        packet::{
            MAX_PACKET_PAYLOAD, PayloadType,
            advert::{self},
            encryption::{decrypt, decrypt_with_channel_secret},
            node::{NodeType, NodeTypeSet},
            path::Path,
            payload::{
                AdvertType, AnonRequestData, ControlData, NeighbourOrdering, Payload, RequestData,
                TextMessageType,
            },
        },
        telemetry::TelemetryPermissions,
    },
    sensor::GpsLocation,
    utils::Reader,
};

pub struct PayloadParser<'a> {
    pub identity: LocalIdentity,
    pub contacts: &'a Contacts,
}

impl PayloadParser<'_> {
    pub fn parse(self, data: &[u8], payload_type: PayloadType) -> ParserResult<Payload> {
        let payload = match payload_type {
            PayloadType::Trace => Self::parse_trace(data)?,
            PayloadType::Control => Self::parse_control(data)?,
            PayloadType::Ack => Self::parse_ack(data)?,
            PayloadType::MultiPart => Self::parse_multipart(data)?,
            PayloadType::Path
            | PayloadType::Request
            | PayloadType::Response
            | PayloadType::TextMessage => self.parse_encrypted(data, payload_type)?,
            PayloadType::AnonymousRequest => self.parse_anon_request(data)?,
            PayloadType::GroupText => self.parse_group_text(data)?,
            PayloadType::Advert => Self::parse_advert(data)?,
            PayloadType::RawCustom | PayloadType::GroupData => todo!(),
        };
        Ok(payload)
    }

    fn parse_group_text(&self, data: &[u8]) -> Result<Payload, ParserError> {
        let mut reader = Reader::new(data);
        let channel_hash = reader.take_u8()?;
        let ciphertext = reader.rest();
        let Some((plaintext, channel)) = self
            .contacts
            .get_matching_channels(channel_hash)
            .find_map(|channel| {
                let plaintext = decrypt_with_channel_secret(&channel.secret, ciphertext).ok()?;
                Some((plaintext, channel.clone()))
            })
        else {
            return Ok(Payload::Undecryptable);
        };
        let mut reader = Reader::new(&plaintext);
        let timestamp = reader.take_le_u32()?;
        let flags = reader.take_u8()?;
        let text_message_type = TextMessageType::try_from(flags >> 2)?;
        let mut message = [0u8; MAX_PACKET_PAYLOAD];
        let rest = reader.rest();
        message[..(rest.len())].copy_from_slice(rest);
        let message = CStr::from_bytes_until_nul(&message)
            .ok()
            .and_then(|s| s.to_str().ok())
            .and_then(|s| heapless::String::<MAX_PACKET_PAYLOAD>::try_from(s).ok())
            .ok_or(ParserError::InvalidInput)?;
        Ok(Payload::GroupText {
            channel,
            timestamp,
            text_message_type,
            message,
        })
    }

    fn parse_anon_request(&self, data: &[u8]) -> Result<Payload, ParserError> {
        let mut reader = Reader::new(data);
        let destination_hash = reader.take_u8()?;
        let sender_public_key = reader.take_chunk::<PUBLIC_KEY_SIZE>()?;
        let ciphertext = reader.rest();
        let shared = self
            .identity
            .get_shared_key_with_public_key(sender_public_key)
            .unwrap();
        let plaintext = decrypt(&shared, ciphertext)?;
        let mut reader = Reader::new(&plaintext);
        let timestamp = reader.take_le_u32()?;
        let request_type = reader.take_u8()?;
        let request_type = AnonRequestType::try_from(request_type)?;
        let request_data = match request_type {
            AnonRequestType::Login => {
                let password = reader.rest();
                let password = CStr::from_bytes_until_nul(password)
                    .ok()
                    .and_then(|s| s.to_str().ok())
                    .ok_or(ParserError::InvalidInput)?;
                let password = password.try_into()?;
                AnonRequestData::Login { password }
            }
            AnonRequestType::LoginNoPassword => AnonRequestData::LoginNoPassword,

            AnonRequestType::Regions | AnonRequestType::Owner | AnonRequestType::Basic => {
                let header = reader.take_u8()?;
                let path_count = header & 0b0011_1111;
                let path_hash_size = (header >> 6) + 1;
                let path_bytes = reader.take_slice((path_count * path_hash_size).into())?;
                let reply_path = match path_hash_size {
                    1 => Path::from_1_byte_slice(path_bytes),
                    2 => Path::from_2_byte_slice(path_bytes),
                    3 => Path::from_3_byte_slice(path_bytes),
                    _ => unreachable!(),
                }?;
                match request_type {
                    AnonRequestType::Regions => AnonRequestData::Regions { reply_path },
                    AnonRequestType::Owner => AnonRequestData::Owner { reply_path },
                    AnonRequestType::Basic => AnonRequestData::Basic { reply_path },
                    _ => unreachable!(),
                }
            }
        };
        Ok(Payload::AnonRequest(request_data))
    }

    fn parse_encrypted(&self, data: &[u8], payload_type: PayloadType) -> ParserResult<Payload> {
        let mut reader = Reader::new(data);
        let destination_hash = reader.take_u8()?;
        if destination_hash != self.identity.public[0] {
            return Ok(Payload::Undecryptable);
        }
        let source_hash = reader.take_u8()?;
        let ciphertext = reader.rest();
        let Some((id, plaintext)) =
            self.contacts
                .get_matching_nodes_iter(source_hash)
                .find_map(|id| {
                    let shared = self.identity.get_shared_key(id).ok()?;
                    let plaintext = decrypt(&shared, ciphertext).ok()?;
                    Some((id.clone(), plaintext))
                })
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
            0 => Path::from_1_byte_slice(rest)?,
            1 => Path::from_2_byte_slice(rest)?,
            2 => Path::from_3_byte_slice(rest)?,
            _ => return Err(ParserError::InvalidInput),
        };
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

    fn parse_advert(data: &[u8]) -> Result<Payload, ParserError> {
        let mut reader = Reader::new(data);
        let public_key = reader.take_chunk::<PUBLIC_KEY_SIZE>()?;
        let timestamp = reader.take_le_u32()?;
        let signature = reader.take_chunk::<SIGNATURE_SIZE>()?;
        let app_data = reader.rest();
        advert::verify_signature(&public_key, &signature, timestamp, app_data)?;
        let mut reader = Reader::new(app_data);
        let flags = reader.take_u8()?;
        let flags = AdvertFeatures::from(flags);
        let location = if flags.has_location() {
            let latitude = reader.take_le_i32()?;
            let longitude = reader.take_le_i32()?;
            Some(GpsLocation {
                latitude,
                longitude,
            })
        } else {
            None
        };
        let extra_1 = if flags.has_feature1() {
            Some(reader.take_le_u16()?)
        } else {
            None
        };
        let extra_2 = if flags.has_feature2() {
            Some(reader.take_le_u16()?)
        } else {
            None
        };
        let name = if flags.has_name() {
            let rest = reader.rest();
            let mut name = [0u8; MAX_PACKET_PAYLOAD];
            name[..(rest.len())].copy_from_slice(rest);
            let name = CStr::from_bytes_until_nul(&name)
                .ok()
                .and_then(|cstr| cstr.to_str().ok())
                .and_then(|s| heapless::String::<MAX_PACKET_PAYLOAD>::try_from(s).ok())
                .ok_or(ParserError::InvalidInput)?;
            Some(name)
        } else {
            None
        };
        Ok(Payload::Advert {
            id: RemoteIdentity { public: public_key },
            timestamp,
            signature,
            advert_type: flags.advert_type(),
            location,
            name,
            extra_1,
            extra_2,
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

#[bitsize(8)]
#[derive(TryFromBits)]
enum AnonRequestType {
    Login = 0x20, // ASCII space ' '
    LoginNoPassword = 0x0,
    Regions = 1,
    Owner = 2,
    Basic = 3,
}

#[bitsize(8)]
#[derive(FromBits)]
struct AdvertFeatures {
    advert_type: AdvertType,
    has_location: bool,
    has_feature1: bool,
    has_feature2: bool,
    has_name: bool,
}
