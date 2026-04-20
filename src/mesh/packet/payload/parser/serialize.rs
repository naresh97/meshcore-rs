use crate::{
    error::SerializerResult,
    mesh::{
        channel::ChannelIdentity,
        identity::LocalIdentity,
        packet::{
            MAX_PACKET_PAYLOAD,
            encryption::{encrypt, encrypt_with_channel_secret},
            path::Path,
            payload::{
                ControlData, Payload,
                parser::{AdvertFeatures, ControlType},
            },
        },
    },
    utils::Writer,
};
use bilge::prelude::*;
type PayloadSerializerResult = SerializerResult<heapless::Vec<u8, MAX_PACKET_PAYLOAD>>;

pub trait PayloadSerializer {
    fn serialize(self, identity: &LocalIdentity) -> PayloadSerializerResult;
}
impl PayloadSerializer for Payload {
    #[allow(unused_variables)]
    fn serialize(self, identity: &LocalIdentity) -> PayloadSerializerResult {
        match self {
            Payload::Trace {
                trace_tag,
                auth_code,
                flags,
                path,
            } => {
                let mut writer = Writer::new();

                writer.put_le_u32(trace_tag)?;
                writer.put_le_u32(auth_code)?;

                let path_hash_size: u8 = match &path {
                    Path::Hash1(_) => 0,
                    Path::Hash2(_) => 1,
                    Path::Hash3(_) => 2,
                };
                let flags = (flags & 0b1111_1000) | path_hash_size;
                writer.put_u8(flags)?;
                writer.put_slice(path.as_slice())?;
                Ok(writer.finish())
            }
            Payload::Control(control_data) => serialize_control(control_data),
            Payload::Ack { crc } => serialize_ack(crc),
            Payload::MultiPart {
                remaining_packets,
                payload_type,
                payload,
            } => todo!(),
            Payload::Undecryptable => todo!(),
            Payload::Path {
                source_hash,
                path,
                extra_type,
                extra,
            } => todo!(),
            Payload::Request(request_data) => todo!(),
            Payload::TextMessage {
                remote,
                timestamp,
                text_message_type,
                text,
            } => {
                let mut plaintext = Writer::<MAX_PACKET_PAYLOAD>::new();
                plaintext.put_le_u32(timestamp)?;
                let flags = u8::from(text_message_type) << 2;
                plaintext.put_u8(flags)?;
                plaintext.put_slice(text.as_bytes())?;
                let plaintext = plaintext.finish();

                let shared_key = identity.get_shared_key(&remote)?;
                let ciphertext = encrypt(&shared_key, &plaintext)?;

                let mut writer = Writer::new();

                let destination_hash = remote.public[0];
                writer.put_u8(destination_hash)?;
                let source_hash = identity.public[0];
                writer.put_u8(source_hash)?;

                Ok(writer.finish())
            }
            Payload::Response { tag, payload } => todo!(),
            Payload::AnonRequest(anon_request_data) => todo!(),
            Payload::GroupText {
                channel,
                timestamp,
                message,
                text_message_type,
            } => serialize_group_text(&channel, timestamp, &message, text_message_type),
            Payload::Advert {
                id,
                timestamp,
                signature,
                location,
                name,
                extra_1,
                extra_2,
                advert_type,
            } => serialize_advert(
                &id,
                timestamp,
                signature,
                location,
                name,
                extra_1,
                extra_2,
                advert_type,
            ),
        }
    }
}

fn serialize_control(control_data: ControlData) -> PayloadSerializerResult {
    match control_data {
        ControlData::DiscoverRequest {
            filter,
            tag,
            only_prefix,
            since,
        } => {
            let mut writer = Writer::new();
            let mut header = u4::from(ControlType::DiscoverRequest).as_u8() << 4;
            if only_prefix {
                header |= 0b1;
            }
            writer.put_u8(header)?;
            writer.put_u8(filter.into())?;
            writer.put_le_u32(tag)?;
            if let Some(since) = since {
                writer.put_le_u32(since)?;
            }
            Ok(writer.finish())
        }
        ControlData::DiscoverResponse {
            filter,
            tag,
            node_type,
            identity,
        } => {
            let mut writer = Writer::new();
            let header = u4::from(ControlType::DiscoverResponse).as_u8() << 4;
            let header = header | (node_type.to_index() & 0b1111);
            writer.put_u8(header)?;
            writer.put_u8(filter.into())?;
            writer.put_le_u32(tag)?;
            writer.put_slice(&identity.public)?;
            Ok(writer.finish())
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn serialize_advert(
    id: &crate::mesh::identity::RemoteIdentity,
    timestamp: u32,
    signature: [u8; 64],
    location: Option<crate::sensor::GpsLocation>,
    name: Option<heapless::String<MAX_PACKET_PAYLOAD>>,
    extra_1: Option<u16>,
    extra_2: Option<u16>,
    advert_type: crate::mesh::packet::payload::AdvertType,
) -> PayloadSerializerResult {
    let mut writer = Writer::new();
    writer.put_slice(&id.public)?;
    writer.put_le_u32(timestamp)?;
    writer.put_slice(&signature)?;
    let app_data = {
        let mut writer = Writer::<MAX_PACKET_PAYLOAD>::new();
        let flags = AdvertFeatures::new(
            advert_type,
            location.is_some(),
            extra_1.is_some(),
            extra_2.is_some(),
            name.is_some(),
        );
        let flags = u8::from(flags);
        writer.put_u8(flags)?;
        if let Some(location) = location {
            writer.put_le_i32(location.latitude)?;
            writer.put_le_i32(location.longitude)?;
        }
        if let Some(extra_1) = extra_1 {
            writer.put_le_u16(extra_1)?;
        }
        if let Some(extra_2) = extra_2 {
            writer.put_le_u16(extra_2)?;
        }
        if let Some(name) = name {
            writer.put_slice(name.as_bytes())?;
        }
        writer.finish()
    };
    writer.put_slice(&app_data)?;
    Ok(writer.finish())
}

fn serialize_ack(crc: u32) -> PayloadSerializerResult {
    let mut writer = Writer::new();
    writer.put_le_u32(crc)?;
    Ok(writer.finish())
}

fn serialize_group_text(
    channel: &ChannelIdentity,
    timestamp: u32,
    message: &heapless::String<MAX_PACKET_PAYLOAD>,
    text_message_type: super::TextMessageType,
) -> PayloadSerializerResult {
    let mut writer = Writer::<MAX_PACKET_PAYLOAD>::new();
    writer.put_u8(channel.hash)?;

    let mut plaintext = Writer::<MAX_PACKET_PAYLOAD>::new();
    plaintext.put_le_u32(timestamp)?;
    let flags = u8::from(text_message_type) << 2;
    plaintext.put_u8(flags)?;
    plaintext.put_slice(message.as_bytes())?;
    let plaintext = plaintext.finish();
    let ciphertext = encrypt_with_channel_secret(&channel.secret, plaintext.as_slice())?;

    writer.put_slice(&ciphertext)?;

    Ok(writer.finish())
}
