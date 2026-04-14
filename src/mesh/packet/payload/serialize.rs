use core::time;

use crate::{
    error::SerializerResult,
    mesh::packet::{MAX_PACKET_PAYLOAD, encryption::encrypt_with_channel_secret, payload::Payload},
    utils::Writer,
};

pub trait PayloadSerializer {
    fn serialize(self) -> SerializerResult<heapless::Vec<u8, MAX_PACKET_PAYLOAD>>;
}
impl PayloadSerializer for Payload {
    fn serialize(self) -> SerializerResult<heapless::Vec<u8, MAX_PACKET_PAYLOAD>> {
        match self {
            Payload::Trace {
                trace_tag,
                auth_code,
                flags,
                path,
            } => todo!(),
            Payload::Control(control_data) => todo!(),
            Payload::Ack { crc } => todo!(),
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
                text_message_type,
                text,
            } => todo!(),
            Payload::Response { tag, payload } => todo!(),
            Payload::AnonRequest(anon_request_data) => todo!(),
            Payload::GroupText {
                channel,
                timestamp,
                message,
                text_message_type,
            } => {
                let mut writer = Writer::<MAX_PACKET_PAYLOAD>::new();
                writer.put_u8(channel.hash)?;

                let mut plaintext = Writer::<MAX_PACKET_PAYLOAD>::new();
                plaintext.put_le_u32(timestamp)?;
                let flags = u8::from(text_message_type) << 2;
                plaintext.put_u8(flags)?;
                plaintext.put_slice(message.as_bytes())?;
                let plaintext = plaintext.finish();
                let ciphertext =
                    encrypt_with_channel_secret(&channel.secret, plaintext.as_slice())?;

                writer.put_slice(&ciphertext);

                Ok(writer.finish())
            }
            Payload::Advert {
                id,
                timestamp,
                location,
                name,
                extra_1,
                extra_2,
            } => todo!(),
        }
    }
}
