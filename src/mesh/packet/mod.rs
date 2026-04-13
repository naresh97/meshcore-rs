mod advert;
pub mod encryption;
mod node;
mod path;
mod payload;

use bilge::prelude::*;

use crate::{
    error::ParserResult,
    mesh::{
        contacts::Contacts,
        identity::LocalIdentity,
        packet::{path::Path, payload::PayloadParser},
    },
    utils::Reader,
};

pub const MAX_PATH_SIZE: usize = 64;
pub const MAX_PACKET_PAYLOAD: usize = 182;

#[derive(Debug)]
pub struct Packet {
    header: Header,
    transport_codes: Option<[u16; 2]>,
    path: Path,
    payload: payload::Payload,
}

#[bitsize(8)]
#[derive(DebugBits, FromBits)]
pub struct Header {
    pub route_type: RouteType,
    pub payload_type: PayloadType,
    pub version: u2,
}

#[bitsize(2)]
#[derive(Debug, FromBits, Clone, Copy)]
pub enum RouteType {
    TransportFlood,
    Flood,
    Direct,
    TransportDirect,
}
impl RouteType {
    pub fn is_direct(self) -> bool {
        matches!(self, RouteType::Direct | Self::TransportDirect)
    }
}

#[bitsize(4)]
#[derive(Debug, FromBits, Clone, Copy)]
pub enum PayloadType {
    Request,
    Response,
    TextMessage,
    Ack,
    Advert,
    GroupText,
    GroupData,
    AnonymousRequest,
    Path,
    Trace,
    MultiPart,
    Control,
    #[fallback]
    RawCustom = 0x0F,
}

#[bitsize(8)]
#[derive(FromBits)]
struct PathMetadata {
    length: u6,
    mode: u2,
}

impl Packet {
    pub fn parse(
        mut data: &[u8],
        identity: &LocalIdentity,
        contacts: &Contacts,
    ) -> ParserResult<Self> {
        let mut reader = Reader::new(data);
        let header = reader.take_u8()?;
        let header = Header::from(header);
        if header.version().as_usize() > 0 {
            return Err(crate::error::ParserError::UnsupportedVersion);
        }

        let transport_codes = {
            let has_transport_codes = matches!(
                header.route_type(),
                RouteType::TransportDirect | RouteType::TransportFlood
            );
            if has_transport_codes {
                let bytes = reader.take_chunk::<4>()?;
                let transport_codes: [u16; 2] = bytemuck::cast(bytes);
                Some(transport_codes)
            } else {
                None
            }
        };
        let path_metadata = reader.take_u8()?;
        let path_metadata = PathMetadata::from(path_metadata);
        let mode = path_metadata.mode().as_usize();
        let path_length = path_metadata.length().as_usize() * (mode + 1);
        let path = reader.take_slice(path_length)?;
        let path = match mode {
            0 => Path::from_1_byte_slice(path),
            1 => Path::from_2_byte_slice(path),
            2 => Path::from_3_byte_slice(path),
            _ => return Err(crate::error::ParserError::InvalidInput),
        }?;

        let payload_parser = PayloadParser {
            identity: identity.clone(),
            contacts,
        };
        let payload = payload_parser.parse(reader.rest(), header.payload_type())?;
        let packet = Packet {
            header,
            transport_codes,
            path,
            payload,
        };

        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use crate::mesh::packet::payload::Payload;

    use super::*;

    #[test]
    fn parse_header() {
        let header = 0x15;
        let header = Header::from(header);
        assert!(matches!(header.route_type(), RouteType::Flood));
        assert!(matches!(header.payload_type(), PayloadType::GroupText));
        assert_eq!(header.version().as_usize(), 0);
    }

    #[test]
    fn parse_packet() {
        let packet = "110D69042B6E0B7C3F2584818B3C2474328A18923E6062FB948B3D7FF2710E9E83177886160D17B886281A7D0A885AB70AD5699AED0F6844F1C3BC71D64257DE285DB3970ECC2F583D6C029CC47CDA1D082FA1FE5867DCC8866C52BAA5AFA8A31E9727405A92B07C372002A1B3CF67E0A7A2009298CB0C0377095B0048656C746563205634205270747220536F6C6172";
        let packet = hex::decode(packet).unwrap();
        let (id, contacts) = mocks();
        let packet = Packet::parse(&packet, &id, &contacts).unwrap();
        assert!(matches!(packet.header.route_type(), RouteType::Flood));
        assert!(matches!(packet.header.payload_type(), PayloadType::Advert));
        assert_eq!(packet.header.version().as_usize(), 0);

        {
            let Path::Hash1(v) = &packet.path else {
                panic!();
            };
            assert_eq!(
                v.as_slice(),
                hex::decode("69042B6E0B7C3F2584818B3C24").unwrap()
            );
        }
        let Payload::Advert {
            id,
            timestamp,
            location,
            name,
            extra_1,
            extra_2,
        } = packet.payload
        else {
            panic!()
        };
        assert_eq!(name.unwrap(), "Heltec V4 Rptr Solar");
        let location = location.unwrap();
        assert_eq!(location.latitude, 51_170_200);
        assert_eq!(location.longitude, 5_966_199);
        assert_eq!(timestamp, 1_775_569_591);
    }

    fn mocks() -> (LocalIdentity, Contacts) {
        (
            LocalIdentity::from_private_key(&hex::decode("104B70BC64F3FDBDEC6E9A9189C40C7B6A64E5D3A91B75D423EDF879C4C082605F852A0F473307596502D95238CE1FEC32C4BEBD7D119AE73974C2BFA650A1B3").unwrap().try_into().unwrap()),
            Contacts::new(),
        )
    }
}
