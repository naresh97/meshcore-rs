use bilge::prelude::*;

pub const MAX_PATH_SIZE: usize = 64;
pub const MAX_PACKET_PAYLOAD: usize = 182;

pub struct Packet {
    header: Header,
    transport_codes: Option<[u16; 2]>,
    path_metadata: PathMetadata,
    path: heapless::Vec<u8, MAX_PATH_SIZE>,
    payload: heapless::Vec<u8, MAX_PACKET_PAYLOAD>,
}

#[bitsize(8)]
#[derive(FromBits)]
pub struct Header {
    pub route_type: RouteType,
    pub payload_type: PayloadType,
    pub version: u2,
}

#[bitsize(2)]
#[derive(FromBits, Clone, Copy)]
pub enum RouteType {
    TransportFlood,
    Flood,
    Direct,
    TransportDirect,
}
impl RouteType {
    pub fn is_direct(&self) -> bool {
        match self {
            RouteType::Direct | Self::TransportDirect => true,
            _ => false,
        }
    }
}

#[bitsize(4)]
#[derive(FromBits, Clone, Copy)]
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
    pub fn parse(mut data: &[u8]) -> Option<Self> {
        let (&header, rest) = data.split_first()?;
        data = rest;
        let header = Header::from(header);
        if header.version().as_usize() > 0 {
            return None;
        }

        let transport_codes = {
            let has_transport_codes = matches!(
                header.route_type(),
                RouteType::TransportDirect | RouteType::TransportFlood
            );
            if has_transport_codes {
                let (bytes, rest) = data.split_at_checked(4)?;
                data = rest;
                let transport_codes: [u16; 2] = bytemuck::cast_slice(bytes).try_into().ok()?;
                Some(transport_codes)
            } else {
                None
            }
        };

        let (&path_metadata, rest) = data.split_first()?;
        data = rest;
        let path_metadata = PathMetadata::from(path_metadata);
        let mode = path_metadata.mode().as_usize();
        if mode == 3 {
            return None;
        }
        let path_length = path_metadata.length().as_usize() * (mode + 1);
        let (path, rest) = data.split_at_checked(path_length)?;
        data = rest;

        let packet = Packet {
            header,
            transport_codes,
            path_metadata,
            path: heapless::Vec::from_slice(path).ok()?,
            payload: heapless::Vec::from_slice(data).ok()?,
        };

        Some(packet)
    }
}

#[cfg(test)]
mod tests {
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
        let packet = Packet::parse(&packet).unwrap();
        assert!(matches!(packet.header.route_type(), RouteType::Flood));
        assert!(matches!(packet.header.payload_type(), PayloadType::Advert));
        assert_eq!(packet.header.version().as_usize(), 0);
        assert_eq!(packet.path_metadata.mode().as_usize(), 0);
        assert_eq!(packet.path_metadata.length().as_usize(), 13);
        assert_eq!(
            packet.path.as_slice(),
            hex::decode("69042B6E0B7C3F2584818B3C24").unwrap()
        );
        assert_eq!(packet.payload.as_slice(), hex::decode("74328A18923E6062FB948B3D7FF2710E9E83177886160D17B886281A7D0A885AB70AD5699AED0F6844F1C3BC71D64257DE285DB3970ECC2F583D6C029CC47CDA1D082FA1FE5867DCC8866C52BAA5AFA8A31E9727405A92B07C372002A1B3CF67E0A7A2009298CB0C0377095B0048656C746563205634205270747220536F6C6172").unwrap());
    }
}
