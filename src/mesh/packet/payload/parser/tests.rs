#![cfg(test)]

use core::time;

use super::*;
use crate::mesh::{
    channel::ChannelIdentity, contacts::Contacts, packet::payload::parser::PayloadParser,
};

fn test_parser() -> PayloadParser {
    PayloadParser {
            identity: LocalIdentity::from_private_key(
                &dehex("104B70BC64F3FDBDEC6E9A9189C40C7B6A64E5D3A91B75D423EDF879C4C082605F852A0F473307596502D95238CE1FEC32C4BEBD7D119AE73974C2BFA650A1B3").try_into().unwrap(),
            ),
            contacts: Contacts::new(),
        }
}

fn dehex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

#[test]
fn parse_trace() {
    let payload = dehex("4864DE9B0000000001FDA6899884988998FDA6");
    let Payload::Trace {
        trace_tag,
        auth_code,
        flags,
        path,
    } = test_parser().parse(&payload, PayloadType::Trace).unwrap()
    else {
        panic!()
    };
    assert_eq!(dehex("4864DE9B"), trace_tag.to_le_bytes());
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
        dehex("92D071650845287E613F77754F51DD72848A5A5A35DC23AAE3D49B743E296B247AA9F29202FD");
    let Payload::Control(ControlData::DiscoverResponse {
        tag,
        node_type,
        identity,
    }) = test_parser().parse(&payload, PayloadType::Control).unwrap()
    else {
        panic!();
    };
    assert!(matches!(node_type, NodeType::Repeater));
    assert_eq!(dehex("71650845"), tag.to_le_bytes());
    assert_eq!(
        dehex("287E613F77754F51DD72848A5A5A35DC23AAE3D49B743E296B247AA9F29202FD"),
        identity.public
    );
}

#[test]
fn parse_control_discover_request() {
    let payload = dehex("800476501AE400000000");
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
    assert_eq!(dehex("76501AE4"), tag.to_le_bytes());
    assert!(filter.contains(NodeType::Repeater));
    assert!(!filter.contains(NodeType::Chat));
    assert!(!filter.contains(NodeType::Room));
    assert!(!filter.contains(NodeType::Sensor));
}

#[test]
fn parse_multipart() {
    let payload = dehex(
        "284D0EB1C4C82936AEA94F00E39D27B628579A769F668AB266F85D188A56834C041E957C5CC533A91DA26DCED3DEF2856AD883BBB064AB7F11DEB2FC3AD4FA03642ACF23435820E7AD35D7A75C64BDED6E3444E3D75B238B3E5F158FAD2B7856F515",
    );
    let _payload = test_parser()
        .parse(&payload, PayloadType::MultiPart)
        .unwrap();
}

#[test]
fn parse_advert() {
    let payload = dehex(
        "47B843A0309A6FB832084EE1ED43FC671B0AD2A0FB126B3E763925CF79A21C49B0254D667C46B104E5AF723DBBC1B20EC84AFB397CCF67FF38F325232AFA390E6CA0D87FD967A3501F4B4ED41153CA1268D0F3893F967A85E4344E4C034D20F7010E890292E633FCFD964E0309F09FA694202D20436173746C6563726167",
    );
    let payload = test_parser().parse(&payload, PayloadType::Advert).unwrap();
    let Payload::Advert {
        id,
        timestamp,
        location,
        name,
        extra_1,
        extra_2,
    } = payload
    else {
        panic!()
    };
    assert_eq!(
        Some("🦔 - Castlecrag"),
        name.map(|s| s.as_str().to_string()).as_deref()
    );
    assert_eq!(
        dehex("47B843A0309A6FB832084EE1ED43FC671B0AD2A0FB126B3E763925CF79A21C49"),
        id.public
    );
    assert_eq!(timestamp, 1_716_331_952);
    let Some(GpsLocation {
        latitude,
        longitude,
    }) = location
    else {
        panic!()
    };
    assert_eq!((latitude, longitude), (-33_803_290, 151_211_670));
}

#[test]
fn parse_ack() {
    let payload = dehex("C6413FBE");
    let Payload::Ack { crc } = test_parser().parse(&payload, PayloadType::Ack).unwrap() else {
        panic!()
    };
    assert_eq!(
        u32::from_le_bytes(dehex("C6413FBE").try_into().unwrap()),
        crc
    );
}

//#[test]
fn parse_text_message() {
    todo!("Use leakable private key");
    let mut parser = PayloadParser {
        identity: LocalIdentity::from_private_key(&dehex("").try_into().unwrap()),
        contacts: Contacts::new(),
    };

    parser.contacts.insert_node(
        dehex("255100a473caaeecb8e685ba6d8582abaa5761d63f73b83382c9640d237db580")
            .try_into()
            .unwrap(),
    );
    let payload = dehex("D3255365327C88F64780F6EFAE4747F8598D425D330266F0C7AEEEED8923FF59D9DE1DB6");
    let payload = parser.parse(&payload, PayloadType::TextMessage).unwrap();

    let Payload::TextMessage {
        text_message_type,
        text,
    } = payload
    else {
        dbg!(payload);
        panic!();
    };
    assert!(matches!(text_message_type, TextMessageType::Plain));
    assert_eq!("Rust is cool!", text);
}

#[test]
fn parse_group_text() {
    let mut parser = test_parser();
    let id = ChannelIdentity::from_hashtag("#test");
    parser.contacts.insert_channel(id);
    let payload = dehex("D96A8977303734A72FEAD4904178434951288D14B203E4E8F0B9B945F55EC50FDA81B5");
    let Payload::GroupText {
        timestamp,
        message,
        text_message_type,
    } = parser.parse(&payload, PayloadType::GroupText).unwrap()
    else {
        panic!()
    };
    assert_eq!("Yuzu43: test", message);
    assert!(matches!(text_message_type, TextMessageType::Plain));
    assert_eq!(1_776_024_490, timestamp);
}
