#![cfg(test)]

use super::*;
use crate::mesh::{contacts::Contacts, packet::payload::parser::PayloadParser};

fn test_parser() -> PayloadParser {
    PayloadParser {
            identity: LocalIdentity::from_private_key(
                &hex::decode("104B70BC64F3FDBDEC6E9A9189C40C7B6A64E5D3A91B75D423EDF879C4C082605F852A0F473307596502D95238CE1FEC32C4BEBD7D119AE73974C2BFA650A1B3").unwrap().try_into().unwrap(),
            ),
            contacts: Contacts {},
        }
}

#[test]
fn parse_trace() {
    let payload = "4864DE9B0000000001FDA6899884988998FDA6";
    let payload = hex::decode(payload).unwrap();
    let Payload::Trace {
        trace_tag,
        auth_code,
        flags,
        path,
    } = test_parser().parse(&payload, PayloadType::Trace).unwrap()
    else {
        panic!()
    };
    assert_eq!(hex::decode("4864DE9B").unwrap(), trace_tag.to_le_bytes());
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
    let payload = "92D071650845287E613F77754F51DD72848A5A5A35DC23AAE3D49B743E296B247AA9F29202FD";
    let payload = hex::decode(payload).unwrap();
    let Payload::Control(ControlData::DiscoverResponse {
        tag,
        node_type,
        identity,
    }) = test_parser().parse(&payload, PayloadType::Control).unwrap()
    else {
        panic!();
    };
    assert!(matches!(node_type, NodeType::Repeater));
    assert_eq!(hex::decode("71650845").unwrap(), tag.to_le_bytes());
    assert_eq!(
        hex::decode("287E613F77754F51DD72848A5A5A35DC23AAE3D49B743E296B247AA9F29202FD").unwrap(),
        identity.public
    );
}

#[test]
fn parse_control_discover_request() {
    let payload = "800476501AE400000000";
    let payload = hex::decode(payload).unwrap();
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
    assert_eq!(hex::decode("76501AE4").unwrap(), tag.to_le_bytes());
    assert!(filter.contains(NodeType::Repeater));
    assert!(!filter.contains(NodeType::Chat));
    assert!(!filter.contains(NodeType::Room));
    assert!(!filter.contains(NodeType::Sensor));
}

#[test]
fn parse_multipart() {
    let payload = "284D0EB1C4C82936AEA94F00E39D27B628579A769F668AB266F85D188A56834C041E957C5CC533A91DA26DCED3DEF2856AD883BBB064AB7F11DEB2FC3AD4FA03642ACF23435820E7AD35D7A75C64BDED6E3444E3D75B238B3E5F158FAD2B7856F515";
    let payload = hex::decode(payload).unwrap();
    let _payload = test_parser()
        .parse(&payload, PayloadType::MultiPart)
        .unwrap();
}
