use bilge::prelude::*;

#[derive(Debug, Clone, Copy)]
pub enum NodeType {
    Chat,
    Repeater,
    Room,
    Sensor,
}

impl NodeType {
    pub fn from_index(index: u8) -> Option<Self> {
        match index {
            1 => Some(Self::Chat),
            2 => Some(Self::Repeater),
            3 => Some(Self::Room),
            4 => Some(Self::Sensor),
            _ => None,
        }
    }
    pub fn to_index(self) -> u8 {
        match self {
            NodeType::Chat => 1,
            NodeType::Repeater => 2,
            NodeType::Room => 3,
            NodeType::Sensor => 4,
        }
    }
}

#[bitsize(8)]
#[derive(FromBits, DebugBits, Clone, Copy)]
pub struct NodeTypeSet {
    reserved: u3,
    is_sensor: bool,
    is_room: bool,
    is_repeater: bool,
    is_chat: bool,
    is_none: bool,
}
impl NodeTypeSet {
    pub fn contains(self, node_type: NodeType) -> bool {
        match node_type {
            NodeType::Chat => self.is_chat(),
            NodeType::Repeater => self.is_repeater(),
            NodeType::Room => self.is_room(),
            NodeType::Sensor => self.is_sensor(),
        }
    }
}
