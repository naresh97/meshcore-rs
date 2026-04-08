use bilge::prelude::*;

#[derive(Clone, Copy)]
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
}

#[bitsize(8)]
#[derive(FromBits, Clone, Copy)]
pub struct NodeTypeSet {
    is_none: bool,
    is_chat: bool,
    is_repeater: bool,
    is_room: bool,
    is_sensor: bool,
    reserved: u3,
}
impl NodeTypeSet {
    pub fn contains(&self, node_type: NodeType) -> bool {
        match node_type {
            NodeType::Chat => self.is_chat(),
            NodeType::Repeater => self.is_repeater(),
            NodeType::Room => self.is_room(),
            NodeType::Sensor => self.is_sensor(),
        }
    }
}
