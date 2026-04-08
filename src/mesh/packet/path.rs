use crate::mesh::packet::raw::MAX_PATH_SIZE;

pub const MAX_PATH_LENGTH_2_BYTE_HASH: usize = MAX_PATH_SIZE / 2;
pub const MAX_PATH_LENGTH_3_BYTE_HASH: usize = MAX_PATH_SIZE / 3;

#[derive(Debug)]
pub enum Path {
    Hash1(heapless::Vec<u8, MAX_PATH_SIZE>),
    Hash2(heapless::Vec<[u8; 2], MAX_PATH_LENGTH_2_BYTE_HASH>),
    Hash3(heapless::Vec<[u8; 3], MAX_PATH_LENGTH_3_BYTE_HASH>),
}
impl Path {
    pub fn from_1_byte_slice(data: &[u8]) -> Option<Self> {
        Some(Self::Hash1(heapless::Vec::from_slice(data).ok()?))
    }
    pub fn from_2_byte_slice(data: &[u8]) -> Option<Self> {
        let data: &[[u8; 2]] = bytemuck::cast_slice(data);
        Some(Self::Hash2(heapless::Vec::from_slice(data).ok()?))
    }
    pub fn from_3_byte_slice(data: &[u8]) -> Option<Self> {
        let data: &[[u8; 3]] = bytemuck::cast_slice(data);
        Some(Self::Hash3(heapless::Vec::from_slice(data).ok()?))
    }
}
