use heapless::CapacityError;

use crate::mesh::packet::MAX_PATH_SIZE;

pub const MAX_PATH_LENGTH_2_BYTE_HASH: usize = MAX_PATH_SIZE / 2;
pub const MAX_PATH_LENGTH_3_BYTE_HASH: usize = MAX_PATH_SIZE / 3;

#[derive(Debug, Clone)]
pub enum Path {
    Hash1(heapless::Vec<u8, MAX_PATH_SIZE>),
    Hash2(heapless::Vec<[u8; 2], MAX_PATH_LENGTH_2_BYTE_HASH>),
    Hash3(heapless::Vec<[u8; 3], MAX_PATH_LENGTH_3_BYTE_HASH>),
}
impl Path {
    pub fn from_1_byte_slice(data: &[u8]) -> Result<Self, CapacityError> {
        Ok(Self::Hash1(heapless::Vec::from_slice(data)?))
    }
    pub fn from_2_byte_slice(data: &[u8]) -> Result<Self, CapacityError> {
        let data: &[[u8; 2]] = bytemuck::cast_slice(data);
        Ok(Self::Hash2(heapless::Vec::from_slice(data)?))
    }
    pub fn from_3_byte_slice(data: &[u8]) -> Result<Self, CapacityError> {
        let data: &[[u8; 3]] = bytemuck::cast_slice(data);
        Ok(Self::Hash3(heapless::Vec::from_slice(data)?))
    }
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Path::Hash1(vec_inner) => vec_inner.as_slice(),
            Path::Hash2(vec_inner) => bytemuck::cast_slice(vec_inner.as_slice()),
            Path::Hash3(vec_inner) => bytemuck::cast_slice(vec_inner.as_slice()),
        }
    }
}
