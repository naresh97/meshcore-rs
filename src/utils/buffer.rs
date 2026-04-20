use heapless::CapacityError;

use crate::error::{ParserError, ParserResult};

pub struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Reader<'a> {
        Self(data)
    }
    pub fn take_u8(&mut self) -> ParserResult<u8> {
        let (&b, rest) = self.0.split_first().ok_or(ParserError::UnexpectedEof)?;
        self.0 = rest;
        Ok(b)
    }
    pub fn take_chunk<const N: usize>(&mut self) -> ParserResult<[u8; N]> {
        let (&b, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(ParserError::UnexpectedEof)?;
        self.0 = rest;
        Ok(b)
    }
    pub fn take_slice(&mut self, length: usize) -> ParserResult<&[u8]> {
        let (b, rest) = self
            .0
            .split_at_checked(length)
            .ok_or(ParserError::UnexpectedEof)?;
        self.0 = rest;
        Ok(b)
    }

    pub fn take_le_u32(&mut self) -> ParserResult<u32> {
        let b = self.take_chunk::<4>()?;
        let b = u32::from_le_bytes(b);
        Ok(b)
    }
    pub fn take_le_i32(&mut self) -> ParserResult<i32> {
        let b = self.take_chunk::<4>()?;
        let b = i32::from_le_bytes(b);
        Ok(b)
    }

    pub fn take_le_u16(&mut self) -> ParserResult<u16> {
        let b = self.take_chunk::<2>()?;
        let b = u16::from_le_bytes(b);
        Ok(b)
    }

    pub fn rest(self) -> &'a [u8] {
        self.0
    }
}

pub struct Writer<const N: usize>(heapless::Vec<u8, N>);
impl<const N: usize> Writer<N> {
    pub fn new() -> Self {
        Self(heapless::Vec::new())
    }

    pub fn put_u8(&mut self, b: u8) -> Result<(), CapacityError> {
        self.0.push(b).map_err(|_| CapacityError::default())
    }

    pub fn put_slice(&mut self, b: &[u8]) -> Result<(), CapacityError> {
        self.0
            .extend_from_slice(b)
            .map_err(|_| CapacityError::default())
    }

    pub fn put_le_u32(&mut self, b: u32) -> Result<(), CapacityError> {
        self.0.extend_from_slice(&b.to_le_bytes())
    }

    pub fn put_le_i32(&mut self, b: i32) -> Result<(), CapacityError> {
        self.0.extend_from_slice(&b.to_le_bytes())
    }

    pub fn put_le_u16(&mut self, b: u16) -> Result<(), CapacityError> {
        self.0.extend_from_slice(&b.to_le_bytes())
    }

    pub fn finish(self) -> heapless::Vec<u8, N> {
        self.0
    }
}
