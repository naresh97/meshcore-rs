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
    pub fn rest(self) -> &'a [u8] {
        self.0
    }
}
