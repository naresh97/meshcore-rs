use bilge::BitsError;
use heapless::CapacityError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HardwareError {
    #[error("radio error")]
    Radio(&'static str),
}

pub type HardwareResult<T> = Result<T, HardwareError>;

#[derive(Debug)]
pub enum EncryptionError {
    //The provided message cannot be validated with the corresponding HMAC
    HmacValidationFailed,
    //The intended messages requires too much space to compute
    OutOfSpace,
    //The secret key provided for HMAC generation is invalid (wrong length)
    HmacInvalidSecret,
    //The HMAC could not be generated for the provided message"
    HmacGenerationFailed,
    //The ciphertext provided is malformed"
    MalformedCiphertext,
    //The secret provided is malformed"
    MalformedSecret,
}
pub type EncryptionResult<T> = Result<T, EncryptionError>;

#[derive(Debug)]
pub enum ParserError {
    UnexpectedEof,
    InvalidInput,
    CapacityExceeded,
    VersionMismatch,
}
pub type ParserResult<T> = Result<T, ParserError>;
impl From<CapacityError> for ParserError {
    fn from(_: CapacityError) -> Self {
        ParserError::CapacityExceeded
    }
}
impl From<BitsError> for ParserError {
    fn from(_: BitsError) -> Self {
        ParserError::InvalidInput
    }
}
