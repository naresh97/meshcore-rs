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
    InvalidSignature,
    InvalidPublicKey,
    InvalidPrivateKey,
}
pub type EncryptionResult<T> = Result<T, EncryptionError>;

#[derive(Debug)]
pub enum ParserError {
    UnexpectedEof,
    InvalidInput,
    CapacityExceeded,
    VersionMismatch,
    EncryptionError(EncryptionError),
    UnsupportedVersion,
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
impl From<EncryptionError> for ParserError {
    fn from(value: EncryptionError) -> Self {
        ParserError::EncryptionError(value)
    }
}

#[derive(Debug)]
pub enum SerializerError {
    CapacityExceeded,
    EncryptionError(EncryptionError),
}

pub type SerializerResult<T> = Result<T, SerializerError>;

impl From<CapacityError> for SerializerError {
    fn from(_: CapacityError) -> Self {
        SerializerError::CapacityExceeded
    }
}
impl From<EncryptionError> for SerializerError {
    fn from(value: EncryptionError) -> Self {
        SerializerError::EncryptionError(value)
    }
}
