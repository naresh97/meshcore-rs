use thiserror::Error;

#[derive(Debug, Error)]
pub enum HardwareError {
    #[error("radio error")]
    Radio(&'static str),
}

pub type HardwareResult<T> = Result<T, HardwareError>;

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("The provided message cannot be validated with the corresponding HMAC")]
    HmacValidationFailed,
    #[error("The intended messages requires too much space to compute")]
    OutOfSpace,
    #[error("The secret key provided for HMAC generation is invalid (wrong length)")]
    HmacInvalidSecret,
    #[error("The HMAC could not be generated for the provided message")]
    HmacGenerationFailed,
    #[error("The ciphertext provided is malformed")]
    MalformedCiphertext,
    #[error("The secret provided is malformed")]
    MalformedSecret,
    #[error("Error generating public key: {0}")]
    PublicKeyGeneration(&'static str),
}
pub type EncryptionResult<T> = Result<T, EncryptionError>;

#[derive(Debug, Error)]
pub enum ParserError {
    #[error("Unexpected end was reached while parsing in {0}. Expected {2} bytes for {1}")]
    UnexpectedEnd(&'static str, &'static str, i32),
    #[error(
        "Capacity exceeded in {0}. Attempted to store an array {1} that exceeds the specified capacity {2}"
    )]
    ExceedsCapacity(&'static str, &'static str, usize),
    #[error("Error while parsing the bits for {1} in {0}")]
    BitParsingError(&'static str, &'static str),
    #[error("A payload was provided that is yet undefined")]
    UndefinedPayload,
}
pub type ParserResult<T> = Result<T, ParserError>;
