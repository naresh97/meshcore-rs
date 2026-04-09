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
