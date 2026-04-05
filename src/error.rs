use thiserror::Error;

#[derive(Debug, Error)]
pub enum HardwareError {
    #[error("radio error")]
    Radio(&'static str),
}
pub type HardwareResult<T> = Result<T, HardwareError>;
