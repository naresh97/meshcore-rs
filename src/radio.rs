use crate::error::HardwareResult;

pub trait Radio
where
    Self: Sized,
{
    fn new() -> HardwareResult<Self>;
    fn params(&self) -> &RadioParams;
    fn set_params(&mut self, params: RadioParams) -> HardwareResult<()>;
    fn set_tx_power(&mut self, tx_power: u8) -> HardwareResult<()>;
}
pub struct RadioParams {}
