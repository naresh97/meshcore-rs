use core::marker::PhantomData;

use crate::error::HardwareResult;

pub trait Radio
where
    Self: Sized,
{
    fn new() -> HardwareResult<Self>;

    fn set_frequency(&mut self, frequency: f32) -> HardwareResult<()>;
    fn set_spreading_factor(&mut self, spreading_factor: u8) -> HardwareResult<()>;
    fn set_bandwidth(&mut self, bandwidth: f32) -> HardwareResult<()>;
    fn set_coding_rate(&mut self, coding_rate: u8) -> HardwareResult<()>;
    fn set_output_power(&mut self, power_dbm: u8) -> HardwareResult<()>;

    fn is_receiving_packet(&self) -> HardwareResult<bool>;
    fn current_rssi(&self) -> HardwareResult<i32>;
}

struct RadioDriver<R: Radio> {
    radio: R,
    state: RadioState,

    noise_floor_n: usize,
    noise_floor_sum: isize,
    noise_floor: isize,
}

impl<R: Radio> RadioDriver<R> {
    fn run(&mut self) -> HardwareResult<()> {
        self.calculate_noise_floor();
        Ok(())
    }

    fn calculate_noise_floor(&mut self) {
        const NUMBER_OF_SAMPLES: usize = 64;
        const SAMPLING_THRESHOLD: isize = 14;
        const LOWER_THRESHOLD: isize = -120;

        if matches!(self.state, RadioState::Rx)
            && self.noise_floor_n < NUMBER_OF_SAMPLES
            && !self.radio.is_receiving_packet().unwrap_or(true)
        {
            let Ok(rssi) = self.radio.current_rssi() else {
                return;
            };
            let rssi = rssi as isize;
            if (rssi < self.noise_floor + SAMPLING_THRESHOLD) {
                self.noise_floor_n = self.noise_floor_n.saturating_add(1);
                self.noise_floor_sum = self.noise_floor_sum.saturating_add(rssi);
            }
        } else if self.noise_floor_n >= NUMBER_OF_SAMPLES && self.noise_floor_sum != 0 {
            self.noise_floor = self.noise_floor_sum / NUMBER_OF_SAMPLES.cast_signed();
            if self.noise_floor < LOWER_THRESHOLD {
                self.noise_floor = LOWER_THRESHOLD;
            }
            self.noise_floor_sum = 0;
        }

        todo!()
    }
}

pub enum RadioState {
    Idle,
    Rx,
    TxWait,
    TxDone,
    IntReady,
}
