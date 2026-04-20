use core::marker::PhantomData;

use crate::{
    mesh::preferences::Preferences,
    platform::Platform,
    radio::{Radio, RadioState},
};

const CALIBRATION_INTERVAL_MS: usize = 2000;
const NUMBER_OF_SAMPLES: usize = 64;
const SAMPLING_THRESHOLD: isize = 14;
const LOWER_THRESHOLD: isize = -120;

pub struct NoiseFloor<R: Radio, P: Platform> {
    samples: usize,
    sum: isize,
    value: isize,
    threshold: isize,
    since_last_calibration_ms: usize,

    _r: PhantomData<R>,
    _p: PhantomData<P>,
}
impl<R: Radio, P: Platform> NoiseFloor<R, P> {
    pub fn run(&mut self, preferences: &Preferences, state: RadioState, radio: &R) {
        let timestamp = P::timestamp_ms();
        if timestamp - self.since_last_calibration_ms >= CALIBRATION_INTERVAL_MS {
            self.recalibrate(preferences.radio_interference_threshold);
        }
        self.run_sampling(state, radio);
    }
    pub fn reset(&mut self) {
        self.value = 0;
        self.samples = 0;
        self.sum = 0;
    }
    pub fn run_sampling(&mut self, state: RadioState, radio: &R) {
        if matches!(state, RadioState::Rx)
            && self.samples < NUMBER_OF_SAMPLES
            && !radio.is_receiving_packet().unwrap_or(true)
        {
            let Ok(rssi) = radio.current_rssi() else {
                return;
            };
            let rssi = rssi as isize;
            if rssi < self.value + SAMPLING_THRESHOLD {
                self.samples = self.samples.saturating_add(1);
                self.sum = self.sum.saturating_add(rssi);
            }
        } else if self.samples >= NUMBER_OF_SAMPLES && self.sum != 0 {
            self.value = self.sum / NUMBER_OF_SAMPLES.cast_signed();
            if self.value < LOWER_THRESHOLD {
                self.value = LOWER_THRESHOLD;
            }
            self.sum = 0;
        }
    }
    fn recalibrate(&mut self, threshold: isize) {
        self.threshold = threshold;
        if self.samples >= NUMBER_OF_SAMPLES {
            self.samples = 0;
            self.sum = 0;
        }
    }
}
