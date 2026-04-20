mod noise_floor;

use core::marker::PhantomData;

use crate::{
    error::HardwareResult,
    mesh::{packet::Packet, preferences::Preferences, queue::PacketQueue},
    platform::Platform,
    radio::noise_floor::NoiseFloor,
};

const MAX_TRANSMISSION_LENGTH: usize = 255;

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

    fn finish_transmit(&self) -> HardwareResult<()>;

    fn sleep(&self) -> HardwareResult<()>;

    fn read_data(&self) -> HardwareResult<Option<heapless::Vec<u8, MAX_TRANSMISSION_LENGTH>>>;
    fn start_receive(&self) -> HardwareResult<()>;
}

struct RadioDriver<R: Radio, P: Platform> {
    radio: R,
    preferences: Preferences,

    state: RadioState,
    is_ready: bool,
    error_states: ErrorStates,

    noise_floor: NoiseFloor<R, P>,

    previous_is_in_rx: bool,
    not_in_rx_since: usize,

    outbound_packet: Option<Packet>,
    outbound_since: usize,
    outbound_expiry: usize,
    n_sent: usize,
    total_airtime: usize,
    last_budget_update: usize,
    tx_budget_ms: usize,
    next_tx_time: usize,

    next_agc_reset_time: usize,

    rx_queue: PacketQueue<P>,

    _p: PhantomData<P>,
}

struct ErrorStates {
    start_rx_timeout: bool,
}

impl<R: Radio, P: Platform> RadioDriver<R, P> {
    const MIN_TX_BUDGET_RESERVE_MS: usize = 100;

    fn run(&mut self) {
        let timestamp = P::timestamp_ms();

        self.noise_floor
            .run(&self.preferences, self.state, &self.radio);

        let is_in_rx = matches!(self.state, RadioState::Rx);
        if is_in_rx != self.previous_is_in_rx {
            self.previous_is_in_rx = is_in_rx;
            if !is_in_rx {
                self.not_in_rx_since = timestamp;
            }
        }
        if !is_in_rx && (timestamp.saturating_sub(self.not_in_rx_since) > 8000) {
            self.error_states.start_rx_timeout = true;
        }

        if self.outbound_packet.is_some() {
            if self.is_send_complete() {
                let tx_duration = timestamp - self.outbound_since;
                self.total_airtime += tx_duration;
                self.update_tx_budget();
                if tx_duration > self.tx_budget_ms {
                    self.tx_budget_ms = 0;
                } else {
                    self.tx_budget_ms -= tx_duration;
                }

                #[allow(
                    clippy::cast_possible_truncation,
                    clippy::cast_sign_loss,
                    clippy::cast_precision_loss
                )]
                if self.tx_budget_ms < Self::MIN_TX_BUDGET_RESERVE_MS {
                    let duty_cycle = 1.0 / (1.0 + self.preferences.airtime_budget_factor);
                    let needed = Self::MIN_TX_BUDGET_RESERVE_MS - self.tx_budget_ms;
                    self.next_tx_time = timestamp + (needed as f32 / duty_cycle) as usize;
                } else {
                    self.next_tx_time = timestamp;
                }

                self.on_send_finished();
                self.outbound_packet = None;
            } else if self.outbound_expiry >= timestamp {
                self.on_send_finished();
                self.outbound_packet = None;
            } else {
                return;
            }

            self.next_agc_reset_time = timestamp + self.preferences.agc_reset_interval_ms * 4000;
        }

        if self.preferences.agc_reset_interval_ms > 0 && timestamp > self.next_agc_reset_time {
            self.reset_agc();
            self.next_agc_reset_time = timestamp + self.preferences.agc_reset_interval_ms * 4000;
        }
    }

    fn receive_raw(&mut self) {
        if self.is_ready {
            let _data = self.radio.read_data();
            self.state = RadioState::Idle;
        }
        if !matches!(self.state, RadioState::Rx) && self.radio.start_receive().is_ok() {
            self.state = RadioState::Rx;
        }
    }

    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    fn update_tx_budget(&mut self) {
        const ONE_HOUR_MS: f32 = 3_600_000_f32;

        let now = P::timestamp_ms();
        let elapsed = now - self.last_budget_update;
        let duty_cycle = 1.0 / (1.0 + self.preferences.airtime_budget_factor);
        let max_budget: usize = (ONE_HOUR_MS * duty_cycle) as usize;
        let refill = (elapsed as f32 * duty_cycle) as usize;
        if refill > 0 {
            self.tx_budget_ms += refill;
            if self.tx_budget_ms > max_budget {
                self.tx_budget_ms = max_budget;
            }
            self.last_budget_update = now;
        }
    }

    fn is_send_complete(&mut self) -> bool {
        if self.is_ready {
            self.state = RadioState::Idle;
            self.n_sent += 1;
            true
        } else {
            false
        }
    }

    fn on_send_finished(&mut self) {
        _ = self.radio.finish_transmit();
        P::on_after_transmit();
        self.state = RadioState::Idle;
    }

    fn reset_agc(&mut self) {
        if !self.is_ready || self.radio.is_receiving_packet().unwrap_or(true) {
            return;
        }
        let _ = self.radio.sleep(); //  warm sleep to reset analog frontend
        self.state = RadioState::Idle;
        self.noise_floor.reset();
    }
}

#[derive(Clone, Copy)]
pub enum RadioState {
    Idle,
    Rx,
    TxWait,
    TxDone,
}
