#![no_std]
#![allow(unused)]
#![warn(unused_variables)]
#![warn(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

mod error;
mod identity;
mod mesh;
mod packet;
mod platform;
mod radio;
mod sensor;

use core::{marker::PhantomData, time::Duration};

use crate::{error::HardwareResult, identity::LocalIdentity, platform::Platform, radio::Radio};

fn main() {}

fn setup<R: Radio>() -> HardwareResult<()> {
    let radio = R::new()?;
    todo!()
}
fn main_loop() {}

trait Storage
where
    Self: Sized,
{
    fn new() -> HardwareResult<Self>;
    fn identity(&self) -> HardwareResult<Option<LocalIdentity>>;
    fn gen_identity(&mut self) -> HardwareResult<LocalIdentity>;
}
