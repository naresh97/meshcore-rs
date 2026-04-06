#![no_std]
#![warn(clippy::pedantic)]
#![allow(unused)]
#![warn(unused_variables)]

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
    let _radio = R::new()?;
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
