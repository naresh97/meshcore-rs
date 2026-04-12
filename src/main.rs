//! # meshcore-rs
//! An implementation of the MeshCore protocol in Rust.
//! While initially heavily leaning on the original C++ implementation by Scott Powell (see LICENSE),
//! it should be written instead in idiomatic Rust code with the aims of providing
//! safety, performance and ease of development/maintainability.

#![cfg_attr(not(test), no_std)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(unused)]
#![warn(unused_variables)]
#![warn(missing_docs)]

mod error;
mod mesh;
mod platform;
mod radio;
mod sensor;
mod utils;

use core::{marker::PhantomData, time::Duration};

use crate::{error::HardwareResult, platform::Platform, radio::Radio};

fn main() {}

fn setup<R: Radio>() -> HardwareResult<()> {
    let _radio = R::new()?;
    todo!()
}
fn main_loop() {}
