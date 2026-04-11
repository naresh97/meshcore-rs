#![allow(unused, clippy::unused_self)]

use crate::mesh::{channel::ChannelIdentity, identity::RemoteIdentity};

pub struct Contacts {}
impl Contacts {
    pub fn get_matching_nodes(&self, hash: u8) -> impl Iterator<Item = &RemoteIdentity> {
        [].into_iter()
    }
    pub fn get_matching_channels(&self, hash: u8) -> impl Iterator<Item = &ChannelIdentity> {
        [].into_iter()
    }
}
