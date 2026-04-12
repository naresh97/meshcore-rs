#![allow(unused, clippy::unused_self)]

use heapless::CapacityError;

use crate::mesh::{
    channel::ChannelIdentity,
    identity::{PUBLIC_KEY_SIZE, RemoteIdentity},
};

const NODE_LIST_SIZE: usize = 2usize.pow(8);

pub struct Contacts {
    nodes: heapless::Vec<[u8; PUBLIC_KEY_SIZE], NODE_LIST_SIZE>,
}

impl Contacts {
    pub fn get_matching_nodes_iter(
        &self,
        hash: u8,
    ) -> impl Iterator<Item = &[u8; PUBLIC_KEY_SIZE]> {
        let start = self.nodes.partition_point(|k| k[0] < hash);
        let remainder = &self.nodes[start..];
        let count = remainder.partition_point(|k| k[0] <= hash);
        let end = start + count;
        self.nodes[start..end].iter()
    }
    pub fn insert_node(&mut self, public_key: [u8; PUBLIC_KEY_SIZE]) -> Result<(), CapacityError> {
        let pos = self.nodes.partition_point(|k| k[0] < public_key[0]);
        self.nodes
            .insert(pos, public_key)
            .map_err(|_| CapacityError::default())?;
        Ok(())
    }

    pub fn get_matching_channels(&self, hash: u8) -> impl Iterator<Item = &ChannelIdentity> {
        [].into_iter()
    }

    pub fn new() -> Self {
        Self {
            nodes: heapless::Vec::new(),
        }
    }
}
