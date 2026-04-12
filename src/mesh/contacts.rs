#![allow(unused, clippy::unused_self)]

use heapless::CapacityError;

use crate::mesh::{
    channel::{CHANNEL_SECRET_SIZE, ChannelIdentity},
    identity::{PUBLIC_KEY_SIZE, RemoteIdentity},
};

const NODE_LIST_SIZE: usize = 2usize.pow(8);

pub struct Contacts {
    nodes: heapless::Vec<RemoteIdentity, NODE_LIST_SIZE>,
    channels: heapless::Vec<ChannelIdentity, NODE_LIST_SIZE>,
}

impl Contacts {
    pub fn get_matching_nodes_iter(&self, hash: u8) -> impl Iterator<Item = &RemoteIdentity> {
        let start = self.nodes.partition_point(|k| k.public[0] < hash);
        let remainder = &self.nodes[start..];
        let count = remainder.partition_point(|k| k.public[0] <= hash);
        let end = start + count;
        self.nodes[start..end].iter()
    }

    pub fn get_matching_channels(&self, hash: u8) -> impl Iterator<Item = &ChannelIdentity> {
        let start = self.channels.partition_point(|k| k.hash < hash);
        let remainder = &self.channels[start..];
        let count = remainder.partition_point(|k| k.hash <= hash);
        let end = start + count;
        self.channels[start..end].iter()
    }

    pub fn insert_node(&mut self, identity: RemoteIdentity) -> Result<(), CapacityError> {
        let pos = self
            .nodes
            .partition_point(|k| k.public[0] < identity.public[0]);
        self.nodes
            .insert(pos, identity)
            .map_err(|_| CapacityError::default())?;
        Ok(())
    }

    pub fn insert_channel(
        &mut self,
        channel_identity: ChannelIdentity,
    ) -> Result<(), CapacityError> {
        let pos = self
            .channels
            .partition_point(|k| k.hash < channel_identity.hash);
        self.channels
            .insert(pos, channel_identity)
            .map_err(|_| CapacityError::default())?;
        Ok(())
    }

    pub fn new() -> Self {
        Self {
            nodes: heapless::Vec::new(),
            channels: heapless::Vec::new(),
        }
    }
}
