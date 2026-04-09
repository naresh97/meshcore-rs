use crate::mesh::identity::RemoteIdentity;

pub struct Contacts {}
impl Contacts {
    pub fn get_matches_hash(&self, hash: u8) -> impl Iterator<Item = RemoteIdentity> {
        todo!();
        [].into_iter()
    }
}
