use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::mesh::packet::raw::MAX_PACKET_PAYLOAD;

pub const CIPHER_KEY_SIZE: usize = 16;
pub const CIPHER_MAC_SIZE: usize = 2;

fn encrypt(secret: &[u8; 16], plaintext: &[u8]) -> Option<heapless::Vec<u8, MAX_PACKET_PAYLOAD>> {
    let mut ciphertext = aes_encrypt(secret, plaintext)?;
    let mut padded = [0u8; 32]; // Initialize all zeros
    padded[..16].copy_from_slice(secret);
    let mac = Hmac::<Sha256>::new_from_slice(&padded).ok()?;
    let (&mac, _) = mac
        .finalize()
        .into_bytes()
        .split_first_chunk::<CIPHER_MAC_SIZE>()?;
    let mut result = heapless::Vec::from_array(mac);
    result.extend(ciphertext);
    Some(result)
}

fn aes_encrypt(
    secret: &[u8; CIPHER_KEY_SIZE],
    plaintext: &[u8],
) -> Option<heapless::Vec<u8, MAX_PACKET_PAYLOAD>> {
    use aes::{
        Aes128,
        cipher::{BlockDecrypt, BlockEncrypt, KeyInit},
    };

    let aes = Aes128::new(secret.into());
    let mut result = heapless::Vec::from_slice(plaintext).ok()?;
    let padding = (16 - (result.len() % 16)) % 16;
    result.resize(result.len() + padding, 0u8);
    let (blocks, _) = result.as_chunks_mut::<16>();
    for block in blocks {
        aes.encrypt_block(block.into());
    }
    Some(result)
}

fn aes_decrypt(
    secret: &[u8; CIPHER_KEY_SIZE],
    ciphertext: &[u8],
) -> Option<heapless::Vec<u8, MAX_PACKET_PAYLOAD>> {
    use aes::{
        Aes128,
        cipher::{BlockDecrypt, BlockEncrypt, KeyInit},
    };

    let aes = Aes128::new(secret.into());
    let mut result = heapless::Vec::from_slice(ciphertext).ok()?;
    let (blocks, _) = result.as_chunks_mut::<16>();
    for block in blocks {
        aes.decrypt_block(block.into());
    }
    Some(result)
}

#[cfg(test)]
mod tests {

    use std::ffi::CStr;

    use super::*;
    #[test]
    fn test_aes_decrypt() {
        let secret = "80174f513e9099612b537bc1cd450a41";
        let secret = hex::decode(secret).unwrap();
        let ciphertext = "343F31A462B35F2D79264F7CC1BADC880F400A68AE504EFE4CA85D69002E3E77";
        let ciphertext = hex::decode(ciphertext).unwrap();
        let plaintext = aes_decrypt(secret[0..16].try_into().unwrap(), &ciphertext).unwrap();
        dbg!(hex::encode(&plaintext));
        let plaintext = CStr::from_bytes_until_nul(&plaintext[5..])
            .unwrap()
            .to_string_lossy();
        assert_eq!("jgerhold-T114: Moin!", plaintext);
    }
    #[test]
    fn test_encrypt() {
        let secret = "80174f513e9099612b537bc1cd450a41";
        let secret = hex::decode(secret).unwrap();
        let plaintext = "da15d669006a676572686f6c642d543131343a204d6f696e2100000000000000";
        let plaintext = hex::decode(plaintext).unwrap();
        let cipher = encrypt(secret[..16].try_into().unwrap(), &plaintext).unwrap();
        dbg!(hex::encode(cipher));
        //e6c5
    }
}
