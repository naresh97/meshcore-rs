use crate::{
    error::{EncryptionError, EncryptionResult},
    mesh::{identity::PUBLIC_KEY_SIZE, packet::raw::MAX_PACKET_PAYLOAD},
};

pub const CIPHER_KEY_SIZE: usize = 16;

pub fn encrypt(
    secret: &[u8; PUBLIC_KEY_SIZE],
    plaintext: &[u8],
) -> EncryptionResult<heapless::Vec<u8, MAX_PACKET_PAYLOAD>> {
    let mut ciphertext = aes_encrypt(
        secret
            .first_chunk::<CIPHER_KEY_SIZE>()
            .ok_or(EncryptionError::MalformedSecret)?,
        plaintext,
    )?;
    let mac = gen_hmac(secret, &ciphertext)?;
    let mut result = heapless::Vec::from_array(mac);
    result.extend(ciphertext);
    Ok(result)
}

pub fn decrypt(
    secret: &[u8; PUBLIC_KEY_SIZE],
    ciphertext: &[u8],
) -> EncryptionResult<heapless::Vec<u8, MAX_PACKET_PAYLOAD>> {
    let (&provided_hmac, ciphertext) = ciphertext
        .split_first_chunk::<CIPHER_MAC_SIZE>()
        .ok_or(EncryptionError::MalformedCiphertext)?;
    let calculated_hmac = gen_hmac(secret, ciphertext)?;
    if provided_hmac != calculated_hmac {
        return Err(EncryptionError::HmacValidationFailed);
    }
    let plaintext = aes_decrypt(
        secret
            .first_chunk::<CIPHER_KEY_SIZE>()
            .ok_or(EncryptionError::MalformedSecret)?,
        ciphertext,
    )?;
    Ok(plaintext)
}

pub fn decrypt_with_channel_secret(
    secret: &[u8; 16],
    ciphertext: &[u8],
) -> EncryptionResult<heapless::Vec<u8, MAX_PACKET_PAYLOAD>> {
    let mut padded = [0u8; 32];
    padded[0..16].copy_from_slice(secret);
    decrypt(&padded, ciphertext)
}

fn aes_encrypt(
    secret: &[u8; CIPHER_KEY_SIZE],
    plaintext: &[u8],
) -> EncryptionResult<heapless::Vec<u8, MAX_PACKET_PAYLOAD>> {
    use aes::{
        Aes128,
        cipher::{BlockDecrypt, BlockEncrypt, KeyInit},
    };

    let aes = Aes128::new(secret.into());
    let mut result =
        heapless::Vec::from_slice(plaintext).map_err(|_| EncryptionError::OutOfSpace)?;
    let padding = (16 - (result.len() % 16)) % 16;
    result.resize(result.len() + padding, 0u8);
    let (blocks, _) = result.as_chunks_mut::<16>();
    for block in blocks {
        aes.encrypt_block(block.into());
    }
    Ok(result)
}

fn aes_decrypt(
    secret: &[u8; CIPHER_KEY_SIZE],
    ciphertext: &[u8],
) -> EncryptionResult<heapless::Vec<u8, MAX_PACKET_PAYLOAD>> {
    use aes::{
        Aes128,
        cipher::{BlockDecrypt, BlockEncrypt, KeyInit},
    };

    let aes = Aes128::new(secret.into());
    let mut result =
        heapless::Vec::from_slice(ciphertext).map_err(|_| EncryptionError::OutOfSpace)?;
    let (blocks, _) = result.as_chunks_mut::<16>();
    for block in blocks {
        aes.decrypt_block(block.into());
    }
    Ok(result)
}

const CIPHER_MAC_SIZE: usize = 2;
fn gen_hmac(secret: &[u8], ciphertext: &[u8]) -> EncryptionResult<[u8; CIPHER_MAC_SIZE]> {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret).map_err(|_| EncryptionError::HmacInvalidSecret)?;
    mac.update(ciphertext);
    let (&mac, _) = mac
        .finalize()
        .into_bytes()
        .split_first_chunk::<CIPHER_MAC_SIZE>()
        .ok_or(EncryptionError::HmacGenerationFailed)?;
    Ok(mac)
}

#[cfg(test)]
mod tests {

    use std::ffi::CStr;

    use super::*;
    #[test]
    fn test_decrypt() {
        let secret_s = "80174f513e9099612b537bc1cd450a41";
        let secret_s = hex::decode(secret_s).unwrap();
        let ciphertext = "E6C5343F31A462B35F2D79264F7CC1BADC880F400A68AE504EFE4CA85D69002E3E77";
        let ciphertext = hex::decode(ciphertext).unwrap();
        let plaintext =
            decrypt_with_channel_secret(&secret_s.try_into().unwrap(), &ciphertext).unwrap();
        let expected = "da15d669006a676572686f6c642d543131343a204d6f696e2100000000000000";
        let expected = hex::decode(expected).unwrap();
        assert_eq!(expected.as_slice(), &plaintext);
    }
    #[test]
    fn test_encrypt() {
        let secret = "80174f513e9099612b537bc1cd450a41";
        let secret = hex::decode(secret).unwrap();
        let plaintext = "da15d669006a676572686f6c642d543131343a204d6f696e2100000000000000";
        let plaintext = hex::decode(plaintext).unwrap();
        let cipher = encrypt(secret[..16].try_into().unwrap(), &plaintext).unwrap();
        let expected = "E6C5343F31A462B35F2D79264F7CC1BADC880F400A68AE504EFE4CA85D69002E3E77";
        let expected = hex::decode(expected).unwrap();
        assert_eq!(expected.as_slice(), &cipher);
    }
}
