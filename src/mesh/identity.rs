use curve25519_dalek::{
    EdwardsPoint, MontgomeryPoint, Scalar, constants::ED25519_BASEPOINT_POINT,
    edwards::CompressedEdwardsY,
};
use sha2::{Digest, Sha512};

use crate::error::{EncryptionError, EncryptionResult};

pub const PRIVATE_KEY_SIZE: usize = 64;
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;

/// An identity created by this device, with private key known on this device.
pub struct LocalIdentity {
    pub private: [u8; PRIVATE_KEY_SIZE],
    pub public: [u8; PUBLIC_KEY_SIZE],
}
impl LocalIdentity {
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_SIZE] {
        // 1. Extract the secret scalar 'a'
        let a = Scalar::from_bytes_mod_order(self.private[0..32].try_into().unwrap());

        // 2. Hash the prefix and message to get the deterministic nonce 'r'
        let mut hasher = Sha512::new();
        hasher.update(&self.private[32..64]);
        hasher.update(message);
        let r = Scalar::from_bytes_mod_order_wide(&hasher.finalize().into());

        // 3. Calculate the public commitment 'R' (r * Basepoint)
        let r_bytes = (r * ED25519_BASEPOINT_POINT).compress().to_bytes();

        // 4. Calculate the challenge 'hram'
        let mut hasher = Sha512::new();
        hasher.update(r_bytes);
        hasher.update(self.public); // Assuming this is an array or slice
        hasher.update(message);
        let hram = Scalar::from_bytes_mod_order_wide(&hasher.finalize().into());

        // 5. Compute the response scalar 'S'
        let s_bytes = (r + hram * a).to_bytes();

        // 6. Assemble the final signature
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&r_bytes);
        signature[32..].copy_from_slice(&s_bytes);

        signature
    }

    pub fn from_private_key(private_key: &[u8; PRIVATE_KEY_SIZE]) -> Self {
        let mut a_bytes = [0u8; 32];
        a_bytes.copy_from_slice(&private_key[..32]);
        let a = Scalar::from_bytes_mod_order(a_bytes);
        let a: EdwardsPoint = a * ED25519_BASEPOINT_POINT;
        let public = a.compress().to_bytes();
        Self {
            private: *private_key,
            public,
        }
    }

    pub fn get_shared_key_with_public_key(
        &self,
        other: [u8; PUBLIC_KEY_SIZE],
    ) -> [u8; PUBLIC_KEY_SIZE] {
        let mut e = [0u8; 32];
        e.copy_from_slice(&self.private[0..32]);
        e[0] &= 0b1111_1000;
        e[31] &= 0b11_1111;
        e[31] |= 0b100_0000;
        let edwards = CompressedEdwardsY(other)
            .decompress()
            .expect("invalid public key");
        let montgomery: MontgomeryPoint = edwards.to_montgomery();
        let shared = montgomery.mul_clamped(e);
        shared.to_bytes()
    }

    pub fn get_shared_key(&self, other: &RemoteIdentity) -> [u8; 32] {
        self.get_shared_key_with_public_key(other.public)
    }
}

#[derive(Debug)]
pub struct RemoteIdentity {
    pub public: [u8; PUBLIC_KEY_SIZE],
}

#[cfg(test)]
mod tests {
    use std::process::id;

    use crate::mesh::packet::encryption::{decrypt, encrypt};

    use super::*;

    const PUBLIC_TEST: &str = "12346BFDBAA49BFBBE6E7A922CABA326294E11D9C72A24A29FBB3DB708FFF1E0";
    const PRIVATE_TEST: &str = "104B70BC64F3FDBDEC6E9A9189C40C7B6A64E5D3A91B75D423EDF879C4C082605F852A0F473307596502D95238CE1FEC32C4BEBD7D119AE73974C2BFA650A1B3";

    #[test]
    fn generate_public() {
        let private = hex::decode(PRIVATE_TEST).unwrap();
        let identity = LocalIdentity::from_private_key(&private.try_into().unwrap());
        assert_eq!(hex::decode(PUBLIC_TEST).unwrap(), identity.public);
    }

    #[test]
    fn sign() {
        let timestamp = "C6A4D769";
        let data = "8152616F4D657368";
        let message = format!("{PUBLIC_TEST}{timestamp}{data}");
        let message = hex::decode(message).unwrap();
        let private = hex::decode(PRIVATE_TEST).unwrap();
        let identity = LocalIdentity::from_private_key(&private.try_into().unwrap());
        let signature = identity.sign(&message);
        let expected = "202c7edfa018287723622ab7a7df150c032e82e4636e31a68b7c543360a62a2707ec4e2d838740f7e5152b60bdcc8ac38298294205b3a921594b3339e08d6a09";
        let expected = hex::decode(expected).unwrap();
        assert_eq!(expected, signature);
    }

    #[test]
    fn decrypt_from_shared() {
        let ciphertext = "3d622e1984b69ad551282a0ddc33c865edf5";
        let ciphertext = hex::decode(ciphertext).unwrap();
        let other = "d382cb99ac49fa97e3f2a52774582e57996653e873de45b9ed68318e5d7b0420";
        let other = hex::decode(other).unwrap();

        let private = hex::decode(PRIVATE_TEST).unwrap();
        let identity = LocalIdentity::from_private_key(&private.try_into().unwrap());

        let shared = identity.get_shared_key_with_public_key(other.try_into().unwrap());
        let plaintext = decrypt(&shared, &ciphertext).unwrap();
        dbg!(hex::encode(&plaintext));

        let roundtrip = encrypt(&shared, &plaintext).unwrap();
        assert_eq!(ciphertext.as_slice(), roundtrip);
        let plaintext = String::from_utf8_lossy(&plaintext[5..7]);
        assert_eq!("Hi", plaintext);
    }

    #[test]
    fn encrypt_from_shared() {
        let plaintext = "efb3d769004869000000000000000000";
        let plaintext = hex::decode(plaintext).unwrap();
        let private = hex::decode(PRIVATE_TEST).unwrap();
        let identity = LocalIdentity::from_private_key(&private.try_into().unwrap());
        let other = "d382cb99ac49fa97e3f2a52774582e57996653e873de45b9ed68318e5d7b0420";
        let other = hex::decode(other).unwrap();
        let shared = identity.get_shared_key_with_public_key(other.try_into().unwrap());
        let ciphertext = encrypt(&shared, &plaintext).unwrap();
        let expected = "3d622e1984b69ad551282a0ddc33c865edf5";
        let expected = hex::decode(expected).unwrap();
        assert_eq!(expected.as_slice(), ciphertext);
    }
}
