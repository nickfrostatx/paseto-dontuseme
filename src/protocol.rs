use crate::encoding::{b64_decode, b64_encode, pre_auth_encode};
use crate::error::{Error, Result};
use crate::keys::{AsymmetricPublicKey, AsymmetricSecretKey, SymmetricKey};
use blake2::digest::{consts::U32, consts::U56, FixedOutput, Mac};
use blake2::Blake2bMac;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{Key as ChaCha20Key, XChaCha20, XNonce as ChaCha20Nonce};
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;

pub trait ProtocolVersion {
    const SYMMETRIC_KEY_LEN: usize;
    const HEADER: &'static str;

    fn encrypt(data: &[u8], key: &SymmetricKey, footer: &[u8], implicit: &[u8]) -> Result<String>;
    fn decrypt(token: &str, key: &SymmetricKey, implicit: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;
}

pub struct V4;

impl ProtocolVersion for V4 {
    const SYMMETRIC_KEY_LEN: usize = 32;
    const HEADER: &'static str = "v4";

    fn encrypt(data: &[u8], key: &SymmetricKey, footer: &[u8], implicit: &[u8]) -> Result<String> {
        let mut nonce = [0u8; Self::NONCE_LEN];
        OsRng.try_fill_bytes(&mut nonce)?;
        Self::encrypt_with_nonce(data, nonce, key, footer, implicit)
    }

    fn decrypt(token: &str, key: &SymmetricKey, implicit: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        if !bool::from(key.version_header.as_bytes().ct_eq(Self::HEADER.as_bytes())) {
            return Err(Error::IncorrectKeyVersion);
        }

        let (message, footer) = Self::parse_token(token)?;

        let mut nonce = [0; Self::NONCE_LEN];
        nonce.copy_from_slice(message.get(..Self::NONCE_LEN).ok_or(Error::InvalidToken)?);
        let mut ciphertext = message
            .get(Self::NONCE_LEN..message.len() - Self::AUTH_TAG_LEN)
            .ok_or(Error::InvalidToken)?;
        let provided_auth_tag = message
            .get(message.len() - Self::AUTH_TAG_LEN..)
            .ok_or(Error::InvalidToken)?;

        let (enc_key, enc_nonce, auth_key) = Self::split_key(key, &nonce);

        let correct_auth_tag = Self::local_auth_tag(&auth_key, &nonce, &ciphertext, &footer, implicit);

        if !bool::from(provided_auth_tag.ct_eq(&correct_auth_tag)) {
            return Err(Error::InvalidToken);
        }

        let mut cipher = XChaCha20::new(&enc_key, &enc_nonce);
        let mut plaintext = ciphertext.to_vec();
        cipher.apply_keystream(&mut plaintext);

        Ok((plaintext, footer))
    }
}

impl V4 {
    const AUTH_TAG_LEN: usize = 32;
    const NONCE_LEN: usize = 32;
    const LOCAL_HEADER: &'static str = "v4.local.";

    fn parse_token(token: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        if token.len() < Self::LOCAL_HEADER.len()
            || !bool::from(
                token[..Self::LOCAL_HEADER.len()]
                    .as_bytes()
                    .ct_eq(Self::LOCAL_HEADER.as_bytes()),
            )
        {
            return Err(Error::IncorrectTokenVersion);
        }

        let without_header = &token[Self::LOCAL_HEADER.len()..];
        if let Some(sep_index) = without_header.chars().position(|c| c == '.') {
            Ok((
                b64_decode(&without_header[..sep_index])?,
                b64_decode(&without_header[sep_index + 1..])?,
            ))
        } else {
            Ok((b64_decode(without_header)?, Vec::new()))
        }
    }

    pub(crate) fn encrypt_with_nonce(
        data: &[u8],
        nonce: [u8; Self::NONCE_LEN],
        key: &SymmetricKey,
        footer: &[u8],
        implicit: &[u8],
    ) -> Result<String> {
        if !bool::from(key.version_header.as_bytes().ct_eq(Self::HEADER.as_bytes())) {
            return Err(Error::IncorrectKeyVersion);
        }
        let (enc_key, enc_nonce, auth_key) = Self::split_key(key, &nonce);

        let mut cipher = XChaCha20::new(&enc_key, &enc_nonce);
        let mut ciphertext = data.to_vec();
        cipher.apply_keystream(&mut ciphertext);

        let auth_tag = Self::local_auth_tag(&auth_key, &nonce, &ciphertext, footer, implicit);

        let token = b64_encode(&[&nonce as &[u8], &ciphertext, &auth_tag].concat())?;

        if footer.is_empty() {
            Ok(["v4.local.", &token].concat())
        } else {
            Ok(["v4.local.", &token, ".", &b64_encode(footer)?].concat())
        }
    }

    fn local_auth_tag(
        auth_key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        footer: &[u8],
        implicit: &[u8],
    ) -> Vec<u8> {
        let pre_auth = pre_auth_encode(&[b"v4.local.", &nonce, &ciphertext, footer, implicit]);
        let mut auth_tag_hasher =
            Blake2bMac::<U32>::new_with_salt_and_personal(&auth_key, &[], &[]).unwrap();
        auth_tag_hasher.update(&pre_auth);
        auth_tag_hasher.finalize_fixed().to_vec()
    }

    fn split_key(
        key: &SymmetricKey,
        nonce: &[u8; Self::NONCE_LEN],
    ) -> (ChaCha20Key, ChaCha20Nonce, Vec<u8>) {
        let mut enc_key_hasher =
            Blake2bMac::<U56>::new_with_salt_and_personal(key.as_bytes(), &[], &[]).unwrap();
        enc_key_hasher.update(b"paseto-encryption-key");
        enc_key_hasher.update(nonce);
        let enc_key_hash = enc_key_hasher.finalize_fixed();

        let enc_key = *ChaCha20Key::from_slice(&enc_key_hash[..32]);
        let enc_nonce = *ChaCha20Nonce::from_slice(&enc_key_hash[32..]);

        let mut auth_key_hasher =
            Blake2bMac::<U32>::new_with_salt_and_personal(key.as_bytes(), &[], &[]).unwrap();
        auth_key_hasher.update(b"paseto-auth-key-for-aead");
        auth_key_hasher.update(nonce);
        let auth_key = auth_key_hasher.finalize_fixed().to_vec();

        (enc_key, enc_nonce, auth_key)
    }
}

#[cfg(test)]
mod tests {
    use crate::keys::{AsymmetricPublicKey, AsymmetricSecretKey, SymmetricKey};
    use crate::protocol::{ProtocolVersion, V4};
    use serde::{self, Deserialize};

    fn test_local(test: &LocalTest) {
        let key = SymmetricKey::try_from_bytes::<V4>(test.key.to_vec()).unwrap();

        let decrypt_result = V4::decrypt(&test.token, &key, test.implicit_assertion.as_bytes());

        if test.expect_fail {
            assert!(decrypt_result.is_err(), "Failed test {}", test.name);
        } else {
            let payload = test.payload.as_ref().unwrap().as_bytes();

            let expected_result = Ok((payload.to_vec(), test.footer.as_bytes().to_vec()));
            assert_eq!(decrypt_result, expected_result, "Failed test {}", test.name);

            let token = V4::encrypt_with_nonce(
                payload,
                test.nonce.clone(),
                &key,
                test.footer.as_bytes(),
                test.implicit_assertion.as_bytes(),
            );
            assert_eq!(token.as_ref(), Ok(&test.token), "Failed test {}", test.name);
        }
    }

    fn test_public(test: &PublicTest) {}

    #[derive(Deserialize)]
    struct TestVectors {
        pub tests: Vec<TestVector>,
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum TestVector {
        Local(LocalTest),
        Public(PublicTest),
    }

    #[derive(Deserialize)]
    struct LocalTest {
        name: String,
        #[serde(rename(deserialize = "expect-fail"))]
        expect_fail: bool,
        #[serde(with = "hex::serde")]
        nonce: [u8; V4::NONCE_LEN],
        #[serde(with = "hex::serde")]
        key: [u8; V4::SYMMETRIC_KEY_LEN],
        token: String,
        payload: Option<String>,
        footer: String,
        #[serde(rename(deserialize = "implicit-assertion"))]
        implicit_assertion: String,
    }

    #[derive(Deserialize)]
    struct PublicTest {
        // TODO: make all the bytestrings hex::serde
        name: String,
        #[serde(rename(deserialize = "expect-fail"))]
        expect_fail: bool,
        #[serde(rename(deserialize = "secret-key"))]
        secret_key: String,
        #[serde(rename(deserialize = "secret-key-seed"))]
        secret_key_seed: String,
        #[serde(rename(deserialize = "public-key-pem"))]
        public_key_pem: String,
        #[serde(rename(deserialize = "secret-key-pem"))]
        secret_key_pem: String,
        token: String,
        payload: Option<String>,
        footer: String,
        #[serde(rename(deserialize = "implicit-assertion"))]
        implicit_assertion: String,
    }

    #[test]
    fn test_vectors() {
        let test_vector_file = include_str!("../test-vectors/v4.json");
        let tests: TestVectors = serde_json::from_str(test_vector_file).unwrap();
        for test in tests.tests {
            match test {
                TestVector::Local(local_test) => test_local(&local_test),
                TestVector::Public(public_test) => test_public(&public_test),
            }
        }
    }
}
