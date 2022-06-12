use crate::error::{Error, Result};
use crate::keys::{AsymmetricPublicKey, AsymmetricSecretKey, SymmetricKey};
use rand_core::{OsRng, RngCore};

pub trait ProtocolVersion {
    const SYMMETRIC_KEY_LEN: usize;

    fn encrypt(
        data: &[u8],
        key: &SymmetricKey<impl ProtocolVersion>,
        footer: &[u8],
        implicit: &[u8],
    ) -> Result<String>;
}

pub struct V4;

impl ProtocolVersion for V4 {
    const SYMMETRIC_KEY_LEN: usize = 32;

    fn encrypt(
        data: &[u8],
        key: &SymmetricKey<impl ProtocolVersion>,
        footer: &[u8],
        implicit: &[u8],
    ) -> Result<String> {
        let mut nonce = [0u8; Self::NONCE_LEN];
        OsRng.try_fill_bytes(&mut nonce)?;
        Ok(Self::encrypt_with_nonce(
            data, &nonce, key, footer, implicit,
        ))
    }
}

impl V4 {
    const NONCE_LEN: usize = 32;

    fn encrypt_with_nonce(
        data: &[u8],
        nonce: &[u8; Self::NONCE_LEN],
        key: &SymmetricKey<impl ProtocolVersion>,
        footer: &[u8],
        implicit: &[u8],
    ) -> String {
        "v4.local.not implemented".to_string()
    }
}

#[cfg(test)]
mod tests {
    use crate::keys::{AsymmetricPublicKey, AsymmetricSecretKey, SymmetricKey};
    use crate::protocol::{ProtocolVersion, V4};
    use serde::{self, Deserialize};

    fn test_local(test: &LocalTest) {
        let key = SymmetricKey::<V4>::try_from_bytes(test.key.to_vec()).unwrap();

        if test.expect_fail {
        } else {
            let payload = test.payload.as_ref().unwrap().as_bytes();
            let token = V4::encrypt_with_nonce(
                payload,
                &test.nonce,
                &key,
                test.footer.as_bytes(),
                test.implicit_assertion.as_bytes(),
            );
            assert_eq!(token, test.token, "Failed test {}", test.name);
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
