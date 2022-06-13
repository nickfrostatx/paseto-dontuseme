use crate::error::{Error, Result};
use crate::protocol::ProtocolVersion;
use rand_core::{OsRng, RngCore};

pub struct SymmetricKey {
    pub(crate) bytes: Vec<u8>,
    pub(crate) version_header: &'static str,
}

impl SymmetricKey {
    pub fn generate<V: ProtocolVersion>() -> Result<Self> {
        let mut bytes = vec![0u8; V::SYMMETRIC_KEY_LEN];
        OsRng.try_fill_bytes(&mut bytes)?;
        Ok(Self {
            bytes,
            version_header: V::HEADER,
        })
    }

    pub fn try_from_bytes<V: ProtocolVersion>(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() != V::SYMMETRIC_KEY_LEN {
            Err(Error::IncorrectKeySize)
        } else {
            Ok(Self {
                bytes,
                version_header: V::HEADER,
            })
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub fn encrypt<V: ProtocolVersion>(
        &self,
        data: &[u8],
        footer: &[u8],
        implicit: &[u8],
    ) -> Result<String> {
        V::encrypt(data, self, footer, implicit)
    }
}

pub struct AsymmetricSecretKey {}

pub struct AsymmetricPublicKey {}
