use crate::error::{Error, Result};
use crate::protocol::ProtocolVersion;
use core::marker::PhantomData;
use rand_core::{OsRng, RngCore};

pub struct SymmetricKey<V: ProtocolVersion> {
    pub(crate) bytes: Vec<u8>,
    phantom: PhantomData<V>,
}

impl<V> SymmetricKey<V>
where
    V: ProtocolVersion,
{
    pub fn generate() -> Result<Self> {
        let mut bytes = vec![0u8; V::SYMMETRIC_KEY_LEN];
        OsRng.try_fill_bytes(&mut bytes)?;
        Ok(Self {
            bytes: bytes,
            phantom: PhantomData,
        })
    }

    pub fn try_from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() != V::SYMMETRIC_KEY_LEN {
            Err(Error::IncorrectKeySize)
        } else {
            Ok(Self {
                bytes,
                phantom: PhantomData,
            })
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub fn encrypt(&self, data: &[u8], footer: &[u8], implicit: &[u8]) -> Result<String> {
        V::encrypt(data, self, footer, implicit)
    }
}

pub struct AsymmetricSecretKey {}

pub struct AsymmetricPublicKey {}
