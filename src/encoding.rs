use crate::error::{Error, Result};
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};

fn le64(n: u64) -> [u8; 8] {
    let mut bytes = n.to_le_bytes();
    // Clear the MSB for interoperability
    bytes[7] &= 127;
    bytes
}

pub fn pre_auth_encode(pieces: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&le64(pieces.len() as u64));
    for piece in pieces {
        output.extend_from_slice(&le64(piece.len() as u64));
        output.extend_from_slice(piece);
    }
    output
}

pub fn b64_encode(decoded: &[u8]) -> Result<String> {
    Base64UrlSafeNoPadding::encode_to_string(decoded).map_err(|_| Error::Base64EncodeError)
}

pub fn b64_decode(encoded: &str) -> Result<Vec<u8>> {
    Base64UrlSafeNoPadding::decode_to_vec(encoded, None).map_err(|_| Error::InvalidBase64)
}
