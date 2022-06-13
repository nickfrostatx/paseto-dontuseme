//! # paseto-dontuseme
//! Please please don't use this for anything.
//!
//! ```rust
//! use paseto_dontuseme::keys::SymmetricKey;
//! use paseto_dontuseme::protocol::{ProtocolVersion, V4};
//!
//! let key = SymmetricKey::generate::<V4>().unwrap();
//! let token = V4::encrypt(b"data", &key, b"footer", b"implicit").unwrap();
//! assert_eq!(
//!     V4::decrypt(&token, &key, b"implicit"),
//!     Ok((b"data".to_vec(), b"footer".to_vec()))
//! );
//! ```
pub mod encoding;
pub mod error;
pub mod keys;
pub mod protocol;
