//! # paseto-dontuseme
//! Please please don't use this for anything.
//!
//! ```rust
//! use paseto_dontuseme::keys::SymmetricKey;
//! use paseto_dontuseme::protocol::V4;
//!
//! let symmetric_key = SymmetricKey::<V4>::generate().unwrap();
//! ```
pub mod error;
pub mod keys;
pub mod protocol;
