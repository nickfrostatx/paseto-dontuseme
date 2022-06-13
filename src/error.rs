use std::fmt;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Error {
    Base64EncodeError,
    IncorrectKeySize,
    IncorrectKeyVersion,
    IncorrectTokenVersion,
    InvalidBase64,
    InvalidToken,
    RngError,
}

pub type Result<T> = std::result::Result<T, Error>;

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Base64EncodeError => write!(f, "error encoding to base64"),
            Error::IncorrectKeySize => write!(f, "incorrect key size"),
            Error::IncorrectKeyVersion => write!(f, "incorrect key version"),
            Error::IncorrectTokenVersion => write!(f, "incorrect token version"),
            Error::InvalidBase64 => write!(f, "invalid base64"),
            Error::InvalidToken => write!(f, "invalid token"),
            Error::RngError => write!(f, "error getting random bytes"),
        }
    }
}

impl From<rand_core::Error> for Error {
    fn from(_: rand_core::Error) -> Self {
        Error::RngError
    }
}
