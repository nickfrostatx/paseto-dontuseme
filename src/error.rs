use std::fmt;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Error {
    IncorrectKeySize,
    RngError,
}

pub type Result<T> = std::result::Result<T, Error>;

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::IncorrectKeySize => write!(f, "incorrect key size"),
            Error::RngError => write!(f, "error getting random bytes"),
        }
    }
}

impl From<rand_core::Error> for Error {
    fn from(_: rand_core::Error) -> Self {
        Error::RngError
    }
}
