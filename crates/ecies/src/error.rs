use thiserror::Error;

/// An error that occurs while reading or writing to an ECIES stream.
#[derive(Debug, Error)]
pub enum ECIESError {
    /// Error during IO
    #[error("IO Error")]
    IO(std::io::Error),

    /// Erroe when interacting with secp256k1
    #[error(transparent)]
    Sec256k1(secp256k1::Error),
}

impl From<secp256k1::Error> for ECIESError {
    fn from(source: secp256k1::Error) -> Self {
        ECIESError::Sec256k1(source).into()
    }
}

impl From<std::io::Error> for ECIESError {
    fn from(source: std::io::Error) -> Self {
        ECIESError::IO(source).into()
    }
}
