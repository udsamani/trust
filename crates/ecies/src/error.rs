use thiserror::Error;

/// An error that occurs while reading or writing to an ECIES stream.
#[derive(Debug, Error)]
pub enum ECIESError {
    /// Error during IO
    #[error("IO Error")]
    IO(std::io::Error),

    /// Error when checking the HMAC tag against the tag on the message being decrypted
    #[error("tag check failure in read_header")]
    TagCheckDecryptFailed,

    /// Error when trying to split an array beyond its length
    #[error("requested {idx} but array len is {len}")]
    OutOfBounds {
        /// The index you are trying to split at
        idx: usize,
        /// The length of the array
        len: usize,
    },

    /// Error when decoding RLP data
    #[error(transparent)]
    RLPDecoding(trust_rlp::RlpDecodeError),

    /// Error when parsing AUTH data
    #[error("invalid auth data")]
    InvalidAuthData,

    /// Error when parsing ACK data
    #[error("invalid ack data")]
    InvalidAckData,

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

impl From<trust_rlp::RlpDecodeError> for ECIESError {
    fn from(source: trust_rlp::RlpDecodeError) -> Self {
        ECIESError::RLPDecoding(source).into()
    }
}
