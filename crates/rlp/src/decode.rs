use crate::types::Header;
use bytes::{Buf, Bytes, BytesMut};

pub trait RlpDecodable: Sized {
    fn decode(buf: &mut &[u8]) -> Result<Self, RlpDecodeError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RlpDecodeError {
    Overflow,
    LeadingZero,
    InputTooShort,
    NonCanonicalSingleByte,
    NonCanonicalSize,
    UnexpectedLength,
    UnexpectedString,
    UnexpectedList,
    Custom(&'static str),
}

impl std::error::Error for RlpDecodeError {}

impl core::fmt::Display for RlpDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RlpDecodeError::Overflow => write!(f, "Overflow"),
            RlpDecodeError::LeadingZero => write!(f, "Leading Zero"),
            RlpDecodeError::InputTooShort => write!(f, "Input Too Short"),
            RlpDecodeError::UnexpectedLength => write!(f, "Unexpected Length"),
            RlpDecodeError::UnexpectedString => write!(f, "Unexpected String"),
            RlpDecodeError::NonCanonicalSingleByte => write!(f, "Non Canonical Single Byte"),
            RlpDecodeError::NonCanonicalSize => write!(f, "Non Canonical Size"),
            RlpDecodeError::UnexpectedList => write!(f, "Unexpected List"),
            RlpDecodeError::Custom(err) => write!(f, "{err}"),
        }
    }
}

impl RlpDecodable for Header {
    fn decode(buf: &mut &[u8]) -> Result<Self, RlpDecodeError> {
        if !buf.has_remaining() {
            return Err(RlpDecodeError::InputTooShort);
        }

        let b = buf[0];
        let h: Self = {
            if b < 0x80 {
                Self { list: false, payload_len: 1 }
            } else if b < 0xB8 {
                buf.advance(1);
                let h = Self { list: false, payload_len: b as usize - 0x80 };

                if h.payload_len == 1 {
                    if !buf.has_remaining() {
                        return Err(RlpDecodeError::InputTooShort);
                    }

                    if buf[0] < 0x80 {
                        return Err(RlpDecodeError::NonCanonicalSingleByte);
                    }
                }
                h
            } else if b < 0xC0 {
                buf.advance(1);
                let len_of_len = b as usize - 0xB7;
                if buf.len() < len_of_len {
                    return Err(RlpDecodeError::InputTooShort);
                }
                let payload_len = usize::try_from(u64::from_be_bytes(
                    static_left_pad(&buf[..len_of_len]).ok_or(RlpDecodeError::LeadingZero)?,
                ))
                .map_err(|_| RlpDecodeError::Custom("Input too big"))?;
                buf.advance(len_of_len);
                if payload_len < 56 {
                    return Err(RlpDecodeError::NonCanonicalSize);
                }

                Self { list: false, payload_len }
            } else if b < 0xF8 {
                buf.advance(1);
                Self { list: true, payload_len: b as usize - 0xC0 }
            } else {
                buf.advance(1);
                let list = true;
                let len_of_len = b as usize - 0xF7;
                if buf.len() < len_of_len {
                    return Err(RlpDecodeError::InputTooShort);
                }
                let payload_len = usize::try_from(u64::from_be_bytes(
                    static_left_pad(&buf[..len_of_len]).ok_or(RlpDecodeError::LeadingZero)?,
                ))
                .map_err(|_| RlpDecodeError::Custom("Input too big"))?;
                buf.advance(len_of_len);
                if payload_len < 56 {
                    return Err(RlpDecodeError::NonCanonicalSize);
                }

                Self { list, payload_len }
            }
        };

        if buf.remaining() < h.payload_len {
            return Err(RlpDecodeError::InputTooShort);
        }
        Ok(h)
    }
}

fn static_left_pad<const LEN: usize>(data: &[u8]) -> Option<[u8; LEN]> {
    if data.len() > LEN {
        return None;
    }

    let mut v = [0; LEN];

    if data.is_empty() {
        return Some(v);
    }

    if data[0] == 0 {
        return None;
    }

    v[LEN - data.len()..].copy_from_slice(data);
    Some(v)
}
