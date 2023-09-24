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

impl<const N: usize> RlpDecodable for [u8; N] {
    fn decode(from: &mut &[u8]) -> Result<Self, RlpDecodeError> {
        let h = Header::decode(from)?;
        if h.list {
            return Err(RlpDecodeError::UnexpectedList);
        }
        if h.payload_len != N {
            return Err(RlpDecodeError::UnexpectedLength);
        }

        let mut to = [0_u8; N];
        to.copy_from_slice(&from[..N]);
        from.advance(N);

        Ok(to)
    }
}

impl RlpDecodable for BytesMut {
    fn decode(from: &mut &[u8]) -> Result<Self, RlpDecodeError> {
        let h = Header::decode(from)?;
        if h.list {
            return Err(RlpDecodeError::UnexpectedList);
        }
        let mut to = BytesMut::with_capacity(h.payload_len);
        to.extend_from_slice(&from[..h.payload_len]);
        from.advance(h.payload_len);

        Ok(to)
    }
}

impl RlpDecodable for Bytes {
    fn decode(buf: &mut &[u8]) -> Result<Self, RlpDecodeError> {
        BytesMut::decode(buf).map(BytesMut::freeze)
    }
}

macro_rules! decode_integer {
    ($t:ty) => {
        impl RlpDecodable for $t {
            fn decode(buf: &mut &[u8]) -> Result<Self, RlpDecodeError> {
                let h = Header::decode(buf)?;
                if h.list {
                    return Err(RlpDecodeError::UnexpectedList);
                }
                if h.payload_len > (<$t>::BITS as usize / 8) {
                    return Err(RlpDecodeError::Overflow);
                }
                if buf.remaining() < h.payload_len {
                    return Err(RlpDecodeError::InputTooShort);
                }
                // In the case of 0x80, the Header will be decoded, leaving h.payload_len to be
                // zero.
                // 0x80 is the canonical encoding of 0, so we return 0 here.
                if h.payload_len == 0 {
                    return Ok(<$t>::from(0u8));
                }
                let v = <$t>::from_be_bytes(
                    static_left_pad(&buf[..h.payload_len]).ok_or(RlpDecodeError::LeadingZero)?,
                );
                buf.advance(h.payload_len);
                Ok(v)
            }
        }
    };
}

decode_integer!(usize);
decode_integer!(u8);
decode_integer!(u16);
decode_integer!(u32);
decode_integer!(u64);
decode_integer!(u128);

pub struct Rlp<'a> {
    payload_view: &'a [u8],
}

impl<'a> Rlp<'a> {
    pub fn new(mut payload: &'a [u8]) -> Result<Self, RlpDecodeError> {
        let h = Header::decode(&mut payload)?;
        if !h.list {
            return Err(RlpDecodeError::UnexpectedString);
        }

        let payload_view = &payload[..h.payload_len];
        Ok(Self { payload_view })
    }

    pub fn get_next<T: RlpDecodable>(&mut self) -> Result<Option<T>, RlpDecodeError> {
        if self.payload_view.is_empty() {
            return Ok(None);
        }

        Ok(Some(T::decode(&mut self.payload_view)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RlpDecodable;
    use core::fmt::Debug;
    use hex_literal::hex;

    fn check_decode<'a, T, IT>(fixtures: IT)
    where
        T: RlpDecodable + PartialEq + Debug,
        IT: IntoIterator<Item = (Result<T, RlpDecodeError>, &'a [u8])>,
    {
        for (expected, mut input) in fixtures {
            assert_eq!(T::decode(&mut input), expected);
            if expected.is_ok() {
                assert_eq!(input, &[]);
            }
        }
    }

    #[test]
    fn rlp_strings() {
        check_decode::<Bytes, _>(vec![
            (Ok(hex!("00")[..].to_vec().into()), &hex!("00")[..]),
            (
                Ok(hex!("6f62636465666768696a6b6c6d")[..].to_vec().into()),
                &hex!("8D6F62636465666768696A6B6C6D")[..],
            ),
            (Err(RlpDecodeError::UnexpectedList), &hex!("C0")[..]),
        ])
    }

    #[test]
    fn rlp_u64() {
        check_decode(vec![
            (Ok(9_u64), &hex!("09")[..]),
            (Ok(0_u64), &hex!("80")[..]),
            (Ok(0x0505_u64), &hex!("820505")[..]),
            (Ok(0xCE05050505_u64), &hex!("85CE05050505")[..]),
            (Err(RlpDecodeError::Overflow), &hex!("8AFFFFFFFFFFFFFFFFFF7C")[..]),
            (Err(RlpDecodeError::InputTooShort), &hex!("8BFFFFFFFFFFFFFFFFFF7C")[..]),
            (Err(RlpDecodeError::UnexpectedList), &hex!("C0")[..]),
            (Err(RlpDecodeError::LeadingZero), &hex!("00")[..]),
            (Err(RlpDecodeError::NonCanonicalSingleByte), &hex!("8105")[..]),
            (Err(RlpDecodeError::LeadingZero), &hex!("8200F4")[..]),
            (Err(RlpDecodeError::NonCanonicalSize), &hex!("B8020004")[..]),
            (
                Err(RlpDecodeError::Overflow),
                &hex!("A101000000000000000000000000000000000000008B000000000000000000000000")[..],
            ),
        ])
    }
}
