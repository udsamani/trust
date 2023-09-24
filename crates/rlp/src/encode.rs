use crate::types::*;
use auto_impl::auto_impl;
use bytes::{BufMut, BytesMut};

macro_rules! to_be_bytes_trimmed {
    ($be:ident, $x:expr) => {{
        $be = $x.to_be_bytes();
        &$be[($x.leading_zeros() / 8) as usize..]
    }};
}

pub const fn length_of_length(payload_length: usize) -> usize {
    if payload_length < 56 {
        1
    } else {
        1 + 8 - payload_length.leading_zeros() as usize / 8
    }
}

#[auto_impl(&)]
#[cfg_attr(feature = "alloc", auto_impl(Box, Arc))]
pub trait RlpEncodable {
    fn encode(&self, out: &mut dyn BufMut);

    fn length(&self) -> usize {
        let mut out = BytesMut::new();
        self.encode(&mut out);
        out.len()
    }
}

impl RlpEncodable for &str {
    fn encode(&self, out: &mut dyn BufMut) {
        self.as_bytes().encode(out);
    }
    fn length(&self) -> usize {
        self.as_bytes().length()
    }
}

impl RlpEncodable for Header {
    fn encode(&self, out: &mut dyn BufMut) {
        if self.payload_len < 56 {
            let code = if self.list { EMPTY_LIST_CODE } else { EMPTY_STRING_CODE };
            out.put_u8(code + self.payload_len as u8);
        } else {
            let len_be;
            let len_be = to_be_bytes_trimmed!(len_be, self.payload_len);
            let code = if self.list { 0xF7 } else { 0xB7 };
            out.put_u8(code + len_be.len() as u8);
            out.put_slice(len_be);
        }
    }
}

impl<'a> RlpEncodable for &'a [u8] {
    fn encode(&self, out: &mut dyn BufMut) {
        if self.len() != 1 || self[0] >= EMPTY_STRING_CODE {
            Header { list: false, payload_len: self.len() }.encode(out);
        }
        out.put_slice(self);
    }

    fn length(&self) -> usize {
        let mut len = self.len();
        if self.len() != 1 || self[0] >= EMPTY_STRING_CODE {
            len += length_of_length(self.len());
        }
        len
    }
}

impl<const LEN: usize> RlpEncodable for [u8; LEN] {
    fn encode(&self, out: &mut dyn BufMut) {
        (self as &[u8]).encode(out)
    }

    fn length(&self) -> usize {
        (self as &[u8]).length()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use hex_literal::hex;

    fn encoded<T: RlpEncodable>(t: T) -> BytesMut {
        let mut out = BytesMut::new();
        t.encode(&mut out);
        out
    }

    #[test]
    fn rlp_str() {
        assert_eq!(encoded("")[..], hex!("80")[..]);
        assert_eq!(encoded("udit")[..], hex!("8475646974")[..]);
    }
}
