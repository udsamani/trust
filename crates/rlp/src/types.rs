#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Header {
    pub list: bool,
    pub payload_len: usize,
}

pub const EMPTY_STRING_CODE: u8 = 0x80;
pub const EMPTY_LIST_CODE: u8 = 0xC0;
