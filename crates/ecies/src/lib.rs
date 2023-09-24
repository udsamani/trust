extern crate bytes;

use bytes::{Bytes, BytesMut};
use ethereum_types::H512 as PeerId;

pub mod algorithm;
pub mod mac;
pub mod stream;
pub mod util;

mod error;
pub use error::ECIESError;

mod codec;

/// Raw Outbound values for an ECIES protocol
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutboundECIESValue {
    /// The AUTH message being sent out
    Auth,
    /// The ACK message being sent out
    Ack,
    /// The message being sent out.
    Message(Bytes),
}

/// Raw Inbound values for an ECIES protocol
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InboundECIESValue {
    /// Receiving a message from a [`PeerId`]
    AuthReceive(PeerId),
    /// Receiving an ACK message
    Ack,
    /// Receiving a message
    Message(BytesMut),
}
