use crate::{algorithm::ECIES, ECIESError, InboundECIESValue, OutboundECIESValue};
use bytes::BytesMut;
use ethereum_types::H512 as PeerId;
use secp256k1::SecretKey;
use std::io;
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug)]
pub(crate) struct ECIESCodec {
    ecies: ECIES,
    state: ECIESState,
}

impl ECIESCodec {
    pub(crate) fn new_client(secret_key: SecretKey, remote_id: PeerId) -> Result<Self, ECIESError> {
        Ok(Self { ecies: ECIES::new_client(secret_key, remote_id)?, state: ECIESState::Auth })
    }
}

impl Decoder for ECIESCodec {
    type Item = InboundECIESValue;
    type Error = ECIESError;

    fn decode(&mut self, buf: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            match self.state {
                ECIESState::Auth => {
                    if buf.len() < 2 {
                        return Ok(None);
                    }

                    let payload_size = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                    let total_size = payload_size + 2;

                    if buf.len() < total_size {
                        return Ok(None);
                    }

                    // Read Auth from ECIES.
                    // self.ecies.read_auth(&mut buf.split_to(total_size))?;

                    self.state = ECIESState::Header;
                    return Ok(Some(InboundECIESValue::AuthReceive(self.ecies.remote_id())));
                }
                ECIESState::Ack => {
                    if buf.len() < 2 {
                        return Ok(None);
                    }

                    let payload_size = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                    let total_size = payload_size + 2;

                    if buf.len() < total_size {
                        return Ok(None);
                    }

                    // Read Ack From ECIES
                    // self.ecies.read_ack(&mut buf.split_to(total_size))?;

                    self.state = ECIESState::Header;
                    return Ok(Some(InboundECIESValue::Ack));
                }
                ECIESState::Header => {
                    if buf.len() < ECIES::header_len() {
                        return Ok(None);
                    }

                    // Read Header for ECIES
                    self.state = ECIESState::Body;
                }
                ECIESState::Body => {
                    let body_len = self.ecies.body_len();
                    if buf.len() < body_len {
                        return Ok(None);
                    }

                    let mut data = buf.split_to(body_len);
                    let mut ret = BytesMut::new();
                    // ret.extend_from_slice(self.ecies.read_body(&mut data)?);

                    self.state = ECIESState::Header;
                    return Ok(Some(InboundECIESValue::Message(ret)));
                }
            }
        }
    }
}

impl Encoder<OutboundECIESValue> for ECIESCodec {
    type Error = io::Error;

    fn encode(&mut self, item: OutboundECIESValue, buf: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            OutboundECIESValue::Auth => {
                self.state = ECIESState::Ack;
                // self.ecies.write_auth(buf);
                Ok(())
            }
            OutboundECIESValue::Ack => {
                self.state = ECIESState::Header;
                // self.ecies.write_ack(buf);
                Ok(())
            }
            OutboundECIESValue::Message(data) => {
                // self.ecies.write_header(buf, data.len());
                // self.ecies.write_body(buf, &data);
                Ok(())
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ECIESState {
    Auth,
    Ack,
    Header,
    Body,
}
