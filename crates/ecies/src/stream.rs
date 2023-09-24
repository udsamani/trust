use crate::{codec::ECIESCodec, ECIESError};
use ethereum_types::H512 as PeerId;
use secp256k1::SecretKey;
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Decoder, Framed};

/// ECIES stream over TCP.
#[derive(Debug)]
pub struct ECIESStream<I> {
    stream: Framed<I, ECIESCodec>,
    remote_id: PeerId,
}

impl<I> ECIESStream<I>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn connect(
        transport: I,
        secret_key: SecretKey,
        remote_id: PeerId,
    ) -> Result<Self, ECIESError> {
        let ecies = ECIESCodec::new_client(secret_key, remote_id)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid handshake"))?;
        let transport = ecies.framed(transport);
        Ok(Self { stream: transport, remote_id })
    }
}
