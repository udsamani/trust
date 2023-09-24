use crate::{mac::MAC, util::id2pk, ECIESError};
use aes::Aes256;
use bytes::Bytes;
use ctr::Ctr64BE;
use educe::Educe;
use ethereum_types::{H256, H512 as PeerId};
use secp256k1::{PublicKey, SecretKey, SECP256K1};

#[derive(Educe)]
#[educe(Debug)]
pub struct ECIES {
    secret_key: SecretKey,
    public_key: PublicKey,
    remote_public_key: Option<PublicKey>,

    pub(crate) remote_id: Option<PeerId>,

    ephemeral_secret_key: SecretKey,
    ephemeral_public_key: PublicKey,
    ephemeral_shared_secret: Option<H256>,
    remote_ephemeral_public_key: Option<PublicKey>,

    nonce: H256,
    remote_nonce: Option<H256>,

    #[educe(Debug(ignore))]
    incoming_aes: Option<Ctr64BE<Aes256>>,
    #[educe(Debug(ignore))]
    outgoing_aes: Option<Ctr64BE<Aes256>>,
    incoming_mac: Option<MAC>,
    outgoing_mac: Option<MAC>,

    init_message: Option<Bytes>,
    remote_init_message: Option<Bytes>,

    body_size: Option<usize>,
}

impl ECIES {
    fn new_static_client(
        secret_key: SecretKey,
        remote_id: PeerId,
        nonce: H256,
        ephemeral_secret_key: SecretKey,
    ) -> Result<Self, ECIESError> {
        let public_key = PublicKey::from_secret_key(SECP256K1, &secret_key);
        let remote_public_key = id2pk(remote_id)?;
        let ephemeral_public_key = PublicKey::from_secret_key(SECP256K1, &ephemeral_secret_key);

        Ok(Self {
            secret_key,
            public_key,
            ephemeral_secret_key,
            ephemeral_public_key,
            nonce,

            remote_public_key: Some(remote_public_key),
            remote_ephemeral_public_key: None,
            remote_nonce: None,
            ephemeral_shared_secret: None,
            init_message: None,
            remote_init_message: None,
            remote_id: Some(remote_id),
            body_size: None,
            incoming_aes: None,
            outgoing_aes: None,
            outgoing_mac: None,
            incoming_mac: None,
        })
    }

    pub fn new_client(secret_key: SecretKey, remote_id: PeerId) -> Result<Self, ECIESError> {
        let nonce = H256::random();
        let ephemeral_secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());

        Self::new_static_client(secret_key, remote_id, nonce, ephemeral_secret_key)
    }

    /// Return the contained remote peer ID.
    pub fn remote_id(&self) -> PeerId {
        self.remote_id.unwrap()
    }

    pub const fn header_len() -> usize {
        32
    }

    pub fn body_len(&self) -> usize {
        let len = self.body_size.unwrap();
        (if len % 16 == 0 { len } else { (len / 16 + 1) * 16 }) + 16
    }
}
