use crate::{
    mac::MAC,
    util::{hmac_sha256, id2pk, sha256},
    ECIESError,
};
use aes::{cipher::StreamCipher, Aes128, Aes256};
use bytes::{Bytes, BytesMut};
use ctr::Ctr64BE;
use digest::{crypto_common::KeyIvInit, Digest};
use educe::Educe;
use ethereum_types::{H128, H256, H512 as PeerId};
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use sha2::Sha256;

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

fn kdf(secret: H256, s1: &[u8], dest: &mut [u8]) {
    // SEC/ISO/Shoup specify counter size SHOULD be equivalent
    // to size of hash output, however, it also notes that
    // the 4 bytes is okay. NIST specifies 4 bytes.
    let mut ctr = 1_u32;
    let mut written = 0_usize;
    while written < dest.len() {
        let mut hasher = Sha256::default();
        let ctrs = [(ctr >> 24) as u8, (ctr >> 16) as u8, (ctr >> 8) as u8, ctr as u8];
        hasher.update(ctrs);
        hasher.update(secret.as_bytes());
        hasher.update(s1);
        let d = hasher.finalize();
        dest[written..(written + 32)].copy_from_slice(&d);
        written += 32;
        ctr += 1;
    }
}

fn ecdh_x(public_key: &PublicKey, secret_key: &SecretKey) -> H256 {
    H256::from_slice(&secp256k1::ecdh::shared_secret_point(public_key, secret_key)[..32])
}

fn split_at_mut<T>(arr: &mut [T], idx: usize) -> Result<(&mut [T], &mut [T]), ECIESError> {
    if idx > arr.len() {
        return Err(ECIESError::OutOfBounds { idx, len: arr.len() }.into());
    }
    Ok(arr.split_at_mut(idx))
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

    fn decrypt_message<'a>(&self, data: &'a mut [u8]) -> Result<&'a mut [u8], ECIESError> {
        let (auth_data, encrypted) = split_at_mut(data, 2)?;
        let (pubkey_bytes, encrypted) = split_at_mut(encrypted, 65)?;
        let public_key = PublicKey::from_slice(pubkey_bytes)?;
        let (data_iv, tag_bytes) = split_at_mut(encrypted, encrypted.len() - 32)?;
        let (iv, encrypted_data) = split_at_mut(data_iv, 16)?;
        let tag = H256::from_slice(tag_bytes);

        let x = ecdh_x(&public_key, &self.secret_key);
        let mut key = [0u8; 32];
        kdf(x, &[], &mut key);
        let enc_key = H128::from_slice(&key[..16]);
        let mac_key = sha256(&key[16..32]);

        let check_tag = hmac_sha256(mac_key.as_ref(), &[iv, encrypted_data], auth_data);
        if check_tag != tag {
            return Err(ECIESError::TagCheckDecryptFailed.into());
        }

        let decrypted_data = encrypted_data;

        let mut decryptor = Ctr64BE::<Aes128>::new(enc_key.as_ref().into(), (*iv).into());
        decryptor.apply_keystream(decrypted_data);

        Ok(decrypted_data)
    }

    fn encrypt_message(&self, data: &[u8], out: &mut BytesMut) {
        out.reserve(secp256k1::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE + 16 + data.len() + 32);

        let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        out.extend_from_slice(
            &PublicKey::from_secret_key(SECP256K1, &secret_key).serialize_uncompressed(),
        );

        let x = ecdh_x(&self.remote_public_key.unwrap(), &secret_key);
        let mut key = [0u8; 32];
        kdf(x, &[], &mut key);

        let enc_key = H128::from_slice(&key[..16]);
        let mac_key = sha256(&key[16..32]);

        let iv = H128::random();
        let mut encryptor = Ctr64BE::<Aes128>::new(enc_key.as_ref().into(), iv.as_ref().into());

        let mut encrypted = data.to_vec();
        encryptor.apply_keystream(&mut encrypted);

        let total_size: u16 = u16::try_from(65 + 16 + data.len() + 32).unwrap();

        let tag =
            hmac_sha256(mac_key.as_ref(), &[iv.as_bytes(), &encrypted], &total_size.to_be_bytes());

        out.extend_from_slice(iv.as_bytes());
        out.extend_from_slice(&encrypted);
        out.extend_from_slice(tag.as_ref());
    }
}
