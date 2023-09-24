use crate::{
    mac::{HeaderBytes, MAC},
    util::{hmac_sha256, id2pk, sha256},
    ECIESError,
};
use aes::{cipher::StreamCipher, Aes128, Aes256};
use byteorder::{BigEndian, ReadBytesExt};
use bytes::{Bytes, BytesMut};
use ctr::Ctr64BE;
use digest::{crypto_common::KeyIvInit, Digest};
use educe::Educe;
use ethereum_types::{H128, H256, H512 as PeerId};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    PublicKey, SecretKey, SECP256K1,
};
use sha2::Sha256;
use sha3::Keccak256;
use trust_rlp::Rlp;

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
    inbound_aes: Option<Ctr64BE<Aes256>>,
    #[educe(Debug(ignore))]
    outbound_aes: Option<Ctr64BE<Aes256>>,
    inbound_mac: Option<MAC>,
    outbound_mac: Option<MAC>,

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
            inbound_aes: None,
            outbound_aes: None,
            outbound_mac: None,
            inbound_mac: None,
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

    fn parse_auth_unencrypted(&mut self, data: &[u8]) -> Result<(), ECIESError> {
        let mut data = Rlp::new(data)?;

        let sigdata = data.get_next::<[u8; 65]>()?.ok_or(ECIESError::InvalidAuthData)?;
        let signature = RecoverableSignature::from_compact(
            &sigdata[..64],
            RecoveryId::from_i32(sigdata[64] as i32)?,
        )?;
        let remote_id = data.get_next::<[u8; 64]>()?.ok_or(ECIESError::InvalidAuthData)?.into();
        self.remote_id = Some(remote_id);
        self.remote_public_key = Some(id2pk(remote_id)?);
        self.remote_nonce =
            Some(data.get_next::<[u8; 32]>()?.ok_or(ECIESError::InvalidAuthData)?.into());

        let x = ecdh_x(&self.remote_public_key.unwrap(), &self.secret_key);
        self.remote_ephemeral_public_key = Some(SECP256K1.recover_ecdsa(
            &secp256k1::Message::from_slice((x ^ self.remote_nonce.unwrap()).as_ref()).unwrap(),
            &signature,
        )?);
        self.ephemeral_shared_secret =
            Some(ecdh_x(&self.remote_ephemeral_public_key.unwrap(), &self.ephemeral_secret_key));

        Ok(())
    }

    fn parse_ack_unencrypted(&mut self, data: &[u8]) -> Result<(), ECIESError> {
        let mut data = Rlp::new(data)?;
        self.remote_ephemeral_public_key =
            Some(id2pk(data.get_next::<[u8; 64]>()?.ok_or(ECIESError::InvalidAckData)?.into())?);
        self.remote_nonce =
            Some(data.get_next::<[u8; 32]>()?.ok_or(ECIESError::InvalidAckData)?.into());

        self.ephemeral_shared_secret =
            Some(ecdh_x(&self.remote_ephemeral_public_key.unwrap(), &self.ephemeral_secret_key));
        Ok(())
    }

    pub fn read_auth(&mut self, data: &mut [u8]) -> Result<(), ECIESError> {
        self.remote_init_message = Some(Bytes::copy_from_slice(data));
        let unencrypted = self.decrypt_message(data)?;
        self.parse_auth_unencrypted(unencrypted)
    }

    pub fn read_ack(&mut self, data: &mut [u8]) -> Result<(), ECIESError> {
        self.remote_init_message = Some(Bytes::copy_from_slice(data));
        let unencrypted = self.decrypt_message(data)?;
        self.parse_ack_unencrypted(unencrypted)?;
        self.setup_frame(false);
        Ok(())
    }

    fn setup_frame(&mut self, incoming: bool) {
        let mut hasher = Keccak256::new();
        for el in &if incoming {
            [self.nonce, self.remote_nonce.unwrap()]
        } else {
            [self.remote_nonce.unwrap(), self.nonce]
        } {
            hasher.update(el);
        }
        let h_nonce = H256::from(hasher.finalize().as_ref());

        let iv = H128::default();
        let shared_secret: H256 = {
            let mut hasher = Keccak256::new();
            hasher.update(self.ephemeral_shared_secret.unwrap().0.as_ref());
            hasher.update(h_nonce.0.as_ref());
            H256::from(hasher.finalize().as_ref())
        };

        let aes_secret: H256 = {
            let mut hasher = Keccak256::new();
            hasher.update(self.ephemeral_shared_secret.unwrap().0.as_ref());
            hasher.update(shared_secret.0.as_ref());
            H256::from(hasher.finalize().as_ref())
        };
        self.inbound_aes =
            Some(Ctr64BE::<Aes256>::new(aes_secret.0.as_ref().into(), iv.as_ref().into()));
        self.outbound_aes =
            Some(Ctr64BE::<Aes256>::new(aes_secret.0.as_ref().into(), iv.as_ref().into()));

        let mac_secret: H256 = {
            let mut hasher = Keccak256::new();
            hasher.update(self.ephemeral_shared_secret.unwrap().0.as_ref());
            hasher.update(aes_secret.0.as_ref());
            H256::from(hasher.finalize().as_ref())
        };
        self.inbound_mac = Some(MAC::new(mac_secret));
        self.inbound_mac.as_mut().unwrap().update((mac_secret ^ self.nonce).as_ref());
        self.inbound_mac.as_mut().unwrap().update(self.remote_init_message.as_ref().unwrap());
        self.outbound_mac = Some(MAC::new(mac_secret));
        self.outbound_mac
            .as_mut()
            .unwrap()
            .update((mac_secret ^ self.remote_nonce.unwrap()).as_ref());
        self.outbound_mac.as_mut().unwrap().update(self.init_message.as_ref().unwrap());
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

    pub fn read_body<'a>(&mut self, data: &'a mut [u8]) -> Result<&'a mut [u8], ECIESError> {
        let (body, mac_bytes) = split_at_mut(data, data.len() - 16)?;
        let mac = H128::from_slice(mac_bytes);
        self.inbound_mac.as_mut().unwrap().update_body(body);
        let check_mac = self.inbound_mac.as_mut().unwrap().digest();
        if check_mac != mac {
            return Err(ECIESError::TagCheckBodyFailed.into());
        }

        let size = self.body_size.unwrap();
        self.body_size = None;
        let ret = body;
        self.inbound_aes.as_mut().unwrap().apply_keystream(ret);
        Ok(split_at_mut(ret, size)?.0)
    }

    pub fn read_header(&mut self, data: &mut [u8]) -> Result<usize, ECIESError> {
        let (header_bytes, mac_bytes) = split_at_mut(data, 16)?;
        let header = HeaderBytes::from_mut_slice(header_bytes);
        let mac = H128::from_slice(&mac_bytes[..16]);

        self.inbound_mac.as_mut().unwrap().update_header(header);
        let check_mac = self.inbound_mac.as_mut().unwrap().digest();
        if check_mac != mac {
            return Err(ECIESError::TagCheckHeaderFailed.into());
        }

        self.inbound_aes.as_mut().unwrap().apply_keystream(header);
        if header.as_slice().len() < 3 {
            return Err(ECIESError::InvalidHeader.into());
        }

        let body_size = usize::try_from(header.as_slice().read_uint::<BigEndian>(3)?)?;

        self.body_size = Some(body_size);

        Ok(self.body_size.unwrap())
    }
}
