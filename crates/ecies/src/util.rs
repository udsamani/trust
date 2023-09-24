use ethereum_types::H512 as PeerId;
use secp256k1::PublicKey;

pub fn id2pk(id: PeerId) -> Result<PublicKey, secp256k1::Error> {
    let mut s = [0u8; 65];
    s[0] = 4;
    s[1..].copy_from_slice(id.as_bytes());
    PublicKey::from_slice(&s)
}
