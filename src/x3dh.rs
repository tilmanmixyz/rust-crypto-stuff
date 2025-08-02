//! This is an implementation of [X3DH](https://signal.org/https://signal.org/docs/specifications/x3dh/)
//! but using Ed25519 for identity instead of implementing a signing algorithm
//! on top of X25519, i.e. [XEdDSA](https://signal.org/docs/specifications/xeddsa/).
//! It also uses Blake3 over SHA-512

use ed25519::{ed25519::signature::Signer, Signature, ed25519::signature::Verifier};

const RUST_CRYPTO_STUFF_X3DH_INFO: &str = "RUST_CRYPTO_STUFF_X3DH_ED25519_BLAKE3";

pub struct User {
    pub ed25519_identity_pk: ed25519::VerifyingKey,
    pub x25519_signed_prekey: SignedX25519PreKey,

    ed25519_identity_sk: ed25519::SigningKey,
    x25519_prekey_sk: x25519::ReusableSecret,
}

impl User {
    pub fn new() -> User {
        let mut csprng = rand::rng();
        
        let identity_key = ed25519::SigningKey::generate(&mut csprng);
        
        let x25519_prekey_sk = x25519::ReusableSecret::random_from_rng(&mut csprng);
        
        let x25519_prekey_pk = x25519::PublicKey::from(&x25519_prekey_sk);
        let x25519_prekey_pk_signature = identity_key.sign(x25519_prekey_pk.as_bytes());
        let x25519_signed_prekey = SignedX25519PreKey {
            pk: x25519_prekey_pk,
            signature: x25519_prekey_pk_signature.to_bytes(),
        };

        User {
            x25519_prekey_sk,
            x25519_signed_prekey,
            ed25519_identity_pk: identity_key.verifying_key(),
            ed25519_identity_sk: identity_key,
        }
    }

    pub fn init_x3dh(&self, other: &KeyBundle) -> Result<(), X3DHError> {
        other.ed25519_identity_pk.verify_strict(other.x25519_signed_prekey.pk.as_bytes(), &Signature::from_bytes(&other.x25519_signed_prekey.signature)).map_err(|_| X3DHError::PreKeySignatureNoMatch)?;

        let mut csprng = rand::rng();
        // EKA
        let x25519_ephemeral_sk = x25519::ReusableSecret::random_from_rng(&mut csprng);    

        // IKA
        let self_x25519_identity_sk = ed25519_sk_to_x25519(&self.ed25519_identity_sk);
        // IKB
        let other_x25519_identity_pk = ed25519_pk_to_x25519(&other.ed25519_identity_pk);
        
        // DH1 = DH(IKA, SPKB)
        let dh1 = self_x25519_identity_sk.diffie_hellman(&other.x25519_signed_prekey.pk);

        // DH2 = DH(EKA, OKB)
        let dh2 = x25519_ephemeral_sk.diffie_hellman(&other_x25519_identity_pk);

        // DH3 = DH(EKA, SPKB)
        let dh3 = x25519_ephemeral_sk.diffie_hellman(&other.x25519_signed_prekey.pk);

        // SK = KDF(DH1 | DH2 | DH3)
        let mut kdf = blake3::Hasher::new_derive_key(RUST_CRYPTO_STUFF_X3DH_INFO);
        kdf.update(dh1.as_bytes());
        kdf.update(dh2.as_bytes());
        kdf.update(dh3.as_bytes());
        let sk = kdf.finalize().as_bytes();

        Ok(())
    }
}

/// convert an Ed25519 secret key into an X25519 secret key
fn ed25519_sk_to_x25519(ed25519_secret_key: &ed25519::SigningKey) -> x25519::StaticSecret {
    // SHA-512(ed25519_secret_key)
    return x25519::StaticSecret::from(ed25519_secret_key.to_scalar_bytes());
}

/// convert an Ed25519 public key to an X25519 public key
fn ed25519_pk_to_x25519(ed25519_public_key: &ed25519::VerifyingKey) -> x25519::PublicKey {
    // u = (1 + y) / (1 - y) = (Z + Y) / (Z - Y)
    return x25519::PublicKey::from(ed25519_public_key.to_montgomery().to_bytes());
}

pub struct KeyBundle {
    pub x25519_signed_prekey: SignedX25519PreKey,
    pub ed25519_identity_pk: ed25519::VerifyingKey,
}

pub struct SignedX25519PreKey {
    pub pk: x25519::PublicKey,
    pub signature: ed25519::ed25519::SignatureBytes,
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum X3DHError {
    #[error("the signature of the other parties prekey does not match their identity")]
    PreKeySignatureNoMatch
}