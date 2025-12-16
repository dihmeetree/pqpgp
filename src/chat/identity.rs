//! Identity key management for the chat protocol.
//!
//! This module provides long-term identity keys used to authenticate users in the
//! chat protocol. Identity keys are:
//!
//! - **Long-lived**: Used for the lifetime of an account
//! - **Signing keys**: ML-DSA-87 for authentication (not encryption)
//! - **Publicly verifiable**: Used to verify signed prekeys and establish trust
//!
//! ## Key Hierarchy
//!
//! ```text
//! Identity Key (ML-DSA-87, long-term)
//!     └── Signs → Signed PreKey (ML-KEM-1024, medium-term)
//!                     └── Used in → X3DH key agreement
//! ```
//!
//! ## Security Considerations
//!
//! - Identity private keys should be stored encrypted with user's passphrase
//! - Key fingerprints should be verified out-of-band (QR code, phone call, etc.)
//! - Compromise of identity key allows impersonation but not decryption of past messages

use crate::crypto::{
    generate_key_id, hash_data, sign_message, verify_signature, Algorithm, KeyUsage, Password,
    PrivateKey, PublicKey, Signature,
};
use crate::error::{PqpgpError, Result};
use pqcrypto_mldsa::mldsa87;
use pqcrypto_traits::sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::ZeroizeOnDrop;

/// A public identity key for authentication and verification.
///
/// This is the public component of an identity, used to:
/// - Verify signatures on prekeys
/// - Authenticate users in the protocol
/// - Generate fingerprints for out-of-band verification
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityKey {
    /// The ML-DSA-87 public key bytes
    key_bytes: Vec<u8>,
    /// Unique key identifier (derived from key material)
    key_id: u64,
    /// Creation timestamp
    created: u64,
}

impl fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityKey")
            .field("key_id", &format!("{:016X}", self.key_id))
            .field("key_size", &self.key_bytes.len())
            .field("created", &self.created)
            .finish()
    }
}

impl fmt::Display for IdentityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdentityKey({:016X})", self.key_id)
    }
}

impl IdentityKey {
    /// Creates a new identity key from raw ML-DSA-87 public key bytes.
    ///
    /// # Arguments
    /// * `key_bytes` - The ML-DSA-87 public key bytes
    ///
    /// # Errors
    /// Returns an error if the key bytes are invalid.
    pub fn from_bytes(key_bytes: Vec<u8>) -> Result<Self> {
        // Validate by attempting to parse
        mldsa87::PublicKey::from_bytes(&key_bytes)
            .map_err(|_| PqpgpError::key("Invalid ML-DSA-87 public key bytes"))?;

        let created = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let key_id = generate_key_id(&key_bytes, Algorithm::Mldsa87, created);

        Ok(Self {
            key_bytes,
            key_id,
            created,
        })
    }

    /// Returns the unique key identifier.
    pub fn key_id(&self) -> u64 {
        self.key_id
    }

    /// Returns the creation timestamp.
    pub fn created(&self) -> u64 {
        self.created
    }

    /// Returns the raw public key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.key_bytes
    }

    /// Computes the fingerprint of this identity key.
    ///
    /// The fingerprint is a SHA3-512 hash of the key material, suitable for
    /// out-of-band verification (e.g., comparing over phone, QR code scanning).
    pub fn fingerprint(&self) -> [u8; 64] {
        let mut data = Vec::new();
        data.extend_from_slice(b"PQPGP-identity-v1");
        data.extend_from_slice(&self.key_bytes);
        hash_data(&data)
    }

    /// Returns a short fingerprint suitable for display (first 8 bytes as hex).
    pub fn short_fingerprint(&self) -> String {
        let fp = self.fingerprint();
        hex::encode(&fp[..8])
    }

    /// Verifies a signature created by this identity.
    ///
    /// # Arguments
    /// * `message` - The message that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Errors
    /// Returns an error if the signature is invalid.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        let public_key = self.as_public_key()?;
        verify_signature(&public_key, message, signature)
    }

    /// Converts to the underlying crypto PublicKey type.
    pub(crate) fn as_public_key(&self) -> Result<PublicKey> {
        let mldsa_key = mldsa87::PublicKey::from_bytes(&self.key_bytes)
            .map_err(|_| PqpgpError::key("Failed to parse ML-DSA-87 public key"))?;
        Ok(PublicKey::new_mldsa87(
            mldsa_key,
            self.key_id,
            KeyUsage::sign_only(),
        ))
    }
}

/// A private identity key for signing.
///
/// This is the private component of an identity, used to:
/// - Sign prekeys for authentication
/// - Sign messages for authentication (in authenticated protocols)
///
/// # Security
///
/// This key should be:
/// - Stored encrypted at rest
/// - Never transmitted over the network
/// - Backed up securely by the user
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct IdentityPrivateKey {
    /// The ML-DSA-87 secret key bytes (zeroized on drop)
    key_bytes: Vec<u8>,
    /// Associated key ID (matches the public key)
    key_id: u64,
    /// Whether the key is encrypted
    encrypted: bool,
}

impl fmt::Debug for IdentityPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityPrivateKey")
            .field("key_id", &format!("{:016X}", self.key_id))
            .field("encrypted", &self.encrypted)
            .finish_non_exhaustive()
    }
}

impl IdentityPrivateKey {
    /// Returns the key ID.
    pub fn key_id(&self) -> u64 {
        self.key_id
    }

    /// Returns whether this key is encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// Signs a message with this identity key.
    ///
    /// # Arguments
    /// * `message` - The message to sign
    /// * `password` - Password if the key is encrypted
    ///
    /// # Errors
    /// Returns an error if signing fails or password is required but not provided.
    pub fn sign(&self, message: &[u8], password: Option<&Password>) -> Result<Signature> {
        let private_key = self.as_private_key(password)?;
        sign_message(&private_key, message, password)
    }

    /// Converts to the underlying crypto PrivateKey type.
    pub(crate) fn as_private_key(&self, _password: Option<&Password>) -> Result<PrivateKey> {
        let mldsa_key = mldsa87::SecretKey::from_bytes(&self.key_bytes)
            .map_err(|_| PqpgpError::key("Failed to parse ML-DSA-87 secret key"))?;
        Ok(PrivateKey::new_mldsa87(
            mldsa_key,
            self.key_id,
            KeyUsage::sign_only(),
        ))
    }
}

/// A complete identity key pair (public + private).
///
/// This represents a user's long-term identity in the chat protocol.
/// It's used to:
/// - Sign prekey bundles
/// - Authenticate during session establishment
/// - Provide a stable identifier for contacts
#[derive(Clone, Serialize, Deserialize)]
pub struct IdentityKeyPair {
    /// The public identity key
    pub public: IdentityKey,
    /// The private identity key
    pub private: IdentityPrivateKey,
}

impl fmt::Debug for IdentityKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityKeyPair")
            .field("key_id", &format!("{:016X}", self.public.key_id))
            .finish()
    }
}

impl fmt::Display for IdentityKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identity({:016X})", self.public.key_id)
    }
}

impl IdentityKeyPair {
    /// Generates a new identity key pair.
    ///
    /// This creates a fresh ML-DSA-87 key pair suitable for long-term use
    /// as a chat identity.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use pqpgp::chat::IdentityKeyPair;
    ///
    /// let identity = IdentityKeyPair::generate()?;
    /// println!("New identity: {}", identity.public.short_fingerprint());
    /// # Ok::<(), pqpgp::error::PqpgpError>(())
    /// ```
    pub fn generate() -> Result<Self> {
        let (public_key, secret_key) = mldsa87::keypair();

        let created = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let public_bytes = SignPublicKey::as_bytes(&public_key).to_vec();
        let private_bytes = SignSecretKey::as_bytes(&secret_key).to_vec();

        let key_id = generate_key_id(&public_bytes, Algorithm::Mldsa87, created);

        let public = IdentityKey {
            key_bytes: public_bytes,
            key_id,
            created,
        };

        let private = IdentityPrivateKey {
            key_bytes: private_bytes,
            key_id,
            encrypted: false,
        };

        Ok(Self { public, private })
    }

    /// Returns the key ID for this identity.
    pub fn key_id(&self) -> u64 {
        self.public.key_id
    }

    /// Returns the public identity key.
    pub fn public_key(&self) -> &IdentityKey {
        &self.public
    }

    /// Returns the private identity key.
    pub fn private_key(&self) -> &IdentityPrivateKey {
        &self.private
    }

    /// Signs data with this identity.
    ///
    /// # Arguments
    /// * `data` - The data to sign
    /// * `password` - Password if the private key is encrypted
    pub fn sign(&self, data: &[u8], password: Option<&Password>) -> Result<Signature> {
        self.private.sign(data, password)
    }

    /// Verifies a signature created by this identity.
    ///
    /// # Arguments
    /// * `data` - The data that was signed
    /// * `signature` - The signature to verify
    pub fn verify(&self, data: &[u8], signature: &Signature) -> Result<()> {
        self.public.verify(data, signature)
    }

    /// Returns the fingerprint of the public key.
    pub fn fingerprint(&self) -> [u8; 64] {
        self.public.fingerprint()
    }

    /// Returns a short fingerprint suitable for display.
    pub fn short_fingerprint(&self) -> String {
        self.public.short_fingerprint()
    }
}

/// Type alias for backwards compatibility and cleaner API.
pub type Identity = IdentityKeyPair;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation() {
        let identity = IdentityKeyPair::generate().unwrap();

        assert_eq!(identity.public.key_id, identity.private.key_id);
        assert!(!identity.private.is_encrypted());
        assert!(!identity.public.as_bytes().is_empty());
    }

    #[test]
    fn test_identity_signing() {
        let identity = IdentityKeyPair::generate().unwrap();
        let message = b"Test message for identity signing";

        let signature = identity.sign(message, None).unwrap();
        assert_eq!(signature.key_id(), identity.key_id());

        // Verification should succeed
        identity.verify(message, &signature).unwrap();
    }

    #[test]
    fn test_identity_verification_fails_wrong_message() {
        let identity = IdentityKeyPair::generate().unwrap();
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let signature = identity.sign(message, None).unwrap();

        // Verification should fail with wrong message
        assert!(identity.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_identity_verification_fails_wrong_identity() {
        let identity1 = IdentityKeyPair::generate().unwrap();
        let identity2 = IdentityKeyPair::generate().unwrap();
        let message = b"Test message";

        let signature = identity1.sign(message, None).unwrap();

        // Verification with wrong identity should fail
        assert!(identity2.verify(message, &signature).is_err());
    }

    #[test]
    fn test_identity_fingerprint() {
        let identity1 = IdentityKeyPair::generate().unwrap();
        let identity2 = IdentityKeyPair::generate().unwrap();

        // Different identities should have different fingerprints
        assert_ne!(identity1.fingerprint(), identity2.fingerprint());
        assert_ne!(identity1.short_fingerprint(), identity2.short_fingerprint());

        // Fingerprint should be deterministic
        assert_eq!(identity1.fingerprint(), identity1.fingerprint());
    }

    #[test]
    fn test_identity_key_from_bytes() {
        let identity = IdentityKeyPair::generate().unwrap();
        let bytes = identity.public.as_bytes().to_vec();

        // Should be able to reconstruct from bytes (note: key_id will differ due to timestamp)
        let recovered = IdentityKey::from_bytes(bytes.clone()).unwrap();

        // The public key bytes should match
        assert_eq!(recovered.as_bytes(), identity.public.as_bytes());
    }

    #[test]
    fn test_invalid_identity_key_bytes() {
        let invalid_bytes = vec![0u8; 100]; // Wrong size

        assert!(IdentityKey::from_bytes(invalid_bytes).is_err());
    }

    #[test]
    fn test_identity_display() {
        let identity = IdentityKeyPair::generate().unwrap();

        let display = format!("{}", identity);
        assert!(display.contains("Identity("));

        let debug = format!("{:?}", identity);
        assert!(debug.contains("IdentityKeyPair"));
    }

    #[test]
    fn test_identity_serialization() {
        let identity = IdentityKeyPair::generate().unwrap();

        // Serialize and deserialize
        let serialized = bincode::serialize(&identity).unwrap();
        let deserialized: IdentityKeyPair = bincode::deserialize(&serialized).unwrap();

        assert_eq!(identity.key_id(), deserialized.key_id());
        assert_eq!(identity.public.as_bytes(), deserialized.public.as_bytes());
    }
}
