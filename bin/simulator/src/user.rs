//! Simulated user for the forum simulator.
//!
//! Each user has their own keypair and can create forum content.

use pqpgp::crypto::KeyPair;
use pqpgp::error::Result;

/// A simulated user with cryptographic identity.
#[derive(Debug)]
pub struct SimulatedUser {
    /// User's ML-DSA-87 keypair for signing.
    keypair: KeyPair,
}

impl SimulatedUser {
    /// Creates a new simulated user with a fresh keypair.
    pub fn new(_name: &str, _relay_port: u16) -> Result<Self> {
        let keypair = KeyPair::generate_mldsa87()?;

        Ok(Self { keypair })
    }

    /// Returns the user's keypair.
    pub fn keypair(&self) -> &KeyPair {
        &self.keypair
    }
}
