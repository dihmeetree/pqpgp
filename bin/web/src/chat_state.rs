//! Chat state management for the web interface.
//!
//! This module provides persistent storage and management of:
//! - Chat identity (long-term identity key)
//! - Prekey bundles for session establishment
//! - Active chat sessions
//! - Message history

use pqpgp::chat::prekey::PreKeyGenerator;
use pqpgp::chat::{EncryptedChatMessage, IdentityKeyPair, PreKeyBundle, Session};
use pqpgp::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::info;

/// Number of one-time prekeys to generate initially
const INITIAL_ONE_TIME_PREKEYS: u32 = 10;

/// Converts a fingerprint byte array to a hex string
fn fingerprint_to_hex(fp: &[u8; 64]) -> String {
    fp.iter().map(|b| format!("{:02x}", b)).collect()
}

/// A stored chat session with metadata
pub struct StoredSession {
    /// The cryptographic session
    pub session: Session,
    /// Contact fingerprint (their identity key fingerprint as hex)
    #[allow(dead_code)]
    pub contact_fingerprint: String,
    /// Contact display name
    #[allow(dead_code)]
    pub contact_name: String,
}

/// Message stored in history
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    /// Message content (decrypted)
    pub content: String,
    /// Timestamp as formatted string
    pub timestamp: String,
    /// Whether this was sent by us
    pub is_outgoing: bool,
}

/// Chat contact information stored in state
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredContact {
    /// Contact's identity fingerprint (hex string)
    pub fingerprint: String,
    /// Display name
    pub name: String,
    /// Contact's prekey bundle (serialized, for initiating sessions)
    pub prekey_bundle: Option<Vec<u8>>,
    /// Whether we have an active session
    pub has_session: bool,
}

/// Global chat state shared across requests
pub struct ChatState {
    /// Our identity key pair
    identity: Option<IdentityKeyPair>,
    /// Our prekey generator
    prekey_generator: Option<PreKeyGenerator>,
    /// Active sessions by contact fingerprint (hex string)
    sessions: HashMap<String, StoredSession>,
    /// Contact list by fingerprint (hex string)
    contacts: HashMap<String, StoredContact>,
    /// Message history by contact fingerprint (hex string)
    messages: HashMap<String, Vec<StoredMessage>>,
    /// Password for saving state (kept in memory only, never persisted)
    password: Option<String>,
}

impl Default for ChatState {
    fn default() -> Self {
        Self::new()
    }
}

impl ChatState {
    /// Creates a new empty chat state
    pub fn new() -> Self {
        Self {
            identity: None,
            prekey_generator: None,
            sessions: HashMap::new(),
            contacts: HashMap::new(),
            messages: HashMap::new(),
            password: None,
        }
    }

    /// Sets the password for saving state (kept in memory only)
    pub fn set_password(&mut self, password: String) {
        self.password = Some(password);
    }

    /// Gets the password for saving state
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    /// Generates a new chat identity
    pub fn generate_identity(&mut self) -> Result<String> {
        let identity = IdentityKeyPair::generate()?;
        let fingerprint = fingerprint_to_hex(&identity.public.fingerprint());

        // Generate prekeys
        let prekey_generator = PreKeyGenerator::new(&identity, INITIAL_ONE_TIME_PREKEYS)?;

        info!("Generated new chat identity: {}", fingerprint);

        self.identity = Some(identity);
        self.prekey_generator = Some(prekey_generator);

        Ok(fingerprint)
    }

    /// Returns whether we have an identity
    #[allow(dead_code)]
    pub fn has_identity(&self) -> bool {
        self.identity.is_some()
    }

    /// Returns our identity fingerprint as a hex string
    pub fn our_fingerprint(&self) -> Option<String> {
        self.identity
            .as_ref()
            .map(|id| fingerprint_to_hex(&id.public.fingerprint()))
    }

    /// Returns our prekey bundle for sharing with others
    pub fn our_prekey_bundle(&self) -> Option<PreKeyBundle> {
        match (&self.identity, &self.prekey_generator) {
            (Some(identity), Some(generator)) => Some(generator.create_bundle(identity, true)),
            _ => None,
        }
    }

    /// Returns our prekey bundle as a serialized string (base64)
    pub fn our_prekey_bundle_encoded(&self) -> Option<String> {
        self.our_prekey_bundle().and_then(|bundle| {
            bincode::serialize(&bundle)
                .ok()
                .map(|bytes| base64_encode(&bytes))
        })
    }

    /// Adds a contact with their prekey bundle
    pub fn add_contact(&mut self, name: String, prekey_bundle_encoded: &str) -> Result<String> {
        // Decode and deserialize the prekey bundle
        let bundle_bytes = base64_decode(prekey_bundle_encoded.trim())
            .map_err(|_| pqpgp::error::PqpgpError::chat("Invalid base64 encoding"))?;

        let bundle: PreKeyBundle = bincode::deserialize(&bundle_bytes)
            .map_err(|e| pqpgp::error::PqpgpError::chat(format!("Invalid prekey bundle: {}", e)))?;

        // Verify the bundle
        bundle.verify()?;

        // Extract fingerprint from the bundle
        let fingerprint = fingerprint_to_hex(&bundle.identity_key().fingerprint());

        // Check if contact already exists
        if self.contacts.contains_key(&fingerprint) {
            return Err(pqpgp::error::PqpgpError::chat("Contact already exists"));
        }

        let contact = StoredContact {
            fingerprint: fingerprint.clone(),
            name,
            prekey_bundle: Some(bundle_bytes),
            has_session: false,
        };

        self.contacts.insert(fingerprint.clone(), contact);
        Ok(fingerprint)
    }

    /// Returns all contacts
    pub fn contacts(&self) -> Vec<StoredContact> {
        self.contacts.values().cloned().collect()
    }

    /// Removes a contact and their session/messages
    pub fn remove_contact(&mut self, fingerprint: &str) {
        self.contacts.remove(fingerprint);
        self.sessions.remove(fingerprint);
        self.messages.remove(fingerprint);
    }

    /// Initiates a session with a contact
    pub fn initiate_session(&mut self, contact_fingerprint: &str) -> Result<()> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| pqpgp::error::PqpgpError::chat("No identity configured"))?;

        let contact = self
            .contacts
            .get(contact_fingerprint)
            .ok_or_else(|| pqpgp::error::PqpgpError::chat("Contact not found"))?;

        let bundle_bytes = contact
            .prekey_bundle
            .as_ref()
            .ok_or_else(|| pqpgp::error::PqpgpError::chat("Contact has no prekey bundle"))?;

        let bundle: PreKeyBundle = bincode::deserialize(bundle_bytes)
            .map_err(|e| pqpgp::error::PqpgpError::chat(format!("Invalid prekey bundle: {}", e)))?;

        // Verify the bundle
        bundle.verify()?;

        // Create the session
        let session = Session::initiate(identity, &bundle)?;

        let stored_session = StoredSession {
            session,
            contact_fingerprint: contact_fingerprint.to_string(),
            contact_name: contact.name.clone(),
        };

        self.sessions
            .insert(contact_fingerprint.to_string(), stored_session);

        // Update contact status
        if let Some(c) = self.contacts.get_mut(contact_fingerprint) {
            c.has_session = true;
        }

        info!("Initiated session with contact: {}", contact_fingerprint);
        Ok(())
    }

    /// Receives an initial message and establishes a session
    #[allow(dead_code)]
    pub fn receive_initial_message(
        &mut self,
        encrypted_message: &EncryptedChatMessage,
    ) -> Result<(String, String)> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| pqpgp::error::PqpgpError::chat("No identity configured"))?;

        let prekey_generator = self
            .prekey_generator
            .as_mut()
            .ok_or_else(|| pqpgp::error::PqpgpError::chat("No prekey generator"))?;

        // Receive the initial message
        let (session, plaintext) =
            Session::receive_initial(identity, prekey_generator, encrypted_message)?;

        // Get the sender's fingerprint from the session (convert to hex)
        let sender_fingerprint = fingerprint_to_hex(&session.peer_identity().fingerprint());

        // Create stored session
        let contact_name = self
            .contacts
            .get(&sender_fingerprint)
            .map(|c| c.name.clone())
            .unwrap_or_else(|| "Unknown".to_string());

        let stored_session = StoredSession {
            session,
            contact_fingerprint: sender_fingerprint.clone(),
            contact_name,
        };

        self.sessions
            .insert(sender_fingerprint.clone(), stored_session);

        // Update contact status
        if let Some(c) = self.contacts.get_mut(&sender_fingerprint) {
            c.has_session = true;
        }

        let message_text = String::from_utf8(plaintext)
            .map_err(|_| pqpgp::error::PqpgpError::chat("Invalid UTF-8 in message"))?;

        info!("Received initial message from: {}", sender_fingerprint);
        Ok((sender_fingerprint, message_text))
    }

    /// Encrypts and sends a message to a contact
    pub fn send_message(
        &mut self,
        contact_fingerprint: &str,
        message: &str,
    ) -> Result<EncryptedChatMessage> {
        // Get or create session
        if !self.sessions.contains_key(contact_fingerprint) {
            self.initiate_session(contact_fingerprint)?;
        }

        let stored_session = self
            .sessions
            .get_mut(contact_fingerprint)
            .ok_or_else(|| pqpgp::error::PqpgpError::chat("Failed to get session"))?;

        // Encrypt the message
        let encrypted = stored_session.session.encrypt(message.as_bytes())?;

        // Store in message history
        let timestamp = chrono::Local::now().format("%H:%M").to_string();
        let stored_msg = StoredMessage {
            content: message.to_string(),
            timestamp,
            is_outgoing: true,
        };

        self.messages
            .entry(contact_fingerprint.to_string())
            .or_default()
            .push(stored_msg);

        info!("Sent encrypted message to: {}", contact_fingerprint);
        Ok(encrypted)
    }

    /// Decrypts a received message
    pub fn receive_message(
        &mut self,
        contact_fingerprint: &str,
        encrypted: &EncryptedChatMessage,
    ) -> Result<String> {
        // Check if this is an initial message
        if encrypted.is_initial {
            let (sender, message) = self.receive_initial_message(encrypted)?;
            // Store in message history
            let timestamp = chrono::Local::now().format("%H:%M").to_string();
            let stored_msg = StoredMessage {
                content: message.clone(),
                timestamp,
                is_outgoing: false,
            };
            self.messages.entry(sender).or_default().push(stored_msg);
            return Ok(message);
        }

        let stored_session = self
            .sessions
            .get_mut(contact_fingerprint)
            .ok_or_else(|| pqpgp::error::PqpgpError::chat("No session with this contact"))?;

        // Decrypt the message
        let plaintext = stored_session.session.decrypt(encrypted)?;

        let message = String::from_utf8(plaintext)
            .map_err(|_| pqpgp::error::PqpgpError::chat("Invalid UTF-8 in message"))?;

        // Store in message history
        let timestamp = chrono::Local::now().format("%H:%M").to_string();
        let stored_msg = StoredMessage {
            content: message.clone(),
            timestamp,
            is_outgoing: false,
        };

        self.messages
            .entry(contact_fingerprint.to_string())
            .or_default()
            .push(stored_msg);

        info!("Received encrypted message from: {}", contact_fingerprint);
        Ok(message)
    }

    /// Returns message history for a contact
    pub fn get_messages(&self, contact_fingerprint: &str) -> Vec<StoredMessage> {
        self.messages
            .get(contact_fingerprint)
            .cloned()
            .unwrap_or_default()
    }

    /// Returns whether we have an active session with a contact
    #[allow(dead_code)]
    pub fn has_session(&self, contact_fingerprint: &str) -> bool {
        self.sessions.contains_key(contact_fingerprint)
    }

    // === Serialization methods for persistent storage ===

    /// Serializes the identity key pair to bytes
    pub fn identity_bytes(&self) -> Result<Option<Vec<u8>>> {
        match &self.identity {
            Some(identity) => {
                let bytes = bincode::serialize(identity).map_err(|e| {
                    pqpgp::error::PqpgpError::serialization(format!(
                        "Failed to serialize identity: {}",
                        e
                    ))
                })?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }

    /// Serializes the prekey generator to bytes
    pub fn prekey_generator_bytes(&self) -> Result<Option<Vec<u8>>> {
        match &self.prekey_generator {
            Some(generator) => {
                let bytes = bincode::serialize(generator).map_err(|e| {
                    pqpgp::error::PqpgpError::serialization(format!(
                        "Failed to serialize prekey generator: {}",
                        e
                    ))
                })?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }

    /// Serializes all sessions to bytes (keyed by fingerprint)
    pub fn sessions_bytes(&self) -> Result<HashMap<String, Vec<u8>>> {
        let mut result = HashMap::new();
        for (fingerprint, stored_session) in &self.sessions {
            let bytes = bincode::serialize(&stored_session.session).map_err(|e| {
                pqpgp::error::PqpgpError::serialization(format!(
                    "Failed to serialize session: {}",
                    e
                ))
            })?;
            result.insert(fingerprint.clone(), bytes);
        }
        Ok(result)
    }

    /// Returns a reference to the contacts map
    pub fn contacts_map(&self) -> &HashMap<String, StoredContact> {
        &self.contacts
    }

    /// Returns a reference to the messages map
    pub fn messages_map(&self) -> &HashMap<String, Vec<StoredMessage>> {
        &self.messages
    }

    /// Reconstructs a ChatState from serialized components
    pub fn from_serializable(
        identity_bytes: Option<Vec<u8>>,
        prekey_generator_bytes: Option<Vec<u8>>,
        sessions_bytes: HashMap<String, Vec<u8>>,
        contacts: HashMap<String, StoredContact>,
        messages: HashMap<String, Vec<StoredMessage>>,
    ) -> Result<Self> {
        // Deserialize identity
        let identity = match identity_bytes {
            Some(bytes) => Some(bincode::deserialize(&bytes).map_err(|e| {
                pqpgp::error::PqpgpError::serialization(format!(
                    "Failed to deserialize identity: {}",
                    e
                ))
            })?),
            None => None,
        };

        // Deserialize prekey generator
        let prekey_generator = match prekey_generator_bytes {
            Some(bytes) => Some(bincode::deserialize(&bytes).map_err(|e| {
                pqpgp::error::PqpgpError::serialization(format!(
                    "Failed to deserialize prekey generator: {}",
                    e
                ))
            })?),
            None => None,
        };

        // Deserialize sessions
        let mut sessions = HashMap::new();
        for (fingerprint, bytes) in sessions_bytes {
            let session: Session = bincode::deserialize(&bytes).map_err(|e| {
                pqpgp::error::PqpgpError::serialization(format!(
                    "Failed to deserialize session: {}",
                    e
                ))
            })?;

            // Get contact name from contacts map
            let contact_name = contacts
                .get(&fingerprint)
                .map(|c| c.name.clone())
                .unwrap_or_else(|| "Unknown".to_string());

            sessions.insert(
                fingerprint.clone(),
                StoredSession {
                    session,
                    contact_fingerprint: fingerprint,
                    contact_name,
                },
            );
        }

        Ok(Self {
            identity,
            prekey_generator,
            sessions,
            contacts,
            messages,
            password: None, // Password is set separately after loading
        })
    }
}

/// Thread-safe wrapper for ChatState (unused, kept for reference)
#[allow(dead_code)]
pub type SharedChatState = Arc<RwLock<ChatState>>;

/// Multi-user chat state manager - stores separate ChatState per session
pub struct ChatStateManager {
    states: HashMap<String, ChatState>,
}

impl Default for ChatStateManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ChatStateManager {
    /// Creates a new chat state manager
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
        }
    }

    /// Gets or creates a ChatState for the given session ID
    pub fn get_or_create(&mut self, session_id: &str) -> &mut ChatState {
        self.states.entry(session_id.to_string()).or_default()
    }

    /// Gets a ChatState for the given session ID (read-only)
    pub fn get(&self, session_id: &str) -> Option<&ChatState> {
        self.states.get(session_id)
    }

    /// Sets a ChatState for the given session ID (replacing any existing state)
    pub fn set(&mut self, session_id: &str, state: ChatState) {
        self.states.insert(session_id.to_string(), state);
    }

    /// Removes the ChatState for the given session ID
    pub fn remove(&mut self, session_id: &str) {
        self.states.remove(session_id);
    }
}

/// Thread-safe wrapper for ChatStateManager
pub type SharedChatStateManager = Arc<RwLock<ChatStateManager>>;

/// Creates a new shared chat state manager
pub fn create_shared_state_manager() -> SharedChatStateManager {
    Arc::new(RwLock::new(ChatStateManager::new()))
}

// Base64 encoding/decoding helpers
fn base64_encode(data: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(data)
}

fn base64_decode(data: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.decode(data)
}
