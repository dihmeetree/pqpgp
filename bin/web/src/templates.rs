//! Askama templates for PQPGP web interface

use askama::Template;

/// Key information for display
#[derive(Debug)]
pub struct KeyInfo {
    pub key_id: String,
    pub algorithm: String,
    pub user_ids: Vec<String>,
    pub has_private_key: bool,
    pub is_password_protected: bool,
}

/// Recipient information for encryption
#[derive(Debug)]
pub struct RecipientInfo {
    pub key_id: String,
    pub user_id: String,
}

/// Signing key information
#[derive(Debug)]
pub struct SigningKeyInfo {
    pub key_id: String,
    pub user_id: String,
}

/// Index page template
#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate {
    pub active_page: String,
}

/// Keys listing template
#[derive(Template)]
#[template(path = "keys.html")]
pub struct KeysTemplate {
    pub keys: Vec<KeyInfo>,
    pub active_page: String,
    pub result: Option<String>,
    pub error: Option<String>,
    pub has_result: bool,
    pub has_error: bool,
    pub csrf_token: String,
}

/// Encryption template
#[derive(Template)]
#[template(path = "encrypt.html")]
pub struct EncryptTemplate {
    pub recipients: Vec<RecipientInfo>,
    pub signing_keys: Vec<SigningKeyInfo>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub has_result: bool,
    pub has_error: bool,
    pub active_page: String,
    pub csrf_token: String,
}

/// Decryption template
#[derive(Template)]
#[template(path = "decrypt.html")]
pub struct DecryptTemplate {
    pub result: Option<String>,
    pub error: Option<String>,
    pub has_result: bool,
    pub has_error: bool,
    pub active_page: String,
    pub csrf_token: String,
}

/// Signing template
#[derive(Template)]
#[template(path = "sign.html")]
pub struct SignTemplate {
    pub signing_keys: Vec<SigningKeyInfo>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub has_result: bool,
    pub has_error: bool,
    pub active_page: String,
    pub csrf_token: String,
}

/// Verification template
#[derive(Template)]
#[template(path = "verify.html")]
pub struct VerifyTemplate {
    pub is_valid: Option<bool>,
    pub error: Option<String>,
    pub has_result: bool,
    pub has_error: bool,
    pub active_page: String,
    pub csrf_token: String,
}

/// View public key template
#[derive(Template)]
#[template(path = "view_public_key.html")]
pub struct ViewPublicKeyTemplate {
    pub key_id: String,
    pub algorithm: String,
    pub user_ids: Vec<String>,
    pub public_key_armored: String,
    pub active_page: String,
}

/// File encryption/decryption template
#[derive(Template)]
#[template(path = "files.html")]
pub struct FilesTemplate {
    pub recipients: Vec<RecipientInfo>,
    pub signing_keys: Vec<SigningKeyInfo>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub has_result: bool,
    pub has_error: bool,
    pub signature_found: bool,
    pub signature_armored: Option<String>,
    pub signer_info: Option<String>,
    pub signature_verified: Option<bool>,
    pub verification_message: Option<String>,
    pub active_page: String,
    pub csrf_token: String,
}

/// Chat contact information
#[derive(Debug, Clone)]
pub struct ChatContact {
    pub fingerprint: String,
    pub name: String,
    pub has_session: bool,
    pub is_selected: bool,
    pub initial: char,
}

/// Chat message for display
#[derive(Debug, Clone)]
pub struct ChatMessageDisplay {
    pub content: String,
    pub timestamp: String,
    pub is_outgoing: bool,
}

/// Chat template
#[derive(Template)]
#[template(path = "chat.html")]
pub struct ChatTemplate {
    pub active_page: String,
    pub csrf_token: String,
    pub contacts: Vec<ChatContact>,
    pub selected_contact: Option<String>,
    pub selected_contact_name: Option<String>,
    pub messages: Vec<ChatMessageDisplay>,
    pub our_identity: Option<String>,
    pub our_prekey_bundle: Option<String>,
    pub saved_identities: Vec<String>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub has_result: bool,
    pub has_error: bool,
}
