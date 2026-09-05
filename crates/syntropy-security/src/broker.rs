use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::keystore::{KeyStore, KeyStoreError};

#[derive(Error, Debug)]
pub enum BrokerError {
    #[error("Credential handle not found: {0}")]
    HandleNotFound(String),

    #[error("Secret for handle '{handle}' (key '{key}') not found in keystore")]
    SecretNotFound { handle: String, key: String },

    #[error("Action '{action}' is not allowed for handle '{handle}'")]
    ActionNotAllowed { handle: String, action: String },

    #[error("Target host '{host}' is not allowed for handle '{handle}'")]
    HostNotAllowed { handle: String, host: String },

    #[error("Keystore error: {0}")]
    KeyStore(#[from] KeyStoreError),

    #[error("Invalid encoding: {0}")]
    InvalidEncoding(String),

    #[error("Lock error: {0}")]
    LockError(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BrokerAction {
    InjectHeader,
    InjectEnv,
    InjectTemplate,
    SignPayload,
    All,
}

impl BrokerAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            BrokerAction::InjectHeader => "InjectHeader",
            BrokerAction::InjectEnv => "InjectEnv",
            BrokerAction::InjectTemplate => "InjectTemplate",
            BrokerAction::SignPayload => "SignPayload",
            BrokerAction::All => "All",
        }
    }
}

/// Metadata and restrictions associated with a credential handle.
#[derive(Debug, Clone)]
pub struct CredentialBinding {
    pub handle: String,
    pub keystore_key: String,
    pub allowed_actions: HashSet<BrokerAction>,
    pub allowed_hosts: Option<Vec<String>>,
}

impl CredentialBinding {
    pub fn new(handle: impl Into<String>, keystore_key: impl Into<String>, actions: &[BrokerAction]) -> Self {
        let mut allowed = HashSet::new();
        for action in actions {
            allowed.insert(*action);
        }
        Self {
            handle: handle.into(),
            keystore_key: keystore_key.into(),
            allowed_actions: allowed,
            allowed_hosts: None,
        }
    }

    pub fn with_hosts(mut self, hosts: Vec<String>) -> Self {
        self.allowed_hosts = Some(hosts);
        self
    }

    pub fn is_action_allowed(&self, action: BrokerAction) -> bool {
        self.allowed_actions.contains(&BrokerAction::All) || self.allowed_actions.contains(&action)
    }

    pub fn is_host_allowed(&self, host: &str) -> bool {
        match &self.allowed_hosts {
            None => true,
            Some(hosts) => hosts.iter().any(|h| h.eq_ignore_ascii_case(host)),
        }
    }
}

/// CredentialBroker implements the inverted token broker pattern.
///
/// Cloud agents or LLM processes only reference abstract `credential_handle` strings.
/// The broker performs cryptographic signing, token injection into outbound requests,
/// and log sanitization locally so that raw credentials are never transmitted to or
/// inspected by cloud coordinators.
pub struct CredentialBroker {
    keystore: Arc<dyn KeyStore>,
    bindings: Arc<RwLock<HashMap<String, CredentialBinding>>>,
}

impl CredentialBroker {
    /// Create a new CredentialBroker backed by the given KeyStore.
    pub fn new(keystore: Arc<dyn KeyStore>) -> Self {
        Self {
            keystore,
            bindings: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a credential handle with permitted actions.
    pub fn register_handle(
        &self,
        handle: impl Into<String>,
        keystore_key: impl Into<String>,
        allowed_actions: &[BrokerAction],
    ) -> Result<(), BrokerError> {
        let binding = CredentialBinding::new(handle, keystore_key, allowed_actions);
        let mut map = self.bindings.write().map_err(|_| BrokerError::LockError("Failed to acquire write lock".into()))?;
        map.insert(binding.handle.clone(), binding);
        Ok(())
    }

    /// Register a credential handle with permitted actions and allowed destination hosts.
    pub fn register_handle_with_hosts(
        &self,
        handle: impl Into<String>,
        keystore_key: impl Into<String>,
        allowed_actions: &[BrokerAction],
        allowed_hosts: Vec<String>,
    ) -> Result<(), BrokerError> {
        let binding = CredentialBinding::new(handle, keystore_key, allowed_actions).with_hosts(allowed_hosts);
        let mut map = self.bindings.write().map_err(|_| BrokerError::LockError("Failed to acquire write lock".into()))?;
        map.insert(binding.handle.clone(), binding);
        Ok(())
    }

    /// Retrieve the secret associated with a handle after verifying permitted actions.
    fn resolve_secret(&self, handle: &str, action: BrokerAction) -> Result<(CredentialBinding, Vec<u8>), BrokerError> {
        let binding = {
            let map = self.bindings.read().map_err(|_| BrokerError::LockError("Failed to acquire read lock".into()))?;
            map.get(handle)
                .cloned()
                .ok_or_else(|| BrokerError::HandleNotFound(handle.to_string()))?
        };

        if !binding.is_action_allowed(action) {
            return Err(BrokerError::ActionNotAllowed {
                handle: handle.to_string(),
                action: action.as_str().to_string(),
            });
        }

        let secret = self
            .keystore
            .get(&binding.keystore_key)?
            .ok_or_else(|| BrokerError::SecretNotFound {
                handle: handle.to_string(),
                key: binding.keystore_key.clone(),
            })?;

        Ok((binding, secret))
    }

    /// Sign a payload using HMAC-SHA256 with the secret corresponding to the handle.
    ///
    /// The cloud agent requests a signature using only the handle; the private key never leaves the broker.
    pub fn sign_payload(&self, handle: &str, payload: &[u8]) -> Result<String, BrokerError> {
        let (_binding, secret) = self.resolve_secret(handle, BrokerAction::SignPayload)?;
        let mac = compute_hmac_sha256(&secret, payload);
        Ok(hex::encode(mac))
    }

    /// Verify an HMAC-SHA256 signature for a payload using the handle's secret.
    pub fn verify_signature(&self, handle: &str, payload: &[u8], signature_hex: &str) -> Result<bool, BrokerError> {
        let expected = self.sign_payload(handle, payload)?;
        Ok(expected.eq_ignore_ascii_case(signature_hex))
    }

    /// Inject an authorization header into a headers map without returning the secret.
    ///
    /// E.g. `inject_header("gh-token", &mut headers, "Authorization", Some("Bearer "), Some("api.github.com"))`
    pub fn inject_header(
        &self,
        handle: &str,
        headers: &mut HashMap<String, String>,
        header_name: &str,
        prefix: Option<&str>,
        target_host: Option<&str>,
    ) -> Result<(), BrokerError> {
        let (binding, secret) = self.resolve_secret(handle, BrokerAction::InjectHeader)?;

        if let Some(host) = target_host {
            if !binding.is_host_allowed(host) {
                return Err(BrokerError::HostNotAllowed {
                    handle: handle.to_string(),
                    host: host.to_string(),
                });
            }
        }

        let secret_str = String::from_utf8(secret)
            .map_err(|e| BrokerError::InvalidEncoding(format!("Secret is not valid UTF-8: {e}")))?;

        let value = match prefix {
            Some(p) => format!("{p}{secret_str}"),
            None => secret_str,
        };

        headers.insert(header_name.to_string(), value);
        Ok(())
    }

    /// Inject credentials into an environment variable map for a local subprocess.
    pub fn inject_env(
        &self,
        handle: &str,
        env_var: &str,
        env: &mut HashMap<String, String>,
    ) -> Result<(), BrokerError> {
        let (_binding, secret) = self.resolve_secret(handle, BrokerAction::InjectEnv)?;
        let secret_str = String::from_utf8(secret)
            .map_err(|e| BrokerError::InvalidEncoding(format!("Secret is not valid UTF-8: {e}")))?;

        env.insert(env_var.to_string(), secret_str);
        Ok(())
    }

    /// Inject secrets into template string placeholders like `{{credential:<handle>}}` or `{{<handle>}}`.
    pub fn inject_template(&self, template: &str) -> Result<String, BrokerError> {
        let bindings = {
            let map = self.bindings.read().map_err(|_| BrokerError::LockError("Failed to acquire read lock".into()))?;
            map.clone()
        };

        let mut output = template.to_string();

        for (handle, binding) in &bindings {
            let p1 = format!("{{{{credential:{handle}}}}}");
            let p2 = format!("{{{{{handle}}}}}");

            if output.contains(&p1) || output.contains(&p2) {
                if !binding.is_action_allowed(BrokerAction::InjectTemplate) {
                    return Err(BrokerError::ActionNotAllowed {
                        handle: handle.clone(),
                        action: BrokerAction::InjectTemplate.as_str().to_string(),
                    });
                }

                let secret = self
                    .keystore
                    .get(&binding.keystore_key)?
                    .ok_or_else(|| BrokerError::SecretNotFound {
                        handle: handle.clone(),
                        key: binding.keystore_key.clone(),
                    })?;

                let secret_str = String::from_utf8(secret)
                    .map_err(|e| BrokerError::InvalidEncoding(format!("Secret for {handle} is not UTF-8: {e}")))?;

                output = output.replace(&p1, &secret_str);
                output = output.replace(&p2, &secret_str);
            }
        }

        Ok(output)
    }

    /// Redact any known registered secrets from output logs, terminal streams, or error messages
    /// before they are dispatched to remote agents.
    pub fn sanitize_output(&self, text: &str) -> String {
        let bindings = match self.bindings.read() {
            Ok(b) => b.clone(),
            Err(_) => return text.to_string(),
        };

        let mut sanitized = text.to_string();

        for (handle, binding) in bindings {
            if let Ok(Some(secret)) = self.keystore.get(&binding.keystore_key) {
                if let Ok(secret_str) = String::from_utf8(secret) {
                    if !secret_str.is_empty() && secret_str.len() >= 4 {
                        let replacement = format!("[REDACTED:{handle}]");
                        sanitized = sanitized.replace(&secret_str, &replacement);
                    }
                }
            }
        }

        sanitized
    }
}

/// Compute standard RFC 2104 HMAC-SHA256.
pub fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut actual_key = [0u8; 64];

    if key.len() > 64 {
        let mut hasher = Sha256::new();
        hasher.update(key);
        let key_hash = hasher.finalize();
        actual_key[..32].copy_from_slice(&key_hash);
    } else {
        actual_key[..key.len()].copy_from_slice(key);
    }

    let mut o_key_pad = [0u8; 64];
    let mut i_key_pad = [0u8; 64];

    for i in 0..64 {
        o_key_pad[i] = actual_key[i] ^ 0x5c;
        i_key_pad[i] = actual_key[i] ^ 0x36;
    }

    let mut inner = Sha256::new();
    inner.update(i_key_pad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(o_key_pad);
    outer.update(inner_hash);
    let outer_hash = outer.finalize();

    let mut mac = [0u8; 32];
    mac.copy_from_slice(&outer_hash);
    mac
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::InMemoryKeyStore;

    #[test]
    fn test_inverted_broker_signing() {
        let keystore = Arc::new(InMemoryKeyStore::new());
        keystore.set_str("keys/signing_key", "super_secret_signing_key_42").unwrap();

        let broker = CredentialBroker::new(keystore);
        broker
            .register_handle("signer-1", "keys/signing_key", &[BrokerAction::SignPayload])
            .unwrap();

        let payload = b"cloud-agent-action-payload";
        let sig = broker.sign_payload("signer-1", payload).unwrap();
        assert!(!sig.is_empty());

        let valid = broker.verify_signature("signer-1", payload, &sig).unwrap();
        assert!(valid);

        let invalid = broker.verify_signature("signer-1", b"tampered-payload", &sig).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_broker_inject_header_and_host_validation() {
        let keystore = Arc::new(InMemoryKeyStore::new());
        keystore.set_str("creds/github", "ghp_tok12345").unwrap();

        let broker = CredentialBroker::new(keystore);
        broker
            .register_handle_with_hosts(
                "gh-token",
                "creds/github",
                &[BrokerAction::InjectHeader],
                vec!["api.github.com".to_string()],
            )
            .unwrap();

        let mut headers = HashMap::new();

        // Allowed host
        broker
            .inject_header("gh-token", &mut headers, "Authorization", Some("Bearer "), Some("api.github.com"))
            .unwrap();
        assert_eq!(headers.get("Authorization"), Some(&"Bearer ghp_tok12345".to_string()));

        // Disallowed host must fail
        let err = broker.inject_header(
            "gh-token",
            &mut headers,
            "Authorization",
            Some("Bearer "),
            Some("malicious.site.com"),
        );
        assert!(err.is_err());
    }

    #[test]
    fn test_broker_template_injection_and_sanitization() {
        let keystore = Arc::new(InMemoryKeyStore::new());
        keystore.set_str("tokens/slack", "xoxb-9988776655").unwrap();

        let broker = CredentialBroker::new(keystore);
        broker
            .register_handle("slack-bot", "tokens/slack", &[BrokerAction::InjectTemplate])
            .unwrap();

        let template = "curl -H 'Authorization: Bearer {{credential:slack-bot}}' https://slack.com";
        let injected = broker.inject_template(template).unwrap();
        assert_eq!(injected, "curl -H 'Authorization: Bearer xoxb-9988776655' https://slack.com");

        // Sanitization redacts secret from text
        let log_output = "Error: Failed response with auth token xoxb-9988776655";
        let redacted = broker.sanitize_output(log_output);
        assert_eq!(redacted, "Error: Failed response with auth token [REDACTED:slack-bot]");
    }
}
