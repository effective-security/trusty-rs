//! Error type shared by the provider traits, registry, and config loading.

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Public error type for configuration, registry, and provider failures.
///
/// Provider crates (PKCS#11, AWS KMS, ...) convert their own SDK-specific
/// errors into [`Error::Provider`] at their boundary rather than adding a
/// variant here, so this crate never has to depend on any provider SDK.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Invalid PKCS#11 token URI.
    #[error("invalid URI")]
    InvalidUri,

    /// Invalid PKCS#11 private-key URI.
    #[error("invalid URI for private key object")]
    InvalidPrivateKeyUri,

    /// A provider kind already has a registered loader.
    #[error("already registered: {kind}")]
    AlreadyRegistered {
        /// Provider kind that collided.
        kind: String,
    },

    /// A provider kind is not in the loader registry.
    #[error("not registered: {kind}")]
    NotRegistered {
        /// Provider kind that was missing.
        kind: String,
    },

    /// Config named a provider kind with no loader.
    #[error("provider not registered: {kind}")]
    ProviderNotRegistered {
        /// Provider kind from token config.
        kind: String,
    },

    /// No provider matched manufacturer+model in a [`Crypto`](crate::provider::Crypto) set.
    #[error("provider for {manufacturer:?} and model {model:?} not found")]
    ProviderNotFound {
        /// Requested manufacturer.
        manufacturer: String,
        /// Requested model.
        model: String,
    },

    /// Legacy OpenSSL encrypted PEM (`Proc-Type: ENCRYPTED`) is not supported.
    #[error("private key is encrypted (legacy Proc-Type ENCRYPTED PEM is not supported)")]
    EncryptedPemUnsupported,

    /// PEM decode found no private-key block.
    #[error("unable to decode private key")]
    UnableToDecodePrivateKey,

    /// DER private key could not be parsed as PKCS#8 / PKCS#1 / SEC1.
    #[error("failed to parse key")]
    FailedToParseKey,

    /// GCM ciphertext shorter than the nonce.
    #[error("ciphertext too short")]
    CiphertextTooShort,

    /// AES key length is not 16, 24, or 32 bytes.
    #[error("invalid AES key length: {0}")]
    InvalidAesKeyLength(usize),

    /// AES-GCM encrypt failed.
    #[error("GCM encrypt failed")]
    GcmEncryptFailure,

    /// AES-GCM authentication failed (tampered ciphertext or wrong key).
    #[error("GCM authentication failed")]
    GcmAuthFailure,

    /// Named curve is not supported by this provider path.
    #[error("unsupported elliptic curve: {0}")]
    UnsupportedCurve(String),

    /// Key ID was not found in the provider.
    #[error("key not found: {0}")]
    KeyNotFound(String),

    /// Operation is not supported for the given key type.
    #[error("unsupported key type")]
    UnsupportedKeyType,

    /// Signing failed.
    #[error("sign failed: {0}")]
    SignFailure(String),

    /// Configuration parse or validation error.
    #[error("config: {0}")]
    Config(String),

    /// Filesystem I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// A provider-specific failure, converted from that provider crate's own
    /// SDK error type at the provider crate's boundary.
    #[error("provider error: {0}")]
    Provider(String),

    /// Operation is not implemented yet (used by stub providers).
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),

    /// Annotated wrapper preserving the source error.
    #[error("{context}: {source}")]
    Context {
        /// Human-readable context.
        context: String,
        /// Nested error.
        #[source]
        source: Box<Error>,
    },
}

impl Error {
    /// Wrap this error with additional context.
    #[must_use]
    pub fn context(self, context: impl Into<String>) -> Self {
        Self::Context { context: context.into(), source: Box::new(self) }
    }

    /// Unwrap any [`Error::Context`] layers, returning the innermost error.
    ///
    /// `.context()` may or may not have been applied along a given call path,
    /// so the same underlying failure can otherwise surface as either its own
    /// variant or `Error::Context { source, .. }` depending on how it was
    /// reached. Match on `root_cause()` instead of the error itself to avoid
    /// having to enumerate `SomeVariant | Error::Context { .. }` at every
    /// call site.
    #[must_use]
    pub fn root_cause(&self) -> &Self {
        let mut current = self;
        while let Self::Context { source, .. } = current {
            current = source;
        }
        current
    }
}
