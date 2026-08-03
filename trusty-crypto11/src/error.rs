//! Error types for the PKCS#11 adapter.

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Public error type for PKCS#11 adapter failures, I/O, and config errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// No token matched serial/label.
    #[error("crypto11: could not find PKCS#11 token")]
    TokenNotFound,

    /// No key matched the search criteria.
    #[error("crypto11: could not find PKCS#11 key")]
    KeyNotFound,

    /// Shared library could not be opened.
    #[error("crypto11: could not open PKCS#11 library: {path}")]
    CannotOpenPkcs11 {
        /// Path that failed to load.
        path: String,
    },

    /// Token RNG returned fewer bytes than requested.
    #[error("crypto11: cannot get random data from PKCS#11")]
    CannotGetRandomData,

    /// Key type is not RSA or ECDSA.
    #[error("crypto11: unrecognized key type")]
    UnsupportedKeyType,

    /// RSA public key fields are not usable.
    #[error("crypto11/rsa: malformed RSA key")]
    MalformedRsaKey,

    /// Unsupported RSA scheme/options (e.g. PSS Auto salt).
    #[error("crypto11/rsa: unsupported RSA option value")]
    UnsupportedRsaOptions,

    /// ASN.1/DER decode failure.
    #[error("crypto11: malformed DER message")]
    MalformedDer,

    /// PKCS#11 returned an empty or odd-length ECDSA signature.
    #[error("crypto11: malformed signature")]
    MalformedSignature,

    /// Named curve is not supported for export/use.
    #[error("crypto11/ecdsa: unsupported elliptic curve")]
    UnsupportedEllipticCurve,

    /// EC point bytes could not be parsed.
    #[error("crypto11/ecdsa: malformed elliptic curve point")]
    MalformedPoint,

    /// Library handle was already closed.
    #[error("crypto11: PKCS#11 library is closed")]
    Closed,

    /// Underlying cryptoki / PKCS#11 failure.
    #[error(transparent)]
    Pkcs11(#[from] cryptoki::error::Error),

    /// Configuration parse or validation error.
    #[error("config: {0}")]
    Config(String),

    /// Filesystem I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

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
    /// Wrap `self` with additional context.
    pub fn context(self, context: impl Into<String>) -> Self {
        Error::Context { context: context.into(), source: Box::new(self) }
    }
}

impl From<der::Error> for Error {
    fn from(_err: der::Error) -> Self {
        Error::MalformedDer
    }
}

impl From<spki::Error> for Error {
    fn from(err: spki::Error) -> Self {
        Error::Config(format!("spki: {err}"))
    }
}

impl From<rsa::Error> for Error {
    fn from(err: rsa::Error) -> Self {
        Error::Config(format!("rsa: {err}"))
    }
}

impl From<pem_rfc7468::Error> for Error {
    fn from(err: pem_rfc7468::Error) -> Self {
        Error::Config(format!("pem: {err}"))
    }
}
