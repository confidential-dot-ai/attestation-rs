/// Every failure names where in the input it happened.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Malformed or non-deterministic CBOR, or a CBOR record that breaks the CEL CDDL.
    #[error("CEL-CBOR at byte {offset}: {reason}")]
    Cbor { offset: usize, reason: String },
    /// Malformed JSON, or a JSON record that breaks the CEL CDDL.
    #[error("CEL-JSON: {0}")]
    Json(String),
    /// A record that is well formed but violates the information model.
    #[error("record {position}: {reason}")]
    Record { position: usize, reason: String },
    /// A TCG2 (TCG_PCR_EVENT2) log that cannot be parsed whole.
    #[error("TCG2 log at byte {offset}: {reason}")]
    Tcg2 { offset: usize, reason: String },
    /// A dstack event log that cannot be ingested.
    #[error("dstack event {position}: {reason}")]
    Dstack { position: usize, reason: String },
    /// A record whose content does not reproduce its digest.
    #[error("record {position}: {reason}")]
    Digest { position: usize, reason: String },
    /// Replay cannot proceed in the requested bank.
    #[error("replay: {0}")]
    Replay(String),
    /// An argument the API cannot accept, such as a malformed content type registration.
    #[error("{0}")]
    Usage(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn record(position: usize, reason: impl Into<String>) -> Error {
    Error::Record {
        position,
        reason: reason.into(),
    }
}
