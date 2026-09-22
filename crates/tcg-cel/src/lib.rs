//! The TCG Canonical Event Log (CEL) v1.1: its information model, the
//! CEL-CBOR and CEL-JSON encodings, replay into registers, and ingest from
//! the native logs confidential VMs produce.
//!
//! - [`Record`] is `TPMS_CEL_EVENT`: a record number counted per index, a
//!   PCR or NV index, a digest per bank, and typed content (Table 2), with
//!   private content types taken through the CDDL's extension socket as
//!   [`ContentType`] registrations.
//! - [`decode_cbor`] and [`encode_cbor`] read and write the CDDL's log, an
//!   array of records, in deterministic CBOR (RFC 8949 section 4.2.1);
//!   [`decode_cbor_sequence`] reads records written back to back.
//!   [`decode_json`] and [`encode_json`] are the JSON encoding. Decoders are
//!   strict: non-deterministic CBOR, repeated or unknown JSON members, out of
//!   range values and broken record numbering are errors.
//! - [`replay`] reproduces register values in one bank.
//! - [`tcg2`] reads TCG2 crypto-agile logs (a TPM firmware log, the TDX
//!   CCEL), [`aael`] the Confidential Containers attestation-agent entries
//!   such a CCEL carries, and [`dstack`] dstack's JSON event log.
//!
//! Replay authenticates digests. Content is bound to its digest only where
//! its content type says how: [`aael::entry`], [`dstack::runtime_event`], and
//! the caller's own extension types.
//!
//! Not covered: the CEL-TLV encoding, replay in the SHA-1, SM3 and SHA-3
//! banks (those digests parse and encode), digest rules for the IMA and
//! systemd content types, and the line-based AAEL of guest-components
//! releases before v0.15.0.

#![forbid(unsafe_code)]

mod alg;
mod cbor;
mod cel_cbor;
mod cel_json;
mod error;
mod json;
mod model;
mod pcclient;
mod replay;

pub mod aael;
pub mod dstack;
pub mod tcg2;

pub use alg::HashAlg;
pub use cel_cbor::{decode_cbor, decode_cbor_sequence, encode_cbor, encode_cbor_record};
pub use cel_json::{decode_json, encode_json};
pub use error::{Error, Result};
pub use model::{
    renumber, CelMgmt, Content, ContentType, Digest, EventType, Field, Index, Record, Schema,
    StateTrans, Value, CONTENT_CEL, CONTENT_IMA_TEMPLATE, CONTENT_IMA_TLV, CONTENT_PCCLIENT_STD,
    CONTENT_SYSTEMD, MAX_BYTES, MAX_DIGESTS, MAX_DIGEST_LEN, MAX_RECORDS,
};
pub use pcclient::{event_type_code, event_type_name, EV_EVENT_TAG, EV_NO_ACTION};
pub use replay::{pc_client_initial, replay, Register, Replay, ReplayOptions};
