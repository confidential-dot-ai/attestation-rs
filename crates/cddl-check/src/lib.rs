//! Validates JSON values against a CDDL module (RFC 8610), for checking the
//! CVM attestation profile's module (`schemas/cvm-profile-v1.cddl`) against
//! the JSON Schemas and the reference parser.
//!
//! The subset is the one the module uses, and nothing outside it is guessed
//! at: a construct the parser or validator does not implement is an error
//! when the module loads. Implemented:
//!
//! - rules with generic parameters; type choices; group choices (`//`);
//! - maps, with member keys, cuts (`^ =>` and `:`), occurrences and named or
//!   parenthesized groups as entries; arrays as ordered groups;
//! - literal integers and text, integer ranges, `~` over `#6.n(type)`;
//! - the prelude types `any`, `bool`, `true`, `false`, `null`, `nil`, `int`,
//!   `uint`, `nint`, `text`, `tstr`, `bytes`, `bstr`, `float`;
//! - the controls `.size`, `.regexp` (XSD regular expressions, anchored),
//!   `.lt`, `.le`, `.gt`, `.ge`, `.eq`, `.ne`, `.default` (RFC 8610),
//!   `.feature`, `.within`, `.and` (RFC 9165), `.b64u`, `.base10` (RFC 9741).
//!
//! JSON has no byte strings: `bytes` matches only what a `.b64u` control
//! decodes. Map members are matched in the order the module lists them, each
//! taking the object members its key matches; the module puts specific keys
//! before wildcards, and the loader refuses a map whose unbounded entry comes
//! before a literal key, where that order would matter.

mod parse;
mod validate;

pub use parse::Error;

use std::collections::BTreeMap;

/// A parsed module.
#[derive(Debug)]
pub struct Module {
    rules: BTreeMap<String, parse::Rule>,
}

impl Module {
    /// Parses a module and checks that every name resolves, every control is
    /// one this crate implements and every generic is called with its arity.
    pub fn parse(text: &str) -> Result<Module, Error> {
        let rules = parse::parse(text)?;
        let module = Module { rules };
        validate::check(&module)?;
        Ok(module)
    }

    /// Whether `value` matches the rule `root` with the given features
    /// enabled (RFC 9165 `.feature`; the profile's JSON encoding is `json`).
    pub fn validate(
        &self,
        root: &str,
        value: &serde_json::Value,
        features: &[&str],
    ) -> Result<bool, Error> {
        validate::validate(self, root, value, features)
    }
}

#[cfg(test)]
mod tests;
