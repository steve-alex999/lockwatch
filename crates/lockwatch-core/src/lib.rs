//! lockwatch-core: the engine behind the `lockwatch` CLI.
//!
//! Pipeline: parse lockfile -> fetch tarballs (verify integrity, cache) ->
//! safe extract -> run rules -> score and report. The library never executes
//! code from the packages it scans; it only downloads, unpacks and reads files.

pub mod analysis;
pub mod cache;
pub mod context;
pub mod error;
pub mod extract;
pub mod integrity;
pub mod lockfile;
pub mod manifest;
pub mod registry;
pub mod rules;
pub mod time;

#[cfg(test)]
mod test_support;

pub use error::{CoreError, Result};
