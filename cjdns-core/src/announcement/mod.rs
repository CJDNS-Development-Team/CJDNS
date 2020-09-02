//! Module for parsing cjdns route announcement messages.
//!
//! TODO rest of the README

pub use models::*;
pub use serialized_ann::serialized_data::*;

mod serialized_ann;
mod models;
mod errors;
