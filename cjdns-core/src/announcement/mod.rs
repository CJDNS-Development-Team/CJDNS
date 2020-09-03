//! Module for parsing cjdns route announcement messages.
//!
//! TODO rest of the README

pub use serialized_ann::serialized_data::AnnouncementPacket;

pub mod models;
mod serialized_ann;
mod errors;
