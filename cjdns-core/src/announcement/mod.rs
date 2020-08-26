//! Announcement message
//! `Ann` or `ann` are shorthands for `Announcement` and `announcement`.

pub use models::*;
pub use serialized_ann::serialized_data::*;

mod serialized_ann;
mod models;
mod errors;


// todo
// 1. Reformat Errors (because we have mix of inner announcement errors and errors from external crates) in serialized_ann module in the next way:
//   - all the functions except for pub should return Box<dyn std::error::Error> | Result<U, &'static str>
//   - but main pub functions (like `parser::parse`, `serialized_data::AnnouncementPacket::{parse, check}` should return original errors with .or() | map_err
// 2. refactoring and clean-ups (also tests)
