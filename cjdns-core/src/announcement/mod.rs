//! Announcement message
//! `Ann` or `ann` are shorthands for `Announcement` and `announcement`.

pub use models::*;
pub use serialized_ann::serialized_data::*;

mod serialized_ann;
mod models;
mod errors;


// todo
// 1. consider using EncodingScheme, not Vec<EncodingSchemeForm>
// 2. Having Announcement node_pub_key and node_ip as parts of header
// 3. Difference between Entity::Version and AnnouncementHeader.ver?
// 4. Resolve pub/mod/pub use/pub mod problems
// 5. parse_header - seems a lot of copy/paste. May be implement own iterator, that iterates over chunks size N, that after each next are divided by D (64-32-16)
// 6. is there always
