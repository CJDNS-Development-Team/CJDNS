//! Announcement parsing utils

use std::fmt;

use cjdns_ann::{Announcement, Entity, LinkStateData, PeerData};
use cjdns_core::EncodingScheme;

pub(super) fn encoding_scheme_from_announcement(ann: &Announcement) -> Option<&EncodingScheme> {
    for e in ann.entities.iter() {
        if let Entity::EncodingScheme { scheme, .. } = e {
            return Some(scheme);
        }
    }
    None
}

pub(super) fn version_from_announcement(ann: &Announcement) -> Option<u16> {
    for e in ann.entities.iter() {
        if let Entity::NodeProtocolVersion(ver) = e {
            return Some(*ver);
        }
    }
    None
}

pub(super) fn peers_from_announcement(ann: &Announcement) -> impl Iterator<Item=&PeerData> {
    ann.entities
        .iter()
        .filter_map(|e| {
            match e {
                Entity::Peer(data) => Some(data),
                _ => None,
            }
        })
}

pub(super) fn link_states_from_announcement(ann: &Announcement) -> impl Iterator<Item=&LinkStateData> {
    ann.entities
        .iter()
        .filter_map(|e| {
            match e {
                Entity::LinkState(data) => Some(data),
                _ => None,
            }
        })
}

pub(super) fn ann_id(ann: &Announcement) -> impl fmt::Display {
    hex::encode(&ann.hash.0[0..8])
}

pub(super) fn is_entity_ephemeral(e: &Entity) -> bool {
    use Entity::*;
    match e {
        NodeProtocolVersion(_) | EncodingScheme { .. } | Peer(_) => false,
        LinkState(_) => true,
    }
}

pub(super) fn is_entity_replacement(old_e: &Entity, new_e: &Entity) -> bool {
    let old_type = std::mem::discriminant(old_e);
    let new_type = std::mem::discriminant(new_e);
    if old_type != new_type {
        return false;
    }
    if matches!(old_e, Entity::EncodingScheme{..}) || matches!(old_e, Entity::NodeProtocolVersion(_)) {
        return true;
    }
    if let (Entity::Peer(old_peer), Entity::Peer(new_peer)) = (old_e, new_e) {
        return old_peer.peer_num == new_peer.peer_num;
    }
    false
}