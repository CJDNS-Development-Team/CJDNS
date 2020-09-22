//! Announce list

use std::collections::HashMap;

use cjdns_ann::AnnHash;

pub(crate) type AnnData = Vec<u8>;

pub(super) struct AnnList {
    ann_by_hash: HashMap<AnnHash, AnnData>,
    ann_hashes_ordered: Vec<AnnHash>,
}

impl AnnList {
    pub(super) fn new() -> Self {
        AnnList {
            ann_by_hash: HashMap::new(),
            ann_hashes_ordered: Vec::new(),
        }
    }

    pub(super) fn add(&mut self, hash: AnnHash, binary: AnnData) {
        self.ann_hashes_ordered.push(hash.clone());
        self.ann_by_hash.insert(hash, binary);
    }

    pub(super) fn remove(&mut self, hash: &AnnHash) {
        self.ann_hashes_ordered.retain(|h| h.bytes() != hash.bytes());
        self.ann_by_hash.remove(hash);
    }

    pub(super) fn hash_list(&self) -> &[AnnHash] {
        &self.ann_hashes_ordered
    }

    pub(super) fn hash_known(&self, hash: &AnnHash) -> bool {
        self.ann_by_hash.contains_key(hash)
    }

    pub(super) fn get(&self, hash: &AnnHash) -> Option<AnnData> {
        self.ann_by_hash.get(hash).cloned()
    }

    pub(super) fn info(&self) -> (usize, usize) {
        let hash_count = self.ann_hashes_ordered.len();
        let ann_count = self.ann_by_hash.len();
        (hash_count, ann_count)
    }
}
