//! Frontier for the Dijkstra algorithm.

use std::cmp::Reverse;
use std::collections::HashMap;
use std::hash::Hash;

use super::numtraits::IntoOrd;

/// Frontier for the Dijkstra algorithm.
/// Internally uses binary search to maintain priority queue and hashmap-based index.
pub(super) struct Frontier<T, W> {
    /// Stores items in cost-descending order,
    /// so the item with the lowest cost is placed at the end of the array.
    queue: Vec<(T, W)>,

    /// Links node tag `<T>` to the index in the `queue`.
    index: HashMap<T, usize>,
}

impl<T, W> Frontier<T, W> where T: Clone + Ord + Eq + Hash, W: Clone + PartialOrd + IntoOrd {
    /// Create new empty instance.
    pub fn new() -> Frontier<T, W> {
        Frontier {
            queue: Vec::new(),
            index: HashMap::new(),
        }
    }

    /// Sorts by cost in descending order, then by tag.
    fn key_fn(item: &(T, W)) -> impl Ord {
        let (t, w) = item;
        (Reverse(w.clone().into_ord()), t.clone())
    }

    /// Find position in the queue where to insert a new item.
    fn insertion_pos(&self, item: &(T, W)) -> usize {
        match self.queue.binary_search_by_key(&Self::key_fn(item), Self::key_fn) {
            Ok(index) | Err(index) => index
        }
    }

    /// Insert a node with associated cost into the priority queue.
    pub fn push(&mut self, tag: T, weight: W) {
        let item = (tag.clone(), weight);
        let index = self.insertion_pos(&item);
        self.queue.insert(index, item);
        self.index.iter_mut().for_each(|(_, old_idx)| if *old_idx >= index { *old_idx += 1; });
        self.index.insert(tag, index);
    }

    /// Extract node with the least cost from the queue.
    pub fn pop(&mut self) -> Option<(T, W)> {
        if let Some((tag, weight)) = self.queue.pop() {
            // Since pop() removed the item with the highest index,
            // no need to correct any other items in index.
            self.index.remove(&tag);
            Some((tag, weight))
        } else {
            None
        }
    }

    /// Insert a node if it is not in the queue yet,
    /// otherwise update associated cost if the new cost is less that existing.
    /// Returns `true` if the node was either inserted or updated,
    /// otherwise (node existed and current cost is less that the new one) `false`.
    pub fn try_insert_or_decrease_cost(&mut self, tag: &T, new_cost: W) -> bool {
        if let Some(&i) = self.index.get(tag) {
            if new_cost < self.queue[i].1 {
                // Remove old item
                self.queue.remove(i);
                self.index.remove(tag);
                self.index.iter_mut().for_each(|(_, old_idx)| if *old_idx >= i { *old_idx -= 1; });

                // Re-insert with updated cost
                let new_item = (tag.clone(), new_cost);
                let new_index = self.insertion_pos(&new_item);
                self.queue.insert(new_index, new_item);
                self.index.iter_mut().for_each(|(_, old_idx)| if *old_idx >= new_index { *old_idx += 1; });
                self.index.insert(tag.clone(), new_index);

                true
            } else {
                false
            }
        } else {
            self.push(tag.clone(), new_cost);
            true
        }
    }
}

#[test]
fn test_push_pop() {
    let mut f = Frontier::new();
    assert_eq!(f.pop(), None);

    f.push("N", 1.0);
    assert_eq!(f.pop(), Some(("N", 1.0)));
    assert_eq!(f.pop(), None);

    f.push("A", 1.0);
    f.push("B", 2.0);
    assert_eq!(f.pop(), Some(("A", 1.0)));
    assert_eq!(f.pop(), Some(("B", 2.0)));
    assert_eq!(f.pop(), None);

    f.push("X", 2.0);
    f.push("Y", 1.0);
    assert_eq!(f.pop(), Some(("Y", 1.0)));
    assert_eq!(f.pop(), Some(("X", 2.0)));
    assert_eq!(f.pop(), None);
}

#[test]
fn test_decrease_cost() {
    let mut f = Frontier::new();
    assert_eq!(f.pop(), None);

    assert_eq!(f.try_insert_or_decrease_cost(&"A", 1.0), true);
    assert_eq!(f.pop(), Some(("A", 1.0)));
    assert_eq!(f.pop(), None);

    f.push("B", 2.0);
    assert_eq!(f.try_insert_or_decrease_cost(&"A", 1.0), true);
    assert_eq!(f.pop(), Some(("A", 1.0)));
    assert_eq!(f.pop(), Some(("B", 2.0)));
    assert_eq!(f.pop(), None);

    assert_eq!(f.try_insert_or_decrease_cost(&"A", 1.0), true);
    assert_eq!(f.try_insert_or_decrease_cost(&"B", 2.0), true);
    assert_eq!(f.pop(), Some(("A", 1.0)));
    assert_eq!(f.pop(), Some(("B", 2.0)));
    assert_eq!(f.pop(), None);

    f.push("X", 1.0);
    assert_eq!(f.try_insert_or_decrease_cost(&"X", 2.0), false);
    assert_eq!(f.pop(), Some(("X", 1.0)));
    assert_eq!(f.pop(), None);

    f.push("Y", 2.0);
    assert_eq!(f.try_insert_or_decrease_cost(&"Y", 1.0), true);
    assert_eq!(f.pop(), Some(("Y", 1.0)));
    assert_eq!(f.pop(), None);

    f.push("X", 1.0);
    f.push("Y", 3.0);
    assert_eq!(f.try_insert_or_decrease_cost(&"Y", 2.0), true);
    assert_eq!(f.pop(), Some(("X", 1.0)));
    assert_eq!(f.pop(), Some(("Y", 2.0)));
    assert_eq!(f.pop(), None);

    f.push("X", 2.0);
    f.push("Y", 3.0);
    assert_eq!(f.try_insert_or_decrease_cost(&"Y", 1.0), true);
    assert_eq!(f.pop(), Some(("Y", 1.0)));
    assert_eq!(f.pop(), Some(("X", 2.0)));
    assert_eq!(f.pop(), None);
}