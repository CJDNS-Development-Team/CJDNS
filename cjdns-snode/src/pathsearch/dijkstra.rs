//! Dijkstra path search implementation.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::ops::Add;

use super::frontier::Frontier;
use super::graph::{GraphBuilder, GraphSolver};
use super::numtraits::{IntoOrd, Zero};

/// Dijkstra path search.
pub struct Dijkstra<T, W> {
    /// Links node with tag `<T>` to the list of ajacent nodest with corresponding weights `<W>`.
    nodes: HashMap<T, Vec<(T, W)>>
}

impl<T, W> Dijkstra<T, W> {
    /// Create new instance with empty graph.
    pub fn new() -> Self {
        Dijkstra {
            nodes: HashMap::new()
        }
    }
}

impl<T, W> GraphBuilder<T, W> for Dijkstra<T, W> where T: Eq + Hash, W: PartialEq + PartialOrd + Zero {
    fn add_node<I: IntoIterator<Item=(T, W)>>(&mut self, node_tag: T, links: I) {
        let links = links.into_iter().collect::<Vec<(T, W)>>();
        debug_assert!(links.iter().all(|(_, w)| *w >= W::ZERO), "Negative weight detected");
        self.nodes.insert(node_tag, links);
    }
}

impl<T, W> GraphSolver<T, W> for Dijkstra<T, W> where T: Clone + Eq + Ord + Hash, W: Clone + PartialEq + PartialOrd + IntoOrd + Add<Output=W> + Zero {
    fn path(&self, from: &T, to: &T) -> Vec<T> {
        let mut path = self.reverse_path(from, to);

        // Reverse the path, so the result will be from `from` to `to`
        path.reverse();

        path
    }

    fn reverse_path(&self, from: &T, to: &T) -> Vec<T> {
        // Don't run when we don't have nodes set
        if self.nodes.is_empty() {
            return Vec::new();
        }

        // Algorithm state
        let mut explored = HashSet::<T>::new();
        let mut frontier = Frontier::<T, W>::new();
        let mut previous = HashMap::<T, T>::new();

        // The resulting reversed path
        let mut rev_path = Vec::<T>::new();

        // Add the starting point to the frontier, it will be the first node visited
        frontier.push(from.clone(), W::ZERO);

        // Run until we have visited every node in the frontier
        while let Some((id, cost)) = frontier.pop() {
            // When the node with the lowest cost in the frontier is our goal node, we're done.
            if id == *to {
                let mut cur_id = id;
                while let Some(prev) = previous.get(&cur_id) {
                    rev_path.push(cur_id.clone());
                    cur_id = prev.clone();
                }
                break;
            }

            // Add the current node to the explored set
            explored.insert(id.clone());

            // Loop all the neighboring nodes
            if let Some(neighbors) = self.nodes.get(&id) {
                for (n_node, n_cost) in neighbors.iter() {
                    // If we already explored the node - skip it
                    if explored.contains(n_node) {
                        continue;
                    }

                    let node_cost = cost.clone() + n_cost.clone();

                    // If the neighboring node is not yet in the frontier, we add it with the correct cost.
                    // Otherwise we only update the cost of this node in the frontier when it's below what's currently set.
                    let updated = frontier.try_insert_or_decrease_cost(n_node, node_cost);
                    if updated {
                        previous.insert(n_node.clone(), id.clone());
                    }
                }
            }
        }

        // Check if path not found
        if rev_path.is_empty() {
            return rev_path;
        }

        // Add the origin waypoint at the end of the array
        rev_path.push(from.clone());

        rev_path
    }
}