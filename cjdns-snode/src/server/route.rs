//! Route computation

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;

use cjdns_core::{EncodingScheme, RoutingLabel};
use cjdns_core::splice::{get_encoding_form, re_encode, splice};
use cjdns_keys::CJDNS_IP6;

use crate::server::nodes::{Node, Nodes};
use crate::server::Server;

use self::dijkstra::*;

pub struct Routing {
    last_rebuild: Instant,
    route_cache: HashMap<CacheKey, Option<Route>>,
    dijkstra: Option<Dijkstra<CJDNS_IP6, f64>>,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct CacheKey(CJDNS_IP6, CJDNS_IP6);

#[derive(Clone)]
pub struct Route {
    pub label: RoutingLabel<u64>,
    hops: Vec<Hop>,
    path: Vec<CJDNS_IP6>,
}

#[derive(Clone)]
struct Hop {
    label: RoutingLabel<u64>,
    orig_label: RoutingLabel<u32>,
    scheme: Arc<EncodingScheme>,
    inverse_form_num: u8,
}

#[derive(PartialEq, Eq, Clone, Debug, Error)]
pub enum RoutingError {
    #[error("Can't build route - either start or end node is not specified")]
    NoInput,
    #[error("Route not found between {0} and {1}")]
    RouteNotFound(CJDNS_IP6, CJDNS_IP6),
}

pub(super) fn get_route(server: Arc<Server>, src: Option<Arc<Node>>, dst: Option<Arc<Node>>) -> Result<Route, RoutingError> {
    if let (Some(src), Some(dst)) = (src, dst) {
        if src == dst {
            Ok(Route::identity())
        } else {
            let nodes = &server.nodes;
            let routing = &mut server.mut_state.lock().routing;
            let error = RoutingError::RouteNotFound(src.ipv6.clone(), dst.ipv6.clone());
            get_route_impl(nodes, routing, src, dst).ok_or(error)
        }
    } else {
        Err(RoutingError::NoInput)
    }
}

fn get_route_impl(nodes: &Nodes, routing: &mut Routing, src: Arc<Node>, dst: Arc<Node>) -> Option<Route> {
    let now = Instant::now();
    const REBUILD_INTERVAL: Duration = Duration::from_secs(3);
    if routing.last_rebuild + REBUILD_INTERVAL < now || routing.dijkstra.is_none() {
        routing.route_cache.clear();
        let mut d = Dijkstra::new();

        for nip in nodes.all_ips() {
            let node = nodes.by_ip(&nip).unwrap();
            let links = node.inward_links_by_ip.lock();
            let mut l = HashMap::new();
            for (pip, peer_links) in links.iter() {
                if peer_links.is_empty() {
                    continue; // Shouldn't happen but let's be safe
                }
                if let Some(reverse) = nodes.by_ip(pip) {
                    if reverse.inward_links_by_ip.lock().get(&nip).is_none() {
                        continue;
                    }
                    let total_cmp = |a: &f64, b: &f64| { // Replace with `f64::total_cmp` when it is stabilized
                        let mut a = a.to_bits() as i64;
                        let mut b = b.to_bits() as i64;
                        a ^= (((a >> 63) as u64) >> 1) as i64;
                        b ^= (((b >> 63) as u64) >> 1) as i64;
                        a.cmp(&b)
                    };
                    let max_value = peer_links
                        .iter()
                        .map(|link| link.mut_state.lock().value)
                        .max_by(total_cmp) // Replace with `f64::total_cmp` when it is stabilized (unstable as of Rust 1.46)
                        .expect("no links") // Safe because of the above `peer_links.is_empty()` check
                    ;
                    let max_value = if max_value == 0.0 { 1e-20 } else { max_value };
                    let min_cost = max_value.recip();
                    l.insert(pip.clone(), min_cost);
                }
            }
            debug!("building dijkstra tree {} {:?}", nip, l);
            d.add_node(nip, l.into_iter());
        }

        routing.dijkstra = Some(d);
        routing.last_rebuild = now;
    }

    let cache_key = CacheKey(dst.ipv6.clone(), src.ipv6.clone());
    if let Some(Some(cached_entry)) = routing.route_cache.get(&cache_key).cloned() {
        return Some(cached_entry);
    }

    // We ask for the path in reverse because we build the graph in reverse.
    // Because nodes announce their own reachability instead of reachability of others.
    let path = {
        let dijkstra = routing.dijkstra.as_ref().expect("no path solver");
        dijkstra.reverse_path(&dst.ipv6, &src.ipv6)
    };

    if path.is_empty() {
        routing.route_cache.insert(cache_key, None);
        return None;
    }

    let (labels, hops) = {
        let mut last: Option<Arc<Node>> = None;
        let mut hops = Vec::new();
        let mut labels = Vec::new();
        let mut form_num = 0;

        for nip in path.iter() {
            if let Some(node) = nodes.by_ip(nip) {
                if let Some(last) = last {
                    if let Some(Some(link)) = node.inward_links_by_ip.lock().get(&last.ipv6).map(|ls| ls.get(0)) {
                        let mut label = RoutingLabel::try_new(link.label.bits() as u64)?;
                        let (_, cur_form_num) = get_encoding_form(label, &last.encoding_scheme).ok()?;
                        if cur_form_num < form_num {
                            label = re_encode(label, &last.encoding_scheme, Some(form_num)).ok()?;
                        }
                        labels.push(label);
                        let hop = Hop {
                            label: label.clone(),
                            orig_label: link.label.clone(),
                            scheme: last.encoding_scheme.clone(),
                            inverse_form_num: form_num,
                        };
                        hops.push(hop);
                        form_num = link.encoding_form_number;
                    } else {
                        return None;
                    }
                }
                last = Some(node);
            } else {
                return None;
            }
        }

        labels.push(RoutingLabel::self_reference());
        labels.reverse();

        (labels, hops)
    };

    let spliced = splice(&labels).ok()?;
    let route = Route {
        label: spliced,
        hops,
        path,
    };

    routing.route_cache.insert(cache_key, Some(route.clone()));

    Some(route)
}

impl Route {
    fn identity() -> Self {
        Route {
            label: RoutingLabel::self_reference(),
            hops: Vec::new(),
            path: Vec::new(),
        }
    }
}

impl Routing {
    pub(super) fn new() -> Self {
        Routing {
            last_rebuild: Instant::now(),
            route_cache: HashMap::new(),
            dijkstra: None,
        }
    }
}

mod dijkstra {
    use std::cmp::Reverse;
    use std::collections::{HashMap, HashSet};
    use std::hash::Hash;
    use std::ops::Add;

    /// Graph building functions.
    pub(super) trait GraphBuilder<T, W> {
        fn add_node<I: IntoIterator<Item=(T, W)>>(&mut self, node_tag: T, links: I);
    }

    /// Path finding functions.
    pub(super) trait GraphSolver<T, W> {
        /// Find a path from `from` node to `to` node.
        fn path(&self, from: &T, to: &T) -> Vec<T>;

        /// Find a reverse path from `to` node to `from` node.
        fn reverse_path(&self, from: &T, to: &T) -> Vec<T>;
    }

    /// Dijkstra path search implementation.
    pub(super) struct Dijkstra<T, W> {
        /// Links node with tag `<T>` to the list of ajacent nodest with corresponding weights `<W>`.
        nodes: HashMap<T, Vec<(T, W)>>
    }

    /// Forntier for the Dijkstra algorithm.
    struct Frontier<T, W> {
        /// Stores items in cost-descending order,
        /// so the item with the lowest cost is placed at the end of the array.
        queue: Vec<(T, W)>,

        /// Links node tag `<T>` to the index in the `queue`.
        index: HashMap<T, usize>,
    }

    /// Helper trait providing zero value for numeric types.
    pub(super) trait Zero {
        const ZERO: Self;
    }

    impl Zero for f64 {
        const ZERO: f64 = 0.0;
    }

    /// Helper trait, providing total ordering for non-`Ord` types,
    /// such as `f64`, given its value is finite (i.e. not `NaN`, `Infinity` etc.)
    pub(super) trait IntoOrd where Self::Output: Ord {
        /// Some substitute `Ord` type which can be used instead of `Self` for ordering purposes.
        /// Only should be used for comparisons, its value itself is meaningless.
        type Output;
        fn into_ord(self) -> Self::Output;
    }

    impl IntoOrd for f64 {
        type Output = i64;

        fn into_ord(self) -> Self::Output {
            // For the explanation of this black magic,
            // see implementation of `f64::total_ord()` (unstable as of Rust 1.46)
            let x = self.to_bits() as i64;
            x ^ (((x >> 63) as u64) >> 1) as i64
        }
    }

    impl<T, W> Dijkstra<T, W> {
        pub(super) fn new() -> Self {
            Dijkstra {
                nodes: HashMap::new()
            }
        }
    }

    impl<T, W> GraphBuilder<T, W> for Dijkstra<T, W> where T: Eq + Hash, W: PartialEq + PartialOrd {
        fn add_node<I: IntoIterator<Item=(T, W)>>(&mut self, node_tag: T, links: I) {
            self.nodes.insert(node_tag, links.into_iter().collect());
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

    impl<T, W> Frontier<T, W> where T: Clone + Ord + Eq + Hash, W: Clone + PartialOrd + IntoOrd {
        pub fn new() -> Frontier<T, W> {
            Frontier {
                queue: Vec::new(),
                index: HashMap::new(),
            }
        }

        /// Sorts by cost in descending order, then by tag
        fn key_fn(item: &(T, W)) -> impl Ord {
            let (t, w) = item;
            (Reverse(w.clone().into_ord()), t.clone())
        }

        pub fn push(&mut self, tag: T, weight: W) {
            let item = (tag.clone(), weight);
            match self.queue.binary_search_by_key(&Self::key_fn(&item), Self::key_fn) {
                Ok(index) | Err(index) => {
                    self.queue.insert(index, item);
                    self.index.iter_mut().for_each(|(_, old_idx)| if *old_idx >= index { *old_idx += 1; });
                    self.index.insert(tag, index);
                }
            }
        }

        pub fn pop(&mut self) -> Option<(T, W)> {
            if let Some((tag, weight)) = self.queue.pop() {
                self.index.remove(&tag);
                Some((tag, weight))
            } else {
                None
            }
        }

        pub fn try_insert_or_decrease_cost(&mut self, tag: &T, new_cost: W) -> bool {
            if let Some(&i) = self.index.get(tag) {
                if new_cost < self.queue[i].1 {
                    self.queue[i].1 = new_cost;
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
    fn test_search() {
        let mut g = Dijkstra::new();
        g.add_node("A", vec![("B", 1.0)]);
        g.add_node("B", vec![("A", 1.0), ("C", 2.0), ("D", 4.0)]);
        g.add_node("C", vec![("B", 2.0), ("D", 1.0)]);
        g.add_node("D", vec![("C", 1.0), ("B", 4.0)]);
        assert_eq!(g.path(&"A", &"D"), vec!["A", "B", "C", "D"]);
        assert_eq!(g.reverse_path(&"A", &"D"), vec!["D", "C", "B", "A"]);
    }
}