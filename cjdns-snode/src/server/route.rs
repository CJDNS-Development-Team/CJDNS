//! Route computation

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock, RwLockWriteGuard};
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use thiserror::Error;
use tokio::task;

use cjdns_core::splice::{get_encoding_form, re_encode, splice};
use cjdns_core::{EncodingScheme, RoutingLabel};
use cjdns_keys::CJDNS_IP6;

use crate::pathsearch::{Dijkstra, GraphBuilder, GraphSolver};
use crate::server::nodes::{Node, Nodes};
use crate::server::Server;

pub struct Routing {
    state: RwLock<Option<RoutingState>>,
}

struct RoutingState {
    rebuild_lock: Mutex<bool>,
    last_rebuild: Instant,
    route_cache: HashMap<CacheKey, Arc<Mutex<Option<Route>>>>,
    dijkstra: Dijkstra<CJDNS_IP6, f64>,
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

//Serializer for Route that returns only the label and path (for use in API responses for returning path between two nodes)
impl Serialize for Route {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut route_map = serializer.serialize_struct("Route", 2)?;
        route_map.serialize_field("label", &self.label.to_string())?;

        let path_strings: Vec<String> = self.path.iter().map(|p| p.to_string()).collect();
        route_map.serialize_field("path", &path_strings)?;
        route_map.end()
    }
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
            let error = RoutingError::RouteNotFound(src.ipv6.clone(), dst.ipv6.clone());
            get_route_impl(server, src, dst).ok_or(error)
        }
    } else {
        Err(RoutingError::NoInput)
    }
}

fn get_route_impl(server: Arc<Server>, src: Arc<Node>, dst: Arc<Node>) -> Option<Route> {
    let (routing, cache_entry, exists) = {
        let mut routing = server.routing.state.write();

        // Check if routing state is not initialized yet
        if routing.is_none() {
            *routing = Some(RoutingState::new(build_node_graph(&server.nodes)));
        }

        let cache = &mut routing.as_mut().expect("routing state").route_cache;
        let cache_key = CacheKey(dst.ipv6.clone(), src.ipv6.clone());
        let (exists, entry) = match cache.entry(cache_key) {
            Entry::Occupied(e) => (true, e.into_mut()),
            Entry::Vacant(e) => (false, e.insert(Arc::new(Mutex::new(None)))),
        };
        let cache_entry = Arc::clone(&entry);

        (routing, cache_entry, exists)
    };

    // Need to lock this cache entry exclusively **before** we downgrade cache's exclusive lock to shared.
    // This is needed so no other thread could see this entry in inconsistent state (possibly just created with `None` value).
    let mut cache_entry = cache_entry.lock();

    // Now we no longer need the exclusive lock to the cache, so downgrade it to shared lock.
    let routing = RwLockWriteGuard::downgrade(routing);
    let routing = routing.as_ref().expect("routing state");

    // Check if routing state needs rebuild, and run it in background if necessary
    if let Some(mut locked) = routing.rebuild_lock.try_lock() {
        let is_locked = *locked;
        if !is_locked && routing.need_rebuild() {
            *locked = true;
            let server = Arc::clone(&server);
            task::spawn(async move {
                let d = build_node_graph(&server.nodes);
                let mut routing = server.routing.state.write();
                let routing = routing.as_mut().expect("routing state");
                routing.route_cache.clear();
                routing.dijkstra = d;
                routing.last_rebuild = Instant::now();
                let mut locked = routing.rebuild_lock.lock();
                *locked = false;
            });
        }
    }

    // Check if route already cached
    if exists {
        return cache_entry.clone();
    }

    // Compute route
    let route = compute_route(&server.nodes, routing, src, dst);

    // Store route in the cache -- now the cache entry's state is consistent
    *cache_entry = route.clone();

    route
}

fn build_node_graph(nodes: &Nodes) -> Dijkstra<CJDNS_IP6, f64> {
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
                // Replace with `f64::total_cmp` when it is stabilized
                let total_cmp = |a: &f64, b: &f64| {
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
        trace!("building dijkstra tree {} {:?}", nip, l);
        d.add_node(nip, l.into_iter());
    }

    d
}

fn compute_route(nodes: &Nodes, routing: &RoutingState, src: Arc<Node>, dst: Arc<Node>) -> Option<Route> {
    // We ask for the path in reverse because we build the graph in reverse.
    // Because nodes announce their own reachability instead of reachability of others.
    let path = routing.dijkstra.reverse_path(&dst.ipv6, &src.ipv6);

    if path.is_empty() {
        return None;
    }

    let (label, hops) = compute_routing_label(nodes, &path)?;

    let route = Route { label, hops, path };

    Some(route)
}

fn compute_routing_label(nodes: &Nodes, rev_path: &[CJDNS_IP6]) -> Option<(RoutingLabel<u64>, Vec<Hop>)> {
    let (labels, hops) = {
        let mut last: Option<Arc<Node>> = None;
        let mut hops = Vec::new();
        let mut labels = Vec::new();
        let mut form_num = 0;

        for nip in rev_path.iter() {
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

    Some((spliced, hops))
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
        Routing { state: RwLock::new(None) }
    }
}

impl RoutingState {
    pub(super) fn new(d: Dijkstra<CJDNS_IP6, f64>) -> Self {
        RoutingState {
            rebuild_lock: Mutex::new(false),
            last_rebuild: Instant::now(),
            route_cache: HashMap::new(),
            dijkstra: d,
        }
    }

    pub(super) fn need_rebuild(&self) -> bool {
        const REBUILD_INTERVAL: Duration = Duration::from_secs(3);
        let now = Instant::now();
        self.last_rebuild + REBUILD_INTERVAL < now
    }
}
