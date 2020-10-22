//! Route computation

#![allow(unused_variables)] //TODO Remove when done

use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use thiserror::Error;

use cjdns_core::{EncodingScheme, RoutingLabel};
use cjdns_core::splice::{get_encoding_form, re_encode, splice};
use cjdns_keys::CJDNS_IP6;

use crate::server::link::Link;
use crate::server::nodes::{Node, Nodes};
use crate::server::Server;

use self::dijkstra::*;

pub struct Routing {
    last_rebuild: Instant,
    route_cache: HashMap<CacheKey, Option<Route>>,
    dijkstra: Option<Dijkstra<CJDNS_IP6, u32>>,
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
    scheme: EncodingScheme, //TODO use `Arc<EncodingScheme>` everywhere to avoid expensive copying
    inverse_form_num: usize, //TODO probably `usize` is too big, smth like `u8` is more than enough - needs refactoring
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
                    let min = peer_links
                        .iter()
                        .map(|link| {
                            let cost = link_cost(link);
                            link.cost.store(cost, Ordering::Relaxed);
                            cost
                        })
                        .min()
                        .expect("no links") // Safe because of the above `peer_links.is_empty()` check
                    ;
                    l.insert(pip.clone(), min);
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
        let mut path = dijkstra.path(&dst.ipv6, &src.ipv6);
        path.reverse();
        path
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
                        let (cur_form, cur_form_num) = get_encoding_form(label, &last.encoding_scheme).ok()?;
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
                        form_num = link.encoding_form_number as usize;
                    } else {
                        return None;
                    }
                }
                last = Some(node);
            } else {
                return None;
            }
        }

        labels.push(RoutingLabel::try_from("0000.0000.0000.0001").expect("bad self route")); //TODO duplicate constant
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

fn link_cost(_link: &Link) -> u32 {
    1
}

impl Route {
    fn identity() -> Self {
        Route {
            label: RoutingLabel::try_from("0000.0000.0000.0001").expect("bad self route"), //TODO duplicate constant
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
    use std::marker::PhantomData;

    pub(super) trait GraphBuilder<T, W: Eq + Ord> {
        fn add_node<I: Iterator<Item=(T, W)>>(&mut self, node: T, inward_links: I);
    }

    pub(super) trait GraphSolver<T, W: Eq + Ord> {
        fn path(&self, from: &T, to: &T) -> Vec<T>;
    }

    //TODO Implement Dijkstra algorithm
    pub(super) struct Dijkstra<T, W> (PhantomData<T>, PhantomData<W>);

    impl<T, W> Dijkstra<T, W> {
        pub(super) fn new() -> Self {
            Dijkstra(PhantomData, PhantomData)
        }
    }

    impl<T, W: Eq + Ord> GraphBuilder<T, W> for Dijkstra<T, W> {
        fn add_node<I: Iterator<Item=(T, W)>>(&mut self, _node: T, _inward_links: I) {
            todo!()
        }
    }

    impl<T, W: Eq + Ord> GraphSolver<T, W> for Dijkstra<T, W> {
        fn path(&self, from: &T, to: &T) -> Vec<T> {
            todo!()
        }
    }
}