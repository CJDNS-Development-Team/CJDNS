//! Route computation

use std::sync::Arc;

use crate::server::nodes::Node;
use crate::server::Server;

pub struct Route;

pub(super) fn get_route(server: Arc<Server>, src: Option<Node>, dst: Option<Node>) -> Result<Route, ()> {
    todo!()
}