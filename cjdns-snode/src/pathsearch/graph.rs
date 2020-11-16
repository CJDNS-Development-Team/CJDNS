//! Path solver graph traits.

/// Graph building functions.
pub trait GraphBuilder<T, W> {
    fn add_node<I: IntoIterator<Item = (T, W)>>(&mut self, node_tag: T, links: I);
}

/// Path finding functions.
pub trait GraphSolver<T, W> {
    /// Find a path from `from` node to `to` node.
    fn path(&self, from: &T, to: &T) -> Vec<T>;

    /// Find a reverse path from `to` node to `from` node.
    fn reverse_path(&self, from: &T, to: &T) -> Vec<T>;

    /// Build a Path Search Tree from a given node.
    fn path_search_tree(&self, start: &T) -> PathSearchTree<T>;
}

/// Tree that describes shortest path from a given start node to every other node.
pub struct PathSearchTree<T> {
    /// The starting node in every path.
    pub start_node: T,

    /// Each tuple contains ending node and intermediate nodes as a vector.
    pub paths: Vec<(T, Vec<T>)>,
}
