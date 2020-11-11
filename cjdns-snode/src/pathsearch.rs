//! Path search in a weighted graph.

pub use self::dijkstra::Dijkstra;
pub use self::graph::{GraphBuilder, GraphSolver};

mod graph;
mod numtraits;
mod dijkstra;
mod frontier;

#[test]
fn test_dijkstra_search() {
    let mut g = Dijkstra::new();
    g.add_node("A", vec![("B", 1.0)]);
    g.add_node("B", vec![("A", 1.0), ("C", 2.0), ("D", 4.0)]);
    g.add_node("C", vec![("B", 2.0), ("D", 1.0)]);
    g.add_node("D", vec![("C", 1.0), ("B", 4.0)]);
    assert_eq!(g.path(&"A", &"D"), vec!["A", "B", "C", "D"]);
    assert_eq!(g.reverse_path(&"A", &"D"), vec!["D", "C", "B", "A"]);
}