//! Path search in a weighted graph.

pub use self::dijkstra::Dijkstra;
pub use self::graph::{GraphBuilder, GraphSolver};

mod dijkstra;
mod frontier;
mod graph;
mod numtraits;

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

#[test]
fn test_dijkstra_search_all() {
    let mut g = Dijkstra::new();
    g.add_node("1", vec![("2", 7.0), ("3", 9.0), ("6", 14.0)]);
    g.add_node("2", vec![("1", 7.0), ("3", 10.0), ("4", 15.0)]);
    g.add_node("3", vec![("1", 9.0), ("2", 10.0), ("4", 11.0), ("6", 2.0)]);
    g.add_node("4", vec![("2", 15.0), ("3", 11.0), ("5", 6.0)]);
    g.add_node("5", vec![("4", 6.0), ("6", 9.0)]);
    g.add_node("6", vec![("1", 14.0), ("3", 2.0), ("5", 9.0)]);
    let mut all = g.path_search_tree(&"1");
    all.paths.sort(); // Because `path_search_tree()` returns paths in unspecified order
    assert_eq!(all.start_node, "1");
    assert_eq!(
        all.paths,
        vec![("2", vec![]), ("3", vec![]), ("4", vec!["3"]), ("5", vec!["3", "6"]), ("6", vec!["3"]),],
    );
}
