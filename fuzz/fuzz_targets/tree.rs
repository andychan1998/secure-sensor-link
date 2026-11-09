//! Any payload bytes into the tree decoder. When it accepts them, the tree must
//! be within the limits, and rebuilding it from the level-order output and
//! encoding it again (both written independently here) must give back exactly
//! the input: so the decoder and the level-order output agree with the spec's
//! format on every tree the fuzzer finds.

#![no_main]

use std::collections::VecDeque;

use libfuzzer_sys::fuzz_target;
use secure_sensor_link::tree::{MAX_DEPTH, MAX_NODES, Tree};

fuzz_target!(|data: &[u8]| {
    let Ok(mut tree) = Tree::decode(data) else {
        return;
    };
    let levels = tree.level_order();
    let (nodes, root) = rebuild(levels);
    assert!(nodes.len() <= MAX_NODES);
    assert!(depth(&nodes, root) <= MAX_DEPTH);
    let mut encoded = Vec::new();
    encode(&nodes, root, &mut encoded);
    assert_eq!(encoded, data);
});

struct Node {
    value: i32,
    children: [Option<usize>; 2],
}

/// Builds the tree from level order: each present node's two children follow
/// in turn, and trailing `None`s are left out.
fn rebuild(levels: &[Option<i32>]) -> (Vec<Node>, Option<usize>) {
    let mut nodes = Vec::new();
    let mut items = levels.iter();
    let root = match items.next() {
        Some(Some(value)) => {
            nodes.push(Node {
                value: *value,
                children: [None, None],
            });
            Some(0)
        }
        Some(None) => panic!("level order starts with null: {levels:?}"),
        None => None,
    };
    let mut queue: VecDeque<usize> = root.into_iter().collect();
    while let Some(parent) = queue.pop_front() {
        for side in 0..2 {
            if let Some(Some(value)) = items.next() {
                let child = nodes.len();
                nodes.push(Node {
                    value: *value,
                    children: [None, None],
                });
                nodes[parent].children[side] = Some(child);
                queue.push_back(child);
            }
        }
    }
    assert!(
        items.next().is_none(),
        "level order has extra entries: {levels:?}"
    );
    (nodes, root)
}

/// The spec's preorder encoding.
fn encode(nodes: &[Node], index: Option<usize>, out: &mut Vec<u8>) {
    match index {
        None => out.push(0x00),
        Some(index) => {
            let node = &nodes[index];
            out.push(0x01);
            out.extend_from_slice(&node.value.to_be_bytes());
            encode(nodes, node.children[0], out);
            encode(nodes, node.children[1], out);
        }
    }
}

fn depth(nodes: &[Node], index: Option<usize>) -> usize {
    index.map_or(0, |index| {
        let [left, right] = nodes[index].children;
        1 + depth(nodes, left).max(depth(nodes, right))
    })
}
