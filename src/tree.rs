//! The binary tree carried in each frame's payload.
//!
//! Encoding (preorder): an absent node is `0x00`; a present node is `0x01`, its
//! value (4 bytes, signed, big-endian), then its left and right subtrees.
//!
//! The decoder never recurses: it keeps its own stack of pending child slots, so
//! stack use doesn't depend on the input. It stops at the first node past
//! [`MAX_NODES`] or deeper than [`MAX_DEPTH`].
//!
//! A [`Tree`] is also the room its decoding and level order work in. One made
//! by [`Tree::with_full_capacity`] has room for the largest tree, so decoding
//! into it again and again ([`Tree::decode_from`]) never allocates.

use std::fmt;

/// Most nodes a tree may have. Raising it is a one-line change.
pub const MAX_NODES: usize = 1_024;
/// Most nodes on any root-to-leaf path. Raising it is a one-line change.
pub const MAX_DEPTH: usize = 64;

/// Node indexes are 16-bit. A 65,535-byte payload can't hold more than 10,922
/// nodes, so raising `MAX_NODES` never needs a wider index; this check fails the
/// build if it ever would.
#[expect(
    clippy::as_conversions,
    reason = "`usize::from` can't run at compile time; widening u16 to usize loses nothing"
)]
const _: () = assert!(MAX_NODES <= u16::MAX as usize);

const ABSENT: u8 = 0x00;
const PRESENT: u8 = 0x01;
/// Smallest encoding of one present node: marker plus value.
const MIN_NODE_BYTES: usize = 5;
/// Most child slots the decoder holds at once: at most one pending right slot
/// per level, plus the slot being read.
const STACK_LEN: usize = MAX_DEPTH + 2;

/// A decoded tree, stored as an array of nodes linked by index, plus the room
/// that decoding it and listing it in level order use.
#[derive(Clone, Debug)]
pub struct Tree {
    nodes: Vec<Node>,
    root: Option<u16>,
    /// Decoding: the child slots still to read.
    stack: Vec<Slot>,
    /// Level order: each position's node, or `None` for a missing child.
    order: Vec<Option<u16>>,
    /// Level order: the values written by the last [`Tree::level_order`].
    levels: Vec<Option<i32>>,
}

/// Two trees are equal when they hold the same nodes; the work space doesn't
/// count.
impl PartialEq for Tree {
    fn eq(&self, other: &Self) -> bool {
        self.nodes == other.nodes && self.root == other.root
    }
}

impl Eq for Tree {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Node {
    value: i32,
    left: Option<u16>,
    right: Option<u16>,
}

/// Where a decoded node gets attached.
#[derive(Clone, Copy, Debug)]
enum Parent {
    Root,
    Left(u16),
    Right(u16),
}

/// A child slot waiting to be read, and the depth a node there would have.
#[derive(Clone, Copy, Debug)]
struct Slot {
    parent: Parent,
    depth: usize,
}

impl Tree {
    /// An empty tree with room for `nodes` nodes, and for decoding and listing
    /// a tree that size.
    fn with_capacity(nodes: usize) -> Self {
        // Each present node adds itself and two child entries: at most 2n + 1.
        let positions = nodes.saturating_mul(2).saturating_add(1);
        Self {
            nodes: Vec::with_capacity(nodes),
            root: None,
            stack: Vec::with_capacity(STACK_LEN),
            order: Vec::with_capacity(positions),
            levels: Vec::with_capacity(positions),
        }
    }

    /// An empty tree with room for the largest tree, reserved once: decoding
    /// into it with [`Tree::decode_from`] never allocates.
    #[must_use]
    pub fn with_full_capacity() -> Self {
        Self::with_capacity(MAX_NODES)
    }

    /// Decodes exactly one tree from `payload` into a new tree with just the
    /// room this payload can need.
    ///
    /// # Errors
    ///
    /// As [`Tree::decode_from`].
    pub fn decode(payload: &[u8]) -> Result<Self, TreeError> {
        let mut tree = Self::with_capacity(MAX_NODES.min(payload.len() / MIN_NODE_BYTES));
        tree.decode_from(payload)?;
        Ok(tree)
    }

    /// Replaces this tree with the one decoded from `payload`, reusing its room.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoding is invalid, has bytes left over, or the
    /// tree exceeds [`MAX_NODES`] or [`MAX_DEPTH`]; then the tree is left empty.
    pub fn decode_from(&mut self, payload: &[u8]) -> Result<(), TreeError> {
        let decoded = self.read(payload);
        if decoded.is_err() {
            self.clear();
        }
        decoded
    }

    fn clear(&mut self) {
        self.nodes.clear();
        self.root = None;
        self.stack.clear();
    }

    fn read(&mut self, payload: &[u8]) -> Result<(), TreeError> {
        self.clear();
        let mut rest = payload;
        self.stack.push(Slot {
            parent: Parent::Root,
            depth: 1,
        });

        while let Some(slot) = self.stack.pop() {
            let offset = payload.len().saturating_sub(rest.len());
            let (&marker, after_marker) = rest.split_first().ok_or(TreeError::Truncated)?;
            rest = after_marker;
            match marker {
                ABSENT => {}
                PRESENT => {
                    if slot.depth > MAX_DEPTH {
                        return Err(TreeError::TooDeep);
                    }
                    if self.nodes.len() >= MAX_NODES {
                        return Err(TreeError::TooManyNodes);
                    }
                    let (value, after_value) =
                        rest.split_first_chunk::<4>().ok_or(TreeError::Truncated)?;
                    rest = after_value;
                    let index = self.push(i32::from_be_bytes(*value), slot.parent)?;
                    let child_depth = slot.depth.checked_add(1).ok_or(TreeError::TooDeep)?;
                    // Right is pushed first so the left subtree is read first.
                    self.stack.push(Slot {
                        parent: Parent::Right(index),
                        depth: child_depth,
                    });
                    self.stack.push(Slot {
                        parent: Parent::Left(index),
                        depth: child_depth,
                    });
                }
                other => {
                    return Err(TreeError::BadMarker {
                        byte: other,
                        offset,
                    });
                }
            }
        }

        if rest.is_empty() {
            Ok(())
        } else {
            Err(TreeError::TrailingBytes { count: rest.len() })
        }
    }

    /// Adds a node and links it to its parent.
    fn push(&mut self, value: i32, parent: Parent) -> Result<u16, TreeError> {
        let index = u16::try_from(self.nodes.len()).map_err(|_| TreeError::TooManyNodes)?;
        self.nodes.push(Node {
            value,
            left: None,
            right: None,
        });
        match parent {
            Parent::Root => self.root = Some(index),
            Parent::Left(p) => self.node_mut(p)?.left = Some(index),
            Parent::Right(p) => self.node_mut(p)?.right = Some(index),
        }
        Ok(index)
    }

    fn node_mut(&mut self, index: u16) -> Result<&mut Node, TreeError> {
        self.nodes
            .get_mut(usize::from(index))
            .ok_or(TreeError::Internal)
    }

    /// Number of nodes in the tree.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the tree is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// The capacity of each part of the tree's room, for tests that check it
    /// never grows.
    #[cfg(test)]
    pub(crate) fn room(&self) -> [usize; 4] {
        [
            self.nodes.capacity(),
            self.stack.capacity(),
            self.order.capacity(),
            self.levels.capacity(),
        ]
    }

    /// The tree in level order, with `None` for each missing child of a present
    /// node and trailing `None`s removed: `[1,2,3,null,null,4,5]` in JSON.
    ///
    /// Written into room the tree keeps for it, so it doesn't allocate when the
    /// tree has room for its size, as every tree does.
    pub fn level_order(&mut self) -> &[Option<i32>] {
        // Breadth first: `order` is both the queue and the result. Each present
        // node appends its two children, and `next` walks along behind.
        self.order.clear();
        self.order.push(self.root);
        let mut next = 0_usize;
        while let Some(&entry) = self.order.get(next) {
            next = next.saturating_add(1);
            if let Some(node) = entry.and_then(|index| self.nodes.get(usize::from(index))) {
                self.order.push(node.left);
                self.order.push(node.right);
            }
        }
        let nodes = &self.nodes;
        self.levels.clear();
        self.levels.extend(self.order.iter().map(|entry| {
            entry
                .and_then(|index| nodes.get(usize::from(index)))
                .map(|node| node.value)
        }));
        while self.levels.last() == Some(&None) {
            self.levels.pop();
        }
        &self.levels
    }
}

/// Why a payload isn't a valid tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreeError {
    Truncated,
    BadMarker {
        byte: u8,
        offset: usize,
    },
    TrailingBytes {
        count: usize,
    },
    TooManyNodes,
    TooDeep,
    /// An index that the decoder itself created was missing.
    Internal,
}

impl fmt::Display for TreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("tree ends early"),
            Self::BadMarker { byte, offset } => {
                write!(
                    f,
                    "tree has byte 0x{byte:02x} at payload offset {offset} where 0x00 or 0x01 was expected"
                )
            }
            Self::TrailingBytes { count } => write!(f, "{count} bytes follow the tree"),
            Self::TooManyNodes => write!(f, "tree has more than {MAX_NODES} nodes"),
            Self::TooDeep => write!(f, "tree is deeper than {MAX_DEPTH} levels"),
            Self::Internal => f.write_str("internal error while decoding the tree"),
        }
    }
}

impl std::error::Error for TreeError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encodes a node with the given value; children follow.
    fn node(value: i32) -> Vec<u8> {
        let mut bytes = vec![PRESENT];
        bytes.extend_from_slice(&value.to_be_bytes());
        bytes
    }

    /// A chain of `n` nodes, each the left child of the one before.
    fn left_chain(n: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        for i in 0..n {
            bytes.extend(node(i32::try_from(i).unwrap()));
        }
        // Each node's missing left child at the bottom, then every right child.
        bytes.extend(std::iter::repeat_n(ABSENT, n + 1));
        bytes
    }

    /// A tree of exactly `n` nodes, each the right child of the one before.
    fn right_chain(n: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        for i in 0..n {
            bytes.extend(node(i32::try_from(i).unwrap()));
            bytes.push(ABSENT);
        }
        bytes.push(ABSENT);
        bytes
    }

    /// A tree with `n` nodes and depth about log2(n), built breadth-first.
    fn balanced(n: usize) -> Vec<u8> {
        fn encode(i: usize, n: usize, out: &mut Vec<u8>) {
            if i >= n {
                out.push(ABSENT);
                return;
            }
            out.extend(node(i32::try_from(i).unwrap()));
            encode(2 * i + 1, n, out);
            encode(2 * i + 2, n, out);
        }
        let mut out = Vec::new();
        encode(0, n, &mut out);
        out
    }

    #[test]
    fn decodes_the_spec_example() {
        let bytes =
            hex::decode("01000000010100000002000001000000030100000004000001000000050000").unwrap();
        assert_eq!(bytes.len(), 31);
        let mut tree = Tree::decode(&bytes).unwrap();
        assert!(!tree.is_empty());
        assert_eq!(tree.len(), 5);
        assert_eq!(
            tree.level_order(),
            vec![Some(1), Some(2), Some(3), None, None, Some(4), Some(5)]
        );
    }

    #[test]
    fn reserves_only_what_the_payload_can_hold_and_never_regrows() {
        // A node needs at least 5 bytes, so a 31-byte payload reserves room for 6:
        // enough for its 5 nodes without growing the array.
        let bytes =
            hex::decode("01000000010100000002000001000000030100000004000001000000050000").unwrap();
        let tree = Tree::decode(&bytes).unwrap();
        assert_eq!(tree.nodes.capacity(), bytes.len() / MIN_NODE_BYTES);
        let full = Tree::decode(&balanced(MAX_NODES)).unwrap();
        assert_eq!(full.nodes.capacity(), MAX_NODES);
    }

    #[test]
    fn trees_are_equal_when_their_nodes_are_whatever_their_work_space_holds() {
        let spec =
            hex::decode("01000000010100000002000001000000030100000004000001000000050000").unwrap();
        let fresh = Tree::decode(&spec).unwrap();
        let mut reused = Tree::with_full_capacity();
        reused.decode_from(&balanced(MAX_NODES)).unwrap();
        reused.level_order();
        reused.decode_from(&spec).unwrap();
        assert_eq!(fresh, reused);
        // Same root, different nodes; same nodes, no root.
        let mut other = node(1);
        other.extend([ABSENT, ABSENT]);
        assert_ne!(fresh, Tree::decode(&other).unwrap());
        let empty = Tree::decode(&[ABSENT]).unwrap();
        let mut rootless = empty.clone();
        rootless.nodes.clone_from(&fresh.nodes);
        assert_ne!(fresh, rootless);
        assert_ne!(rootless, empty);
    }

    #[test]
    fn a_full_capacity_tree_is_reused_for_every_tree_without_growing() {
        let mut tree = Tree::with_full_capacity();
        let reserved = tree.room();
        // Worked out from the limits here, not from the code's own constant.
        let positions = 2 * MAX_NODES + 1;
        assert_eq!(reserved, [MAX_NODES, MAX_DEPTH + 2, positions, positions]);
        // The largest and deepest trees there are, the deepest input there can
        // be, and a tree too large: none needs more room than was reserved.
        for (payload, ok) in [
            (balanced(MAX_NODES), true),
            (left_chain(MAX_DEPTH), true),
            (right_chain(MAX_DEPTH), true),
            (left_chain(MAX_DEPTH + 1), false),
            (right_chain(10_922), false),
            (balanced(MAX_NODES + 1), false),
        ] {
            assert_eq!(tree.decode_from(&payload).is_ok(), ok);
            if ok {
                let levels = tree.level_order().len();
                assert!(levels >= tree.len());
            } else {
                // A failed decode leaves the tree empty.
                assert!(tree.is_empty());
                assert_eq!(tree.level_order(), Vec::<Option<i32>>::new());
            }
            assert_eq!(tree.room(), reserved);
        }
        // Decoding replaces the previous tree completely.
        tree.decode_from(
            &node(7)
                .into_iter()
                .chain([ABSENT, ABSENT])
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(tree.level_order(), vec![Some(7)]);
    }

    #[test]
    fn empty_tree_is_one_zero_byte() {
        let mut tree = Tree::decode(&[ABSENT]).unwrap();
        assert!(tree.is_empty());
        assert_eq!(tree.level_order(), Vec::<Option<i32>>::new());
        assert_eq!(Tree::decode(&[]), Err(TreeError::Truncated));
    }

    #[test]
    fn values_keep_their_sign() {
        let mut bytes = node(-3);
        bytes.extend([ABSENT, ABSENT]);
        assert_eq!(Tree::decode(&bytes).unwrap().level_order(), vec![Some(-3)]);
        let mut bytes = node(i32::MIN);
        bytes.extend([ABSENT, ABSENT]);
        assert_eq!(
            Tree::decode(&bytes).unwrap().level_order(),
            vec![Some(i32::MIN)]
        );
    }

    #[test]
    fn level_order_keeps_inner_nulls_and_drops_trailing_ones() {
        // 1 with only a right child 2, which has only a left child 3.
        let mut bytes = node(1);
        bytes.push(ABSENT);
        bytes.extend(node(2));
        bytes.extend(node(3));
        bytes.extend([ABSENT, ABSENT, ABSENT]);
        assert_eq!(
            Tree::decode(&bytes).unwrap().level_order(),
            vec![Some(1), None, Some(2), Some(3)]
        );
    }

    #[test]
    fn depth_limit_is_exact() {
        Tree::decode(&left_chain(MAX_DEPTH)).unwrap();
        Tree::decode(&right_chain(MAX_DEPTH)).unwrap();
        assert_eq!(
            Tree::decode(&left_chain(MAX_DEPTH + 1)),
            Err(TreeError::TooDeep)
        );
        assert_eq!(
            Tree::decode(&right_chain(MAX_DEPTH + 1)),
            Err(TreeError::TooDeep)
        );
    }

    #[test]
    fn node_limit_is_exact() {
        let mut at_limit = Tree::decode(&balanced(MAX_NODES)).unwrap();
        assert_eq!(at_limit.len(), MAX_NODES);
        assert_eq!(at_limit.level_order().len(), MAX_NODES);
        assert_eq!(
            Tree::decode(&balanced(MAX_NODES + 1)),
            Err(TreeError::TooManyNodes)
        );
    }

    #[test]
    fn a_full_size_chain_is_rejected_without_recursion() {
        // About 10,900 nodes in one 65,535-byte chain: the deepest possible input.
        let bytes = right_chain(10_922);
        assert!(bytes.len() <= 65_535);
        assert_eq!(Tree::decode(&bytes), Err(TreeError::TooDeep));
    }

    #[test]
    fn rejects_bad_markers_truncation_and_leftovers() {
        assert_eq!(
            Tree::decode(&[0x02]),
            Err(TreeError::BadMarker { byte: 2, offset: 0 })
        );
        let mut bad_child = node(1);
        bad_child.extend([ABSENT, 0xff]);
        assert_eq!(
            Tree::decode(&bad_child),
            Err(TreeError::BadMarker {
                byte: 0xff,
                offset: 6
            })
        );
        assert_eq!(Tree::decode(&[PRESENT, 0, 0, 0]), Err(TreeError::Truncated));
        assert_eq!(Tree::decode(&node(1)), Err(TreeError::Truncated));
        assert_eq!(
            Tree::decode(&[ABSENT, ABSENT, ABSENT]),
            Err(TreeError::TrailingBytes { count: 2 })
        );
    }

    #[test]
    fn messages_for_errors_not_shown_elsewhere() {
        assert_eq!(
            TreeError::TrailingBytes { count: 3 }.to_string(),
            "3 bytes follow the tree"
        );
        assert_eq!(
            TreeError::TooManyNodes.to_string(),
            format!("tree has more than {MAX_NODES} nodes")
        );
        assert_eq!(
            TreeError::Internal.to_string(),
            "internal error while decoding the tree"
        );
    }
}
