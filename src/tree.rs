//! The binary tree carried in each frame's payload.
//!
//! Encoding (preorder): an absent node is `0x00`; a present node is `0x01`, its
//! value (4 bytes, signed, big-endian), then its left and right subtrees.
//!
//! The decoder never recurses: it keeps its own stack of pending child slots, so
//! stack use doesn't depend on the input. It stops at the first node past
//! [`MAX_NODES`] or deeper than [`MAX_DEPTH`].

use std::collections::VecDeque;
use std::fmt;

/// Most nodes a tree may have. Raising it is a one-line change.
pub const MAX_NODES: usize = 1_024;
/// Most nodes on any root-to-leaf path. Raising it is a one-line change.
pub const MAX_DEPTH: usize = 64;

/// Node indexes are 16-bit. A 65,535-byte payload can't hold more than 10,922
/// nodes, so raising `MAX_NODES` never needs a wider index; this check fails the
/// build if it ever would.
#[allow(clippy::as_conversions)]
const _: () = assert!(MAX_NODES <= u16::MAX as usize);

const ABSENT: u8 = 0x00;
const PRESENT: u8 = 0x01;
/// Smallest encoding of one present node: marker plus value.
const MIN_NODE_BYTES: usize = 5;

/// A decoded tree, stored as an array of nodes linked by index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tree {
    nodes: Vec<Node>,
    root: Option<u16>,
}

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
    /// Decodes exactly one tree from `payload`.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoding is invalid, has bytes left over, or the
    /// tree exceeds [`MAX_NODES`] or [`MAX_DEPTH`].
    pub fn decode(payload: &[u8]) -> Result<Self, TreeError> {
        let mut rest = payload;
        let capacity = MAX_NODES.min(payload.len() / MIN_NODE_BYTES);
        let mut tree = Self {
            nodes: Vec::with_capacity(capacity),
            root: None,
        };
        // At most one pending right slot per level, plus the slot being read.
        let mut stack: Vec<Slot> = Vec::with_capacity(MAX_DEPTH.saturating_add(2));
        stack.push(Slot {
            parent: Parent::Root,
            depth: 1,
        });

        while let Some(slot) = stack.pop() {
            let offset = payload.len().saturating_sub(rest.len());
            let (&marker, after_marker) = rest.split_first().ok_or(TreeError::Truncated)?;
            rest = after_marker;
            match marker {
                ABSENT => {}
                PRESENT => {
                    if slot.depth > MAX_DEPTH {
                        return Err(TreeError::TooDeep);
                    }
                    if tree.nodes.len() >= MAX_NODES {
                        return Err(TreeError::TooManyNodes);
                    }
                    let (value, after_value) =
                        rest.split_first_chunk::<4>().ok_or(TreeError::Truncated)?;
                    rest = after_value;
                    let index = tree.push(i32::from_be_bytes(*value), slot.parent)?;
                    let child_depth = slot.depth.checked_add(1).ok_or(TreeError::TooDeep)?;
                    // Right is pushed first so the left subtree is read first.
                    stack.push(Slot {
                        parent: Parent::Right(index),
                        depth: child_depth,
                    });
                    stack.push(Slot {
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
            Ok(tree)
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

    fn node(&self, index: u16) -> Option<&Node> {
        self.nodes.get(usize::from(index))
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

    /// The tree in level order, with `None` for each missing child of a present
    /// node and trailing `None`s removed: `[1,2,3,null,null,4,5]` in JSON.
    #[must_use]
    pub fn level_order(&self) -> Vec<Option<i32>> {
        // Each present node adds itself and two child entries: at most 2n + 1.
        let mut out = Vec::with_capacity(self.nodes.len().saturating_mul(2).saturating_add(1));
        let mut queue = VecDeque::with_capacity(self.nodes.len().saturating_add(1));
        queue.push_back(self.root);
        while let Some(entry) = queue.pop_front() {
            match entry.and_then(|index| self.node(index)) {
                Some(node) => {
                    out.push(Some(node.value));
                    queue.push_back(node.left);
                    queue.push_back(node.right);
                }
                None => out.push(None),
            }
        }
        while out.last() == Some(&None) {
            out.pop();
        }
        out
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
        let tree = Tree::decode(&bytes).unwrap();
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
    fn empty_tree_is_one_zero_byte() {
        let tree = Tree::decode(&[ABSENT]).unwrap();
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
        let at_limit = Tree::decode(&balanced(MAX_NODES)).unwrap();
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
}
