//! Sync protocol types for forum DAG synchronization.
//!
//! This module defines the request/response types used for syncing forum data
//! between clients and relays. The protocol is designed to:
//! - Minimize data transfer by only sending missing nodes
//! - Support incremental sync using DAG heads
//! - Be stateless on the server side
//!
//! ## Sync Algorithm
//!
//! 1. Client sends known heads (nodes with no children)
//! 2. Server computes which nodes the client is missing
//! 3. Client requests the missing nodes by hash
//! 4. Client validates and stores the received nodes
//!
//! This approach works because the DAG structure means any node's ancestry
//! can be determined by following parent references.

use crate::forum::{ContentHash, DagNode};
use serde::{Deserialize, Serialize};

/// Request to sync with a forum's DAG.
///
/// The client sends the hashes of nodes it considers "heads" (nodes without children).
/// The server responds with hashes of nodes the client is missing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    /// The forum hash to sync.
    pub forum_hash: ContentHash,
    /// Hashes of nodes the client has that have no children (heads).
    /// If empty, client wants to sync from scratch.
    pub known_heads: Vec<ContentHash>,
    /// Optional: Maximum number of missing hashes to return.
    /// Useful for paginated sync of large forums.
    pub max_results: Option<usize>,
}

impl SyncRequest {
    /// Creates a new sync request for a forum.
    pub fn new(forum_hash: ContentHash) -> Self {
        Self {
            forum_hash,
            known_heads: Vec::new(),
            max_results: None,
        }
    }

    /// Creates a sync request with known heads.
    pub fn with_heads(forum_hash: ContentHash, known_heads: Vec<ContentHash>) -> Self {
        Self {
            forum_hash,
            known_heads,
            max_results: None,
        }
    }

    /// Sets the maximum number of results to return.
    pub fn with_max_results(mut self, max: usize) -> Self {
        self.max_results = Some(max);
        self
    }
}

/// Response to a sync request.
///
/// Contains hashes of nodes the client is missing, which they can then
/// fetch using `FetchNodesRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    /// The forum hash this response is for.
    pub forum_hash: ContentHash,
    /// Hashes of nodes the client is missing.
    /// Ordered so parents come before children (topological order).
    pub missing_hashes: Vec<ContentHash>,
    /// Whether there are more missing nodes than returned.
    /// If true, client should sync again after fetching these.
    pub has_more: bool,
    /// Current heads on the server (for client to update after sync).
    pub server_heads: Vec<ContentHash>,
}

impl SyncResponse {
    /// Creates a new sync response.
    pub fn new(forum_hash: ContentHash) -> Self {
        Self {
            forum_hash,
            missing_hashes: Vec::new(),
            has_more: false,
            server_heads: Vec::new(),
        }
    }

    /// Sets the missing hashes.
    pub fn with_missing(mut self, hashes: Vec<ContentHash>) -> Self {
        self.missing_hashes = hashes;
        self
    }

    /// Sets whether there are more nodes to sync.
    pub fn with_has_more(mut self, has_more: bool) -> Self {
        self.has_more = has_more;
        self
    }

    /// Sets the server's current heads.
    pub fn with_server_heads(mut self, heads: Vec<ContentHash>) -> Self {
        self.server_heads = heads;
        self
    }
}

/// Request to fetch specific nodes by hash.
///
/// Used after a `SyncResponse` to retrieve the actual node data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchNodesRequest {
    /// Hashes of nodes to fetch.
    pub hashes: Vec<ContentHash>,
}

impl FetchNodesRequest {
    /// Creates a new fetch request.
    pub fn new(hashes: Vec<ContentHash>) -> Self {
        Self { hashes }
    }
}

/// Response containing fetched nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchNodesResponse {
    /// The fetched nodes, serialized.
    /// Order matches the request order where possible.
    pub nodes: Vec<SerializedNode>,
    /// Hashes that were not found.
    pub not_found: Vec<ContentHash>,
}

impl FetchNodesResponse {
    /// Creates a new fetch response.
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            not_found: Vec::new(),
        }
    }

    /// Adds a node to the response.
    pub fn add_node(&mut self, hash: ContentHash, data: Vec<u8>) {
        self.nodes.push(SerializedNode { hash, data });
    }

    /// Adds a not-found hash to the response.
    pub fn add_not_found(&mut self, hash: ContentHash) {
        self.not_found.push(hash);
    }
}

impl Default for FetchNodesResponse {
    fn default() -> Self {
        Self::new()
    }
}

/// A serialized node with its hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedNode {
    /// The content hash of the node.
    pub hash: ContentHash,
    /// The serialized node data (bincode format).
    pub data: Vec<u8>,
}

impl SerializedNode {
    /// Deserializes the node data.
    pub fn deserialize(&self) -> crate::error::Result<DagNode> {
        DagNode::from_bytes(&self.data)
    }
}

/// Request to submit a new node to the relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitNodeRequest {
    /// The forum this node belongs to.
    pub forum_hash: ContentHash,
    /// The serialized node data.
    pub node_data: Vec<u8>,
}

impl SubmitNodeRequest {
    /// Creates a new submit request from a node.
    pub fn new(forum_hash: ContentHash, node: &DagNode) -> crate::error::Result<Self> {
        Ok(Self {
            forum_hash,
            node_data: node.to_bytes()?,
        })
    }

    /// Deserializes the node.
    pub fn deserialize_node(&self) -> crate::error::Result<DagNode> {
        DagNode::from_bytes(&self.node_data)
    }
}

/// Response to a submit request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitNodeResponse {
    /// Whether the node was accepted.
    pub accepted: bool,
    /// The hash of the accepted node (if accepted).
    pub node_hash: Option<ContentHash>,
    /// Error message if rejected.
    pub error: Option<String>,
}

impl SubmitNodeResponse {
    /// Creates a successful response.
    pub fn accepted(hash: ContentHash) -> Self {
        Self {
            accepted: true,
            node_hash: Some(hash),
            error: None,
        }
    }

    /// Creates a rejection response.
    pub fn rejected(error: impl Into<String>) -> Self {
        Self {
            accepted: false,
            node_hash: None,
            error: Some(error.into()),
        }
    }
}

/// Request to export an entire forum's DAG.
///
/// Used for backup or full clone operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportForumRequest {
    /// The forum hash to export.
    pub forum_hash: ContentHash,
}

impl ExportForumRequest {
    /// Creates a new export request.
    pub fn new(forum_hash: ContentHash) -> Self {
        Self { forum_hash }
    }
}

/// Response containing a forum export (paginated).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportForumResponse {
    /// The forum hash.
    pub forum_hash: ContentHash,
    /// Nodes in this page, in topological order.
    pub nodes: Vec<SerializedNode>,
    /// Total number of nodes in the forum (across all pages).
    pub total_nodes: Option<usize>,
    /// Whether there are more pages available.
    #[serde(default)]
    pub has_more: bool,
}

impl ExportForumResponse {
    /// Creates a new export response.
    pub fn new(forum_hash: ContentHash) -> Self {
        Self {
            forum_hash,
            nodes: Vec::new(),
            total_nodes: None,
            has_more: false,
        }
    }

    /// Adds nodes to the response.
    pub fn with_nodes(mut self, nodes: Vec<SerializedNode>) -> Self {
        self.total_nodes = Some(nodes.len());
        self.nodes = nodes;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hash() -> ContentHash {
        ContentHash::from_bytes([42u8; 64])
    }

    #[test]
    fn test_sync_request_creation() {
        let hash = test_hash();
        let req = SyncRequest::new(hash);

        assert_eq!(req.forum_hash, hash);
        assert!(req.known_heads.is_empty());
        assert!(req.max_results.is_none());
    }

    #[test]
    fn test_sync_request_with_heads() {
        let hash = test_hash();
        let head = ContentHash::from_bytes([1u8; 64]);
        let req = SyncRequest::with_heads(hash, vec![head]);

        assert_eq!(req.known_heads.len(), 1);
        assert_eq!(req.known_heads[0], head);
    }

    #[test]
    fn test_sync_request_with_max_results() {
        let hash = test_hash();
        let req = SyncRequest::new(hash).with_max_results(100);

        assert_eq!(req.max_results, Some(100));
    }

    #[test]
    fn test_sync_response_creation() {
        let hash = test_hash();
        let resp = SyncResponse::new(hash)
            .with_missing(vec![ContentHash::from_bytes([1u8; 64])])
            .with_has_more(true)
            .with_server_heads(vec![ContentHash::from_bytes([2u8; 64])]);

        assert_eq!(resp.forum_hash, hash);
        assert_eq!(resp.missing_hashes.len(), 1);
        assert!(resp.has_more);
        assert_eq!(resp.server_heads.len(), 1);
    }

    #[test]
    fn test_fetch_nodes_request() {
        let hashes = vec![
            ContentHash::from_bytes([1u8; 64]),
            ContentHash::from_bytes([2u8; 64]),
        ];
        let req = FetchNodesRequest::new(hashes.clone());

        assert_eq!(req.hashes.len(), 2);
    }

    #[test]
    fn test_fetch_nodes_response() {
        let mut resp = FetchNodesResponse::new();
        resp.add_node(ContentHash::from_bytes([1u8; 64]), vec![1, 2, 3]);
        resp.add_not_found(ContentHash::from_bytes([2u8; 64]));

        assert_eq!(resp.nodes.len(), 1);
        assert_eq!(resp.not_found.len(), 1);
    }

    #[test]
    fn test_submit_node_response_accepted() {
        let hash = test_hash();
        let resp = SubmitNodeResponse::accepted(hash);

        assert!(resp.accepted);
        assert_eq!(resp.node_hash, Some(hash));
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_submit_node_response_rejected() {
        let resp = SubmitNodeResponse::rejected("Invalid signature");

        assert!(!resp.accepted);
        assert!(resp.node_hash.is_none());
        assert_eq!(resp.error, Some("Invalid signature".to_string()));
    }

    #[test]
    fn test_export_forum_request() {
        let hash = test_hash();
        let req = ExportForumRequest::new(hash);

        assert_eq!(req.forum_hash, hash);
    }

    #[test]
    fn test_export_forum_response() {
        let hash = test_hash();
        let nodes = vec![SerializedNode {
            hash: ContentHash::from_bytes([1u8; 64]),
            data: vec![1, 2, 3],
        }];
        let resp = ExportForumResponse::new(hash).with_nodes(nodes);

        assert_eq!(resp.forum_hash, hash);
        assert_eq!(resp.nodes.len(), 1);
        assert_eq!(resp.total_nodes, Some(1));
    }

    #[test]
    fn test_serialized_node() {
        // This test verifies the structure exists, actual deserialization
        // is tested in integration with DagNode
        let node = SerializedNode {
            hash: test_hash(),
            data: vec![1, 2, 3],
        };

        assert_eq!(node.hash, test_hash());
        assert_eq!(node.data, vec![1, 2, 3]);
    }

    #[test]
    fn test_sync_request_serialization() {
        let req = SyncRequest::new(test_hash()).with_max_results(50);
        let bytes = bincode::serialize(&req).expect("Failed to serialize");
        let deserialized: SyncRequest =
            bincode::deserialize(&bytes).expect("Failed to deserialize");

        assert_eq!(req.forum_hash, deserialized.forum_hash);
        assert_eq!(req.max_results, deserialized.max_results);
    }

    #[test]
    fn test_sync_response_serialization() {
        let resp = SyncResponse::new(test_hash())
            .with_missing(vec![ContentHash::from_bytes([1u8; 64])])
            .with_has_more(true);
        let bytes = bincode::serialize(&resp).expect("Failed to serialize");
        let deserialized: SyncResponse =
            bincode::deserialize(&bytes).expect("Failed to deserialize");

        assert_eq!(resp.forum_hash, deserialized.forum_hash);
        assert_eq!(resp.missing_hashes.len(), deserialized.missing_hashes.len());
        assert_eq!(resp.has_more, deserialized.has_more);
    }
}
