//! HTTP handlers for forum DAG sync protocol.
//!
//! The relay is a content-addressed DAG storage node. It provides:
//! - **Sync**: Compute missing nodes between client and server
//! - **Fetch**: Retrieve nodes by hash
//! - **Submit**: Accept new validated nodes
//! - **Export**: Bulk export for initial sync
//!
//! The relay does NOT provide application-level views (threads, posts, boards).
//! Clients sync the raw DAG and build their own local views.
//!
//! ## Security
//!
//! - Batch size limits prevent DoS
//! - Content size limits enforced
//! - Cryptographic validation on all submitted nodes
//! - Global resource limits (max forums, max nodes per forum)

use super::persistence::PersistentForumState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use pqpgp::forum::constants::{
    MAX_EXPORT_PAGE_SIZE, MAX_FETCH_BATCH_SIZE, MAX_NODES_PER_FORUM, MAX_SYNC_MISSING_HASHES,
};
use pqpgp::forum::permissions::ForumPermissions;
use pqpgp::forum::types::current_timestamp_millis;
use pqpgp::forum::{
    validate_content_limits, validate_node, ContentHash, DagNode, ExportForumResponse,
    FetchNodesRequest, FetchNodesResponse, ForumGenesis, SerializedNode, SubmitNodeRequest,
    SubmitNodeResponse, SyncRequest, SyncResponse, ValidationContext,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::{error, info, instrument, warn};

// =============================================================================
// RwLock Helpers
// =============================================================================

/// Acquires a read lock, recovering from poison if necessary.
fn acquire_read_lock(
    state: &RwLock<PersistentForumState>,
) -> RwLockReadGuard<'_, PersistentForumState> {
    state.read().unwrap_or_else(|poisoned| {
        error!("RwLock was poisoned on read, recovering");
        poisoned.into_inner()
    })
}

/// Acquires a write lock, recovering from poison if necessary.
fn acquire_write_lock(
    state: &RwLock<PersistentForumState>,
) -> RwLockWriteGuard<'_, PersistentForumState> {
    state.write().unwrap_or_else(|poisoned| {
        error!("RwLock was poisoned on write, recovering");
        poisoned.into_inner()
    })
}

// =============================================================================
// Types
// =============================================================================

/// Thread-safe forum state.
pub type SharedForumState = Arc<RwLock<PersistentForumState>>;

/// Forum info returned in list responses.
#[derive(Debug, Serialize)]
pub struct ForumInfo {
    pub hash: String,
    pub name: String,
    pub node_count: usize,
    pub created_at: u64,
}

/// Query parameters for export pagination.
#[derive(Debug, Deserialize)]
pub struct ExportParams {
    /// Page number (0-indexed). Default: 0
    #[serde(default)]
    pub page: usize,
    /// Page size. Default and max: [`MAX_EXPORT_PAGE_SIZE`]
    pub page_size: Option<usize>,
}

// =============================================================================
// Core DAG Sync Endpoints
// =============================================================================

/// List all forums hosted on this relay.
///
/// Returns minimal info for discovery. Clients should sync the full DAG
/// to get complete forum details.
#[instrument(skip(state))]
pub async fn list_forums(State(state): State<SharedForumState>) -> impl IntoResponse {
    let relay = acquire_read_lock(&state);

    let forums: Vec<ForumInfo> = relay
        .forums()
        .iter()
        .map(|(hash, forum)| {
            // Get original name from genesis (no edit resolution - that's client-side)
            let name = forum
                .nodes
                .get(hash)
                .and_then(|n| {
                    if let DagNode::ForumGenesis(g) = n {
                        Some(g.name().to_string())
                    } else {
                        None
                    }
                })
                .unwrap_or_default();

            ForumInfo {
                hash: hash.to_hex(),
                name,
                node_count: forum.node_count(),
                created_at: forum.created_at,
            }
        })
        .collect();

    info!("Listed {} forums", forums.len());
    Json(forums)
}

/// Sync request - client sends known heads, server returns missing hashes.
///
/// This is the core sync protocol endpoint. Clients call this to discover
/// what nodes they need to fetch.
#[instrument(skip(state, request))]
pub async fn sync_forum(
    State(state): State<SharedForumState>,
    Json(request): Json<SyncRequest>,
) -> impl IntoResponse {
    let relay = acquire_read_lock(&state);

    let forum = match relay.get_forum(&request.forum_hash) {
        Some(f) => f,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(SyncResponse::new(request.forum_hash)),
            );
        }
    };

    // Compute what the client is missing
    let mut missing = forum.compute_missing_nodes(&request.known_heads);

    // Apply limits
    let client_max = request.max_results.unwrap_or(MAX_SYNC_MISSING_HASHES);
    let effective_max = client_max.min(MAX_SYNC_MISSING_HASHES);

    let has_more = if missing.len() > effective_max {
        missing.truncate(effective_max);
        true
    } else {
        false
    };

    let server_heads: Vec<ContentHash> = forum.heads.iter().copied().collect();

    info!(
        "Sync forum {}: client has {} heads, missing {} nodes (has_more={})",
        request.forum_hash.short(),
        request.known_heads.len(),
        missing.len(),
        has_more
    );

    let response = SyncResponse::new(request.forum_hash)
        .with_missing(missing)
        .with_has_more(has_more)
        .with_server_heads(server_heads);

    (StatusCode::OK, Json(response))
}

/// Fetch nodes by hash.
///
/// Limited to [`MAX_FETCH_BATCH_SIZE`] hashes per request.
#[instrument(skip(state, request))]
pub async fn fetch_nodes(
    State(state): State<SharedForumState>,
    Json(request): Json<FetchNodesRequest>,
) -> impl IntoResponse {
    if request.hashes.len() > MAX_FETCH_BATCH_SIZE {
        warn!(
            "Fetch request rejected: {} hashes exceeds limit of {}",
            request.hashes.len(),
            MAX_FETCH_BATCH_SIZE
        );
        return (StatusCode::BAD_REQUEST, Json(FetchNodesResponse::new()));
    }

    // Deduplicate
    let unique_hashes: HashSet<ContentHash> = request.hashes.iter().copied().collect();

    let relay = acquire_read_lock(&state);
    let mut response = FetchNodesResponse::new();

    for hash in unique_hashes {
        let mut found = false;
        for forum in relay.forums().values() {
            if let Some(node) = forum.nodes.get(&hash) {
                match node.to_bytes() {
                    Ok(data) => {
                        response.add_node(hash, data);
                        found = true;
                        break;
                    }
                    Err(_) => {
                        response.add_not_found(hash);
                        found = true;
                        break;
                    }
                }
            }
        }
        if !found {
            response.add_not_found(hash);
        }
    }

    info!(
        "Fetch: {} requested, {} found, {} not found",
        request.hashes.len(),
        response.nodes.len(),
        response.not_found.len()
    );

    (StatusCode::OK, Json(response))
}

/// Submit a new node.
///
/// The node is validated (signature, hash, permissions) before acceptance.
/// ForumGenesis nodes create new forums; other nodes are added to existing forums.
#[instrument(skip(state, request))]
pub async fn submit_node(
    State(state): State<SharedForumState>,
    Json(request): Json<SubmitNodeRequest>,
) -> impl IntoResponse {
    // Deserialize
    let node = match DagNode::from_bytes(&request.node_data) {
        Ok(n) => n,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SubmitNodeResponse::rejected(format!(
                    "Invalid node data: {}",
                    e
                ))),
            );
        }
    };

    let node_hash = *node.hash();

    // Check content limits first (cheap)
    if let Some(error) = validate_content_limits(&node) {
        warn!("Node {} rejected: {}", node_hash.short(), error);
        return (
            StatusCode::BAD_REQUEST,
            Json(SubmitNodeResponse::rejected(error)),
        );
    }

    // Handle ForumGenesis specially - it creates a new forum
    if let DagNode::ForumGenesis(ref genesis) = node {
        return handle_forum_genesis_submit(state, genesis.clone()).await;
    }

    // For all other nodes, add to existing forum
    let mut relay = acquire_write_lock(&state);

    // Validate against forum state
    let validation_result = {
        let forum = match relay.get_forum(&request.forum_hash) {
            Some(f) => f,
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(SubmitNodeResponse::rejected("Forum not found")),
                );
            }
        };

        // Check node limit
        if forum.node_count() >= MAX_NODES_PER_FORUM {
            warn!(
                "Node rejected: forum {} at capacity ({} nodes)",
                request.forum_hash.short(),
                MAX_NODES_PER_FORUM
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(SubmitNodeResponse::rejected(format!(
                    "Forum at capacity ({} nodes)",
                    MAX_NODES_PER_FORUM
                ))),
            );
        }

        // Build validation context
        let permissions: HashMap<ContentHash, ForumPermissions> = forum
            .permissions
            .as_ref()
            .map(|p| {
                let mut map = HashMap::new();
                map.insert(request.forum_hash, p.clone());
                map
            })
            .unwrap_or_default();

        let ctx = ValidationContext::new(&forum.nodes, &permissions, current_timestamp_millis());
        validate_node(&node, &ctx)
    };

    match validation_result {
        Ok(result) if !result.is_valid => {
            warn!("Node {} rejected: {:?}", node_hash.short(), result.errors);
            return (
                StatusCode::BAD_REQUEST,
                Json(SubmitNodeResponse::rejected(format!(
                    "Validation failed: {:?}",
                    result.errors
                ))),
            );
        }
        Err(e) => {
            warn!("Node {} validation error: {}", node_hash.short(), e);
            return (
                StatusCode::BAD_REQUEST,
                Json(SubmitNodeResponse::rejected(format!(
                    "Validation error: {}",
                    e
                ))),
            );
        }
        _ => {}
    }

    // Add node
    match relay.add_node(&request.forum_hash, node.clone()) {
        Ok(added) => {
            if added {
                info!(
                    "Accepted node {} ({:?}) for forum {}",
                    node_hash.short(),
                    node.node_type(),
                    request.forum_hash.short()
                );
            }
            (
                StatusCode::OK,
                Json(SubmitNodeResponse::accepted(node_hash)),
            )
        }
        Err(e) => {
            warn!("Failed to add node {}: {}", node_hash.short(), e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SubmitNodeResponse::rejected(format!(
                    "Failed to add node: {}",
                    e
                ))),
            )
        }
    }
}

/// Handle ForumGenesis submission (creates a new forum).
async fn handle_forum_genesis_submit(
    state: SharedForumState,
    genesis: ForumGenesis,
) -> (StatusCode, Json<SubmitNodeResponse>) {
    // Validate genesis
    let empty_nodes = HashMap::new();
    let empty_perms = HashMap::new();
    let ctx = ValidationContext::new(&empty_nodes, &empty_perms, current_timestamp_millis());

    match validate_node(&DagNode::from(genesis.clone()), &ctx) {
        Ok(result) if !result.is_valid => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SubmitNodeResponse::rejected(format!(
                    "Validation failed: {:?}",
                    result.errors
                ))),
            );
        }
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SubmitNodeResponse::rejected(format!(
                    "Validation error: {}",
                    e
                ))),
            );
        }
        _ => {}
    }

    // Create forum
    let mut relay = acquire_write_lock(&state);
    match relay.create_forum(genesis.clone()) {
        Ok(hash) => {
            info!(
                "Created forum '{}' with hash {}",
                genesis.name(),
                hash.short()
            );
            (
                StatusCode::CREATED,
                Json(SubmitNodeResponse::accepted(hash)),
            )
        }
        Err(e) => (StatusCode::CONFLICT, Json(SubmitNodeResponse::rejected(e))),
    }
}

/// Export a forum's DAG with pagination.
///
/// Used for initial sync when a client has no nodes.
#[instrument(skip(state))]
pub async fn export_forum(
    State(state): State<SharedForumState>,
    Path(hash_hex): Path<String>,
    Query(params): Query<ExportParams>,
) -> impl IntoResponse {
    let hash = match ContentHash::from_hex(&hash_hex) {
        Ok(h) => h,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ExportForumResponse::new(ContentHash::from_bytes([0u8; 64]))),
            );
        }
    };

    let relay = acquire_read_lock(&state);

    let forum = match relay.get_forum(&hash) {
        Some(f) => f,
        None => {
            return (StatusCode::NOT_FOUND, Json(ExportForumResponse::new(hash)));
        }
    };

    // Pagination
    let page_size = params
        .page_size
        .unwrap_or(MAX_EXPORT_PAGE_SIZE)
        .min(MAX_EXPORT_PAGE_SIZE);
    let skip = match params.page.checked_mul(page_size) {
        Some(s) => s,
        None => return (StatusCode::OK, Json(ExportForumResponse::new(hash))),
    };

    let all_nodes: Vec<&DagNode> = forum.nodes_in_order();
    let total_nodes = all_nodes.len();

    let mut nodes = Vec::new();
    for node in all_nodes.into_iter().skip(skip).take(page_size) {
        if let Ok(data) = node.to_bytes() {
            nodes.push(SerializedNode {
                hash: *node.hash(),
                data,
            });
        }
    }

    let has_more = skip + nodes.len() < total_nodes;

    info!(
        "Export forum {} page {} ({} nodes, has_more={})",
        hash.short(),
        params.page,
        nodes.len(),
        has_more
    );

    let mut response = ExportForumResponse::new(hash).with_nodes(nodes);
    response.has_more = has_more;
    response.total_nodes = Some(total_nodes);
    (StatusCode::OK, Json(response))
}

/// Relay statistics.
#[instrument(skip(state))]
pub async fn stats(State(state): State<SharedForumState>) -> impl IntoResponse {
    let relay = acquire_read_lock(&state);

    Json(serde_json::json!({
        "total_forums": relay.forums().len(),
        "total_nodes": relay.total_nodes()
    }))
}
