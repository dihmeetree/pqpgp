//! Client-side storage for forum DAG data.
//!
//! This module provides persistent storage for forum nodes on the client side.
//! The storage is organized to enable efficient:
//! - Node lookup by content hash
//! - Listing nodes by type and parent
//! - Sync operations (finding heads, missing nodes)
//!
//! ## Directory Structure
//!
//! ```text
//! pqpgp_forum_data/
//! ├── nodes/
//! │   └── ab/                      # First byte of hash (hex)
//! │       └── ab12cd34...node      # Full hash, serialized DagNode
//! ├── indexes/
//! │   ├── forums.idx               # List of all forum hashes
//! │   ├── boards/
//! │   │   └── {forum_hash}.idx     # Boards in a forum
//! │   ├── threads/
//! │   │   └── {board_hash}.idx     # Threads in a board
//! │   └── posts/
//! │       └── {thread_hash}.idx    # Posts in a thread
//! └── heads/
//!     └── {forum_hash}.heads       # Current DAG heads for sync
//! ```

use crate::error::Result;
use crate::forum::{BoardGenesis, ContentHash, DagNode, ForumGenesis, Post, ThreadRoot};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

/// Storage manager for forum DAG data.
#[derive(Debug)]
pub struct ForumStorage {
    /// Root directory for forum data.
    root_dir: PathBuf,
}

impl ForumStorage {
    /// Creates a new storage manager with the given root directory.
    ///
    /// Creates the directory structure if it doesn't exist.
    pub fn new(root_dir: impl AsRef<Path>) -> Result<Self> {
        let root_dir = root_dir.as_ref().to_path_buf();

        // Create directory structure
        fs::create_dir_all(root_dir.join("nodes"))?;
        fs::create_dir_all(root_dir.join("indexes/boards"))?;
        fs::create_dir_all(root_dir.join("indexes/threads"))?;
        fs::create_dir_all(root_dir.join("indexes/posts"))?;
        fs::create_dir_all(root_dir.join("heads"))?;

        Ok(Self { root_dir })
    }

    /// Returns the path for a node file.
    fn node_path(&self, hash: &ContentHash) -> PathBuf {
        let hex = hash.to_hex();
        let prefix = &hex[..2];
        self.root_dir
            .join("nodes")
            .join(prefix)
            .join(format!("{}.node", hex))
    }

    /// Returns the path for the forums index.
    fn forums_index_path(&self) -> PathBuf {
        self.root_dir.join("indexes/forums.idx")
    }

    /// Returns the path for a forum's boards index.
    fn boards_index_path(&self, forum_hash: &ContentHash) -> PathBuf {
        self.root_dir
            .join("indexes/boards")
            .join(format!("{}.idx", forum_hash.to_hex()))
    }

    /// Returns the path for a board's threads index.
    fn threads_index_path(&self, board_hash: &ContentHash) -> PathBuf {
        self.root_dir
            .join("indexes/threads")
            .join(format!("{}.idx", board_hash.to_hex()))
    }

    /// Returns the path for a thread's posts index.
    fn posts_index_path(&self, thread_hash: &ContentHash) -> PathBuf {
        self.root_dir
            .join("indexes/posts")
            .join(format!("{}.idx", thread_hash.to_hex()))
    }

    /// Returns the path for a forum's heads file.
    fn heads_path(&self, forum_hash: &ContentHash) -> PathBuf {
        self.root_dir
            .join("heads")
            .join(format!("{}.heads", forum_hash.to_hex()))
    }

    /// Stores a node in the storage.
    ///
    /// Also updates relevant indexes.
    pub fn store_node(&self, node: &DagNode) -> Result<()> {
        let hash = node.hash();
        let path = self.node_path(hash);

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Serialize and write node
        let bytes = node.to_bytes()?;
        let mut file = BufWriter::new(File::create(&path)?);
        file.write_all(&bytes)?;

        // Update indexes
        self.update_indexes(node)?;

        Ok(())
    }

    /// Updates indexes for a node.
    fn update_indexes(&self, node: &DagNode) -> Result<()> {
        match node {
            DagNode::ForumGenesis(forum) => {
                self.append_to_index(&self.forums_index_path(), forum.hash())?;
            }
            DagNode::BoardGenesis(board) => {
                self.append_to_index(&self.boards_index_path(board.forum_hash()), board.hash())?;
            }
            DagNode::ThreadRoot(thread) => {
                self.append_to_index(&self.threads_index_path(thread.board_hash()), thread.hash())?;
            }
            DagNode::Post(post) => {
                self.append_to_index(&self.posts_index_path(post.thread_hash()), post.hash())?;
            }
            DagNode::ModAction(_) => {
                // Moderation actions are not indexed separately
            }
            DagNode::Edit(_) => {
                // Edit nodes are not indexed separately - they're applied when displaying content
            }
        }
        Ok(())
    }

    /// Appends a hash to an index file.
    fn append_to_index(&self, path: &Path, hash: &ContentHash) -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(file, "{}", hash.to_hex())?;
        Ok(())
    }

    /// Reads hashes from an index file.
    fn read_index(&self, path: &Path) -> Result<Vec<ContentHash>> {
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut hashes = Vec::new();

        for line in reader.lines() {
            let line = line?;
            let hash = ContentHash::from_hex(&line)?;
            hashes.push(hash);
        }

        Ok(hashes)
    }

    /// Loads a node by its content hash.
    pub fn load_node(&self, hash: &ContentHash) -> Result<Option<DagNode>> {
        let path = self.node_path(hash);
        if !path.exists() {
            return Ok(None);
        }

        let bytes = fs::read(&path)?;
        let node = DagNode::from_bytes(&bytes)?;
        Ok(Some(node))
    }

    /// Checks if a node exists in storage.
    pub fn node_exists(&self, hash: &ContentHash) -> bool {
        self.node_path(hash).exists()
    }

    /// Lists all forum hashes.
    pub fn list_forums(&self) -> Result<Vec<ContentHash>> {
        self.read_index(&self.forums_index_path())
    }

    /// Lists all board hashes in a forum.
    pub fn list_boards(&self, forum_hash: &ContentHash) -> Result<Vec<ContentHash>> {
        self.read_index(&self.boards_index_path(forum_hash))
    }

    /// Lists all thread hashes in a board.
    pub fn list_threads(&self, board_hash: &ContentHash) -> Result<Vec<ContentHash>> {
        self.read_index(&self.threads_index_path(board_hash))
    }

    /// Lists all post hashes in a thread.
    pub fn list_posts(&self, thread_hash: &ContentHash) -> Result<Vec<ContentHash>> {
        self.read_index(&self.posts_index_path(thread_hash))
    }

    /// Loads a forum by hash.
    pub fn load_forum(&self, hash: &ContentHash) -> Result<Option<ForumGenesis>> {
        let node = self.load_node(hash)?;
        Ok(node.and_then(|n| n.as_forum_genesis().cloned()))
    }

    /// Loads a board by hash.
    pub fn load_board(&self, hash: &ContentHash) -> Result<Option<BoardGenesis>> {
        let node = self.load_node(hash)?;
        Ok(node.and_then(|n| n.as_board_genesis().cloned()))
    }

    /// Loads a thread by hash.
    pub fn load_thread(&self, hash: &ContentHash) -> Result<Option<ThreadRoot>> {
        let node = self.load_node(hash)?;
        Ok(node.and_then(|n| n.as_thread_root().cloned()))
    }

    /// Loads a post by hash.
    pub fn load_post(&self, hash: &ContentHash) -> Result<Option<Post>> {
        let node = self.load_node(hash)?;
        Ok(node.and_then(|n| n.as_post().cloned()))
    }

    /// Gets the current heads for a forum's DAG.
    ///
    /// Heads are the latest nodes that have no children yet.
    pub fn get_heads(&self, forum_hash: &ContentHash) -> Result<HashSet<ContentHash>> {
        let path = self.heads_path(forum_hash);
        if !path.exists() {
            return Ok(HashSet::new());
        }

        let hashes = self.read_index(&path)?;
        Ok(hashes.into_iter().collect())
    }

    /// Updates the heads for a forum's DAG.
    pub fn set_heads(&self, forum_hash: &ContentHash, heads: &HashSet<ContentHash>) -> Result<()> {
        let path = self.heads_path(forum_hash);
        let mut file = BufWriter::new(File::create(path)?);
        for hash in heads {
            writeln!(file, "{}", hash.to_hex())?;
        }
        Ok(())
    }

    /// Loads all nodes from storage into memory.
    ///
    /// This is useful for building complete DAG state.
    pub fn load_all_nodes(&self) -> Result<HashMap<ContentHash, DagNode>> {
        let mut nodes = HashMap::new();
        let nodes_dir = self.root_dir.join("nodes");

        if !nodes_dir.exists() {
            return Ok(nodes);
        }

        // Iterate through prefix directories
        for prefix_entry in fs::read_dir(&nodes_dir)? {
            let prefix_entry = prefix_entry?;
            if !prefix_entry.file_type()?.is_dir() {
                continue;
            }

            // Iterate through node files
            for node_entry in fs::read_dir(prefix_entry.path())? {
                let node_entry = node_entry?;
                let path = node_entry.path();

                if path.extension().and_then(|e| e.to_str()) != Some("node") {
                    continue;
                }

                let bytes = fs::read(&path)?;
                let node = DagNode::from_bytes(&bytes)?;
                nodes.insert(*node.hash(), node);
            }
        }

        Ok(nodes)
    }

    /// Loads all nodes for a specific forum.
    pub fn load_forum_nodes(&self, forum_hash: &ContentHash) -> Result<Vec<DagNode>> {
        let mut nodes = Vec::new();

        // Load forum genesis
        if let Some(forum) = self.load_forum(forum_hash)? {
            nodes.push(DagNode::from(forum));
        } else {
            return Ok(nodes);
        }

        // Load boards
        for board_hash in self.list_boards(forum_hash)? {
            if let Some(board) = self.load_board(&board_hash)? {
                nodes.push(DagNode::from(board));

                // Load threads
                for thread_hash in self.list_threads(&board_hash)? {
                    if let Some(thread) = self.load_thread(&thread_hash)? {
                        nodes.push(DagNode::from(thread));

                        // Load posts
                        for post_hash in self.list_posts(&thread_hash)? {
                            if let Some(post) = self.load_post(&post_hash)? {
                                nodes.push(DagNode::from(post));
                            }
                        }
                    }
                }
            }
        }

        Ok(nodes)
    }

    /// Returns the root directory path.
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// Deletes all stored data.
    ///
    /// Use with caution!
    pub fn clear(&self) -> Result<()> {
        if self.root_dir.exists() {
            fs::remove_dir_all(&self.root_dir)?;
        }
        // Recreate directory structure
        fs::create_dir_all(self.root_dir.join("nodes"))?;
        fs::create_dir_all(self.root_dir.join("indexes/boards"))?;
        fs::create_dir_all(self.root_dir.join("indexes/threads"))?;
        fs::create_dir_all(self.root_dir.join("indexes/posts"))?;
        fs::create_dir_all(self.root_dir.join("heads"))?;
        Ok(())
    }

    /// Removes a specific forum and all its data from local storage.
    ///
    /// This removes:
    /// - The forum genesis node
    /// - All boards, threads, and posts in the forum
    /// - The forum's heads file
    /// - Index entries for the forum
    pub fn remove_forum(&self, forum_hash: &ContentHash) -> Result<()> {
        // Load all nodes for this forum so we can delete them
        let forum_nodes = self.load_forum_nodes(forum_hash)?;

        // Delete each node file
        for node in &forum_nodes {
            let path = self.node_path(node.hash());
            if path.exists() {
                fs::remove_file(&path)?;
            }
        }

        // Delete board indexes for this forum
        let boards_index_path = self.boards_index_path(forum_hash);
        if boards_index_path.exists() {
            // First get board hashes to delete their thread indexes
            let board_hashes = self.read_index(&boards_index_path)?;
            for board_hash in &board_hashes {
                // Delete thread indexes for this board
                let threads_index_path = self.threads_index_path(board_hash);
                if threads_index_path.exists() {
                    // Get thread hashes to delete their post indexes
                    let thread_hashes = self.read_index(&threads_index_path)?;
                    for thread_hash in &thread_hashes {
                        let posts_index_path = self.posts_index_path(thread_hash);
                        if posts_index_path.exists() {
                            fs::remove_file(&posts_index_path)?;
                        }
                    }
                    fs::remove_file(&threads_index_path)?;
                }
            }
            fs::remove_file(&boards_index_path)?;
        }

        // Delete heads file
        let heads_path = self.heads_path(forum_hash);
        if heads_path.exists() {
            fs::remove_file(&heads_path)?;
        }

        // Remove forum from forums.idx
        let forums_index_path = self.forums_index_path();
        if forums_index_path.exists() {
            let forums = self.read_index(&forums_index_path)?;
            let filtered: Vec<_> = forums.iter().filter(|h| *h != forum_hash).collect();
            let mut file = BufWriter::new(File::create(&forums_index_path)?);
            for hash in filtered {
                writeln!(file, "{}", hash.to_hex())?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use tempfile::TempDir;

    fn create_test_keypair() -> KeyPair {
        KeyPair::generate_mldsa87().expect("Failed to generate keypair")
    }

    fn create_test_storage() -> (ForumStorage, TempDir) {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let storage = ForumStorage::new(temp_dir.path().join("forum_data"))
            .expect("Failed to create storage");
        (storage, temp_dir)
    }

    fn create_test_forum(keypair: &KeyPair) -> ForumGenesis {
        ForumGenesis::create(
            "Test Forum".to_string(),
            "A test forum".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create forum")
    }

    #[test]
    fn test_storage_creation() {
        let (storage, _temp_dir) = create_test_storage();
        assert!(storage.root_dir().exists());
        assert!(storage.root_dir().join("nodes").exists());
        assert!(storage.root_dir().join("indexes").exists());
    }

    #[test]
    fn test_store_and_load_forum() {
        let (storage, _temp_dir) = create_test_storage();
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        // Store
        storage
            .store_node(&DagNode::from(forum.clone()))
            .expect("Failed to store forum");

        // Load
        let loaded = storage
            .load_forum(forum.hash())
            .expect("Failed to load forum")
            .expect("Forum not found");

        assert_eq!(forum.name(), loaded.name());
        assert_eq!(forum.hash(), loaded.hash());
    }

    #[test]
    fn test_store_and_load_board() {
        let (storage, _temp_dir) = create_test_storage();
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        let board = BoardGenesis::create(
            *forum.hash(),
            "Test Board".to_string(),
            "A test board".to_string(),
            vec!["tag1".to_string()],
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create board");

        storage.store_node(&DagNode::from(forum.clone())).unwrap();
        storage.store_node(&DagNode::from(board.clone())).unwrap();

        let loaded = storage
            .load_board(board.hash())
            .unwrap()
            .expect("Board not found");

        assert_eq!(board.name(), loaded.name());
    }

    #[test]
    fn test_list_forums() {
        let (storage, _temp_dir) = create_test_storage();
        let keypair = create_test_keypair();

        let forum1 = create_test_forum(&keypair);
        let forum2 = create_test_forum(&keypair);

        storage.store_node(&DagNode::from(forum1.clone())).unwrap();
        storage.store_node(&DagNode::from(forum2.clone())).unwrap();

        let forums = storage.list_forums().unwrap();
        assert_eq!(forums.len(), 2);
        assert!(forums.contains(forum1.hash()));
        assert!(forums.contains(forum2.hash()));
    }

    #[test]
    fn test_list_boards() {
        let (storage, _temp_dir) = create_test_storage();
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        let board1 = BoardGenesis::create(
            *forum.hash(),
            "Board 1".to_string(),
            "".to_string(),
            vec![],
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        let board2 = BoardGenesis::create(
            *forum.hash(),
            "Board 2".to_string(),
            "".to_string(),
            vec![],
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        storage.store_node(&DagNode::from(forum.clone())).unwrap();
        storage.store_node(&DagNode::from(board1.clone())).unwrap();
        storage.store_node(&DagNode::from(board2.clone())).unwrap();

        let boards = storage.list_boards(forum.hash()).unwrap();
        assert_eq!(boards.len(), 2);
    }

    #[test]
    fn test_node_exists() {
        let (storage, _temp_dir) = create_test_storage();
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        assert!(!storage.node_exists(forum.hash()));
        storage.store_node(&DagNode::from(forum.clone())).unwrap();
        assert!(storage.node_exists(forum.hash()));
    }

    #[test]
    fn test_heads() {
        let (storage, _temp_dir) = create_test_storage();
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        let head1 = ContentHash::from_bytes([1u8; 64]);
        let head2 = ContentHash::from_bytes([2u8; 64]);

        let mut heads = HashSet::new();
        heads.insert(head1);
        heads.insert(head2);

        storage.set_heads(forum.hash(), &heads).unwrap();
        let loaded_heads = storage.get_heads(forum.hash()).unwrap();

        assert_eq!(heads, loaded_heads);
    }

    #[test]
    fn test_load_all_nodes() {
        let (storage, _temp_dir) = create_test_storage();
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        let board = BoardGenesis::create(
            *forum.hash(),
            "Board".to_string(),
            "".to_string(),
            vec![],
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        storage.store_node(&DagNode::from(forum.clone())).unwrap();
        storage.store_node(&DagNode::from(board.clone())).unwrap();

        let all_nodes = storage.load_all_nodes().unwrap();
        assert_eq!(all_nodes.len(), 2);
        assert!(all_nodes.contains_key(forum.hash()));
        assert!(all_nodes.contains_key(board.hash()));
    }

    #[test]
    fn test_load_forum_nodes() {
        let (storage, _temp_dir) = create_test_storage();
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        let board = BoardGenesis::create(
            *forum.hash(),
            "Board".to_string(),
            "".to_string(),
            vec![],
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        let thread = ThreadRoot::create(
            *board.hash(),
            "Thread".to_string(),
            "Body".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        let post = Post::create(
            *thread.hash(),
            vec![],
            "Post body".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        storage.store_node(&DagNode::from(forum.clone())).unwrap();
        storage.store_node(&DagNode::from(board)).unwrap();
        storage.store_node(&DagNode::from(thread)).unwrap();
        storage.store_node(&DagNode::from(post)).unwrap();

        let nodes = storage.load_forum_nodes(forum.hash()).unwrap();
        assert_eq!(nodes.len(), 4);
    }

    #[test]
    fn test_clear_storage() {
        let (storage, _temp_dir) = create_test_storage();
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        storage.store_node(&DagNode::from(forum.clone())).unwrap();
        assert!(storage.node_exists(forum.hash()));

        storage.clear().unwrap();
        assert!(!storage.node_exists(forum.hash()));
        assert!(storage.root_dir().join("nodes").exists());
    }
}
