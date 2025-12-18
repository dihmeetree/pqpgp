# Forum Simulator

The PQPGP simulator is a testing tool that creates a realistic multi-user forum environment for security testing and validation.

## Overview

The simulator runs two relay instances and simulates multiple users:

- **Alice** (port 4001): Forum owner, creates forums, boards, threads, and posts
- **Bob** (port 4002): Regular user, creates threads and posts
- **Eve** (malicious): Attempts various attacks against the system

Both relays sync with each other, allowing you to observe the synchronized forum state and test federation.

## Quick Start

```bash
# Run the simulator
cargo run --release -p pqpgp-simulator

# Then connect to either relay:
# - Alice's relay: http://localhost:4001/rpc
# - Bob's relay: http://localhost:4002/rpc
```

## What It Does

### Legitimate Activity

Alice and Bob continuously generate forum activity:

- **Alice**: Creates boards (5%), threads (20%), and posts (75%)
- **Bob**: Creates threads (20%) and posts (80%)

Actions are paced with random delays (500ms-2s) to simulate realistic usage.

### Security Testing

Eve continuously attempts various attacks against Bob's relay to verify security controls. The simulator includes 26 different attack types organized by category:

#### Signature & Authentication Attacks

| Attack              | Description                                                 | Expected Result               |
| ------------------- | ----------------------------------------------------------- | ----------------------------- |
| `forge_signature`   | Sign content with wrong key while claiming another identity | Rejected (signature mismatch) |
| `replay_node`       | Submit the same node twice                                  | Rejected (duplicate)          |
| `tampered_content`  | Modify bytes after signing                                  | Rejected (signature invalid)  |
| `impersonate_owner` | Claim owner identity with different signature               | Rejected (signature mismatch) |

#### DAG Structure Attacks

| Attack                | Description                                  | Expected Result             |
| --------------------- | -------------------------------------------- | --------------------------- |
| `invalid_parent`      | Reference non-existent parent nodes          | Rejected (missing parents)  |
| `wrong_forum`         | Submit node with mismatched forum hash       | Rejected (forum mismatch)   |
| `hash_mismatch`       | Submit to wrong forum endpoint               | Rejected (forum not found)  |
| `thread_wrong_board`  | Create thread in non-existent board          | Rejected (board not found)  |
| `cross_thread_parent` | Post references parent from different thread | Rejected (invalid parent)   |
| `wrong_parent_type`   | Post claims forum genesis as parent          | Rejected (wrong node type)  |
| `excessive_parents`   | Mod action with >50 parent hashes            | Rejected (too many parents) |

#### Permission & Authorization Attacks

| Attack                      | Description                              | Expected Result           |
| --------------------------- | ---------------------------------------- | ------------------------- |
| `permission_escalation`     | Create board without moderator rights    | Rejected (unauthorized)   |
| `unauthorized_mod_action`   | Add moderator without being owner        | Rejected (not owner)      |
| `remove_owner_as_moderator` | Try to remove forum owner from mods      | Rejected (cannot remove)  |
| `cross_forum_mod_action`    | Board mod action referencing wrong forum | Rejected (forum mismatch) |

#### Edit Node Attacks

| Attack                    | Description                         | Expected Result          |
| ------------------------- | ----------------------------------- | ------------------------ |
| `unauthorized_forum_edit` | Edit forum without being owner      | Rejected (not owner)     |
| `unauthorized_board_edit` | Edit board without moderator rights | Rejected (not moderator) |
| `edit_wrong_target_type`  | Use forum edit on board target      | Rejected (type mismatch) |

#### Moderation Target Type Attacks

| Attack                   | Description                              | Expected Result          |
| ------------------------ | ---------------------------------------- | ------------------------ |
| `hide_wrong_target_type` | Use HideThread action on a post hash     | Rejected (type mismatch) |
| `action_scope_mismatch`  | Board-level action on non-existent board | Rejected (board missing) |

#### Timestamp Attacks

| Attack              | Description                       | Expected Result       |
| ------------------- | --------------------------------- | --------------------- |
| `future_timestamp`  | Submit node with future timestamp | Rejected (clock skew) |
| `ancient_timestamp` | Timestamp manipulation attack     | Rejected (signature)  |

#### Content Validation Attacks

| Attack                  | Description                  | Expected Result        |
| ----------------------- | ---------------------------- | ---------------------- |
| `oversized_content`     | Submit 10MB post content     | Rejected (size limit)  |
| `malformed_node_data`   | Submit garbage/invalid data  | Rejected (parse error) |
| `content_size_boundary` | Board name exceeds 100 chars | Rejected (size limit)  |
| `empty_content_fields`  | Thread with empty title      | Rejected (empty field) |

If any attack succeeds, the simulator **panics** to alert you of a security vulnerability.

## Connecting External Clients

### Web UI

Set the relay URL environment variable:

```bash
PQPGP_RELAY_URL=http://127.0.0.1:4001 pqpgp-web
```

**Note**: The simulator creates a new forum each run with a new hash. You'll need to join the new forum or clear your local storage from previous sessions.

### CLI / curl

List available forums:

```bash
curl -X POST http://127.0.0.1:4001/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"forum.list","params":{},"id":1}'
```

### Finding the Forum Hash

The simulator logs the full forum hash at startup:

```
[Alice] Creating forum with hash: <128-character-hex-hash>
```

Use this hash to connect from external clients.

## Architecture

```
┌─────────────────┐     sync      ┌─────────────────┐
│  Alice's Relay  │◄─────────────►│   Bob's Relay   │
│   (port 4001)   │               │   (port 4002)   │
└────────▲────────┘               └────────▲────────┘
         │                                 │
         │ submit                          │ submit/attack
         │                                 │
┌────────┴────────┐               ┌────────┴────────┐
│      Alice      │               │    Bob / Eve    │
│  (forum owner)  │               │ (user/attacker) │
└─────────────────┘               └─────────────────┘
```

- Alice submits to her own relay (port 4001)
- Bob submits to Alice's relay (content syncs to his relay)
- Eve attacks Bob's relay (tests validation on the receiving end)

## Configuration

The simulator uses temporary directories for relay data, so each run starts fresh. Key constants:

| Setting              | Value    | Description                       |
| -------------------- | -------- | --------------------------------- |
| `ALICE_RELAY_PORT`   | 4001     | Alice's relay port                |
| `BOB_RELAY_PORT`     | 4002     | Bob's relay port                  |
| `SYNC_INTERVAL_SECS` | 5        | Peer sync interval                |
| User action delay    | 500ms-2s | Random delay between user actions |
| Attack delay         | 2s-5s    | Random delay between attacks      |

## Interpreting Output

### Normal Operation

```
[Alice] Creating forum with hash: abc123...
[Alice] Forum created successfully: abc123..
[Alice] Board 'General Discussion' created: def456..
[Alice] Thread 'Welcome to PQPGP!' created: ghi789..
[Bob] Posting reply...
[Malicious] Eve attempting attack #1: forge_signature
[Malicious] Attack 'forge_signature' was correctly BLOCKED
```

### Security Vulnerability Detected

If you see:

```
[SECURITY VULNERABILITY] Attack 'xxx' was NOT blocked! This indicates a security flaw.
```

The simulator will panic. This means a security control is broken and needs investigation.

## Rate Limiting

The relay has rate limiting (50 requests per 10 seconds). If you see rate limit errors:

```
[Bob] Failed to create post: HTTP 429: Rate limit exceeded. Please slow down.
```

This is expected behavior when load is high. The simulator's pacing should generally stay under the limit.
