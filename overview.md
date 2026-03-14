<!-- 
    AI AGENT OVERVIEW
    This file is intended to provide a high-level overview of the salamShell project for future AI agents.
    It summarizes the project goals, architecture, and current implementation status.
-->

# salamShell Project Overview

## Project Goal
salamShell is a Work-In-Progress (WIP) SSH server implementation written in Zig.
Its primary objective is to serve as a library for handling SSH connections.

## Technology Stack
- **Language**: Zig 0.15.2
- **Build System**: standard `build.zig`
- **Networking**: `std.net` (TCP listener)

## Project Structure
The core logic resides in `src/salamShell/`, with `src/root.zig` exposing the library interface and `src/main.zig` providing a CLI entry point.

### Key Components

*   **`src/root.zig`**: The main library entry point. Exposes `initSalamShellServer` to create a `Server` instance.
*   **`src/main.zig`**: The executable entry point. Initializes a `Server` on port 2222 (default) and starts listening.
*   **`src/salamShell/server.zig`**: The core SSH server implementation.
    *   Manages the TCP listener loop.
    *   Handles the initial SSH protocol version exchange (`SSH-2.0-salamShell_0.1`).
    *   Implements the main packet processing loop (`handleMessage`).
    *   Uses an `ArenaAllocator` per connection/operation for memory efficiency.
*   **`src/salamShell/types.zig`**: Defines SSH protocol constants and data structures.
    *   `SSH_MSG`: Enumeration of SSH message types (e.g., `KEXINIT`, `USERAUTH_REQUEST`).
    *   `SshPacket`: Struct for parsing SSH packet headers (length, padding) and payload.
    *   `NameList`: Helper for handling SSH name-lists.
*   **`src/salamShell/message_handlers.zig`**: Contains logic for handling specific SSH messages.
    *   Currently implements `handleKexInit` for parsing the client's key exchange initialization.
*   **`src/salamShell/kexAlgo.zig`**: Placeholder for Key Exchange (KEX) algorithms (e.g., ML-KEM).

## Current Implementation Status
The project is in the early stages of development (WIP).

### Implemented
-   [x] Basic TCP listener setup.
-   [x] SSH Protocol Version Exchange.
-   [x] Basic SSH Packet Parsing (length, padding, payload extraction).
-   [x] Initial handling of `SSH_MSG_KEXINIT` (parsing client algorithms).

### Missing / TODO
-   [ ] Full Key Exchange (KEX) negotiation logic.
-   [ ] Host Key support (loading/generating).
-   [ ] User Authentication (password, public key).
-   [ ] Session Channel establishment.
-   [ ] Shell execution / Command handling.

## Architectural Notes
-   The server uses a modular design, separating protocol definitions (`types.zig`) from logic (`server.zig`, `message_handlers.zig`).
-   Memory management relies on Zig's allocators, specifically `ArenaAllocator` for request lifecycles.
-   Future development should focus on completing the SSH handshake (KEX + Auth) before implementing the git-specific logic.
