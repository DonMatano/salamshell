# salamShell Project Overview

## Project Goal
`salamShell` is a Work-In-Progress (WIP) SSH server implementation written in Zig (0.15.2.)

## Technology Stack
- **Language**: Zig 0.15.2
- **Build System**: Standard `build.zig` / `build.zig.zon`
- **Networking**: `std.net` (TCP listener)
- **Concurrency**: `std.Thread` (multi-threaded connection handling)

## Project Structure
The core logic resides in `src/salamShell/`, with `src/root.zig` exposing the library interface and `src/main.zig` providing a CLI entry point.

### Key Components

*   **`src/root.zig`**: The main library entry point.
*   **`src/main.zig`**: The executable entry point. Initializes a `Server` (default port 2222) and starts listening.
*   **`src/salamShell/server.zig`**: The core SSH server implementation.
    *   Manages the TCP listener loop.
    *   Uses `std.Thread` to spawn and detach a new thread for each incoming connection.
    *   Defines supported algorithms (KEX, Host Key, Encryption, MAC, Compression).
*   **`src/salamShell/sshconnection.zig`**: Manages the lifecycle of an individual SSH connection.
    *   Handles SSH Protocol Version Exchange.
    *   Orchestrates the packet flow using `BPP`.
    *   Constructs the server's `SSH_MSG_KEXINIT` payload.
    *   Dispatches messages to handlers in `message_handlers.zig`.
    *   Uses a per-connection `ArenaAllocator`.
*   **`src/salamShell/bpp.zig`**: Implements the SSH Binary Packet Protocol (RFC 4253 Section 6).
    *   `readBPPPacket`: Handles packet length, padding, and payload extraction.
    *   `writeBPPPacket`: Calculates required padding (min 4 bytes, 8-byte block alignment) and writes the packet.
*   **`src/salamShell/types.zig`**: Protocol constants and structures.
    *   `SSH_MSG`: Enum for message types.
    *   `SshPacket`: Struct for parsed packets.
    *   `NameList`: Helper for RFC 4251 name-lists.
*   **`src/salamShell/message_handlers.zig`**: Logic for specific SSH messages.
    *   `handleKexInit`: Parses client algorithm lists.
*   **`src/salamShell/kexAlgo.zig`**: Placeholder for Key Exchange algorithms (e.g., ML-KEM).

## Current Implementation Status
The project is in early development, focusing on the SSH handshake.

### Implemented
- [x] Basic TCP listener with multi-threading support.
- [x] SSH Protocol Version Exchange (RFC 4253 Section 4.2).
- [x] Binary Packet Protocol (BPP) implementation (RFC 4253 Section 6).
- [x] Reading and Writing of basic SSH packets.
- [x] Parsing of client `SSH_MSG_KEXINIT` and generation of server `SSH_MSG_KEXINIT`.

### Missing / TODO
- [ ] Key Exchange (KEX) negotiation logic (comparing client/server algorithm lists).
- [ ] Diffie-Hellman / ML-KEM exchange implementation.
- [ ] Key derivation and encryption/MAC state setup.
- [ ] Host Key management.
- [ ] User Authentication (password, public key).
- [ ] Channel and Session management.

## Architectural Notes
- **Memory Management**: The server uses a per-connection `ArenaAllocator` managed by the `SSHConnection` struct.
- **Modularity**: Protocol framing (`BPP`), connection state (`SSHConnection`), and server configuration (`Server`) are strictly separated.
- **Security**: The implementation aims to follow RFC 4253 closely, including proper padding and length validation.
