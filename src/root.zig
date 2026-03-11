//! By convention, root.zig is the root source file when making a library.
const std = @import("std");
const SalamShell = @import("salamShell/salamShell.zig");

pub fn initSalamShellServer(alloc: std.mem.Allocator) !SalamShell.Server {
    const server = try SalamShell.Server.init(alloc);
    return server;
}
