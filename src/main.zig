const std = @import("std");
const salamShell = @import("salamShell");

pub fn main() !void {
    // Prints to stderr, ignoring potential errors.
    var debugAllocator = std.heap.GeneralPurposeAllocator(.{}).init;
    defer std.debug.assert(debugAllocator.deinit() == .ok);
    const alloc = debugAllocator.allocator();
    var server = try salamShell.initSalamShellServer(alloc);
    server.deinit();
}
