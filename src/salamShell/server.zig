const std = @import("std");
const Alloc = std.mem.Allocator;

const Server = @This();

alloc: Alloc,
arena: *std.heap.ArenaAllocator,

pub fn init(alloc: Alloc) !Server {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    return .{
        .alloc = alloc,
        .arena = &arena,
    };
}

pub fn deinit(self: *Server) void {
    self.arena.deinit();
}
