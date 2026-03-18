const std = @import("std");
const types = @import("types.zig");
const message_handlers = @import("message_handlers.zig");
const SSHConnection = @import("sshconnection.zig");
const Alloc = std.mem.Allocator;

const Server = @This();

alloc: Alloc,
arena: std.heap.ArenaAllocator,
port: u16,
shell_name: []const u8 = "salamaShell",
protocol_version: []const u8 = "0.0.1",
supported_kex_algo: types.NameList = .{
    .names = &.{"mlkem768x25519-sha256"},
    .length = 0, //FIXME: look how we can add this better.
},
supported_host_algo: types.NameList = .{
    .names = &.{"ssh-ed25519"},
    .length = 0, //Fix Me! look how we can add this.
},
supported_encryption_algo: types.NameList = .{
    .names = &.{"chacha20-poly1305@openssh.com"},
    .length = 0, //FIXME: look how we can add this better.
},
supported_mac_algo: types.NameList = .{
    .names = &.{"hmac-sha2-256"},
    .length = 0, //FIXME: look how we can add this better.
},
supported_compression_algo: types.NameList = .{
    .names = &.{"none"},
    .length = 0, //FIXME: look how we can add this better.
},
supported_languages: types.NameList = .{
    .names = &.{},
    .length = 0,
},

const log = std.log.scoped(.SalamaShellServer);
const IoWriter = std.Io.Writer;
const IoReader = std.Io.Reader;

pub fn init(alloc: Alloc, port: ?u16) !Server {
    // var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    var port_num = port;
    if (port_num == null) {
        port_num = 22;
    }
    return .{
        .alloc = alloc,
        .arena = std.heap.ArenaAllocator.init(alloc),
        .port = port_num.?,
    };
}

pub fn arenaAlloc(self: *Server) Alloc {
    return self.arena.allocator();
}

pub fn deinit(self: *Server) void {
    self.arena.deinit();
}

pub fn listen(self: *Server) !void {
    const net = std.net;
    const address = try net.Address.parseIp("127.0.0.1", self.port);
    var server = try address.listen(.{ .reuse_address = true });
    defer server.deinit();
    log.info("SSH server started and listening at port: {d}", .{self.port});
    while (true) {
        var conn = try server.accept();
        const thread = try std.Thread.spawn(.{}, createSSHConnection, .{ self, &conn });
        thread.detach();
    }
}

fn createSSHConnection(server: *Server, connection: *std.net.Server.Connection) !void {
    var ssh_connection = try SSHConnection.init(connection, server, server.alloc);
    ssh_connection.handleConnection() catch |err| {
        log.err("Connection failed with an error of {}", .{err});
    };
}
