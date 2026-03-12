const std = @import("std");
const Alloc = std.mem.Allocator;

const Server = @This();

alloc: Alloc,
arena: std.heap.ArenaAllocator,
port: u16,

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

pub fn deinit(self: *Server) void {
    self.arena.deinit();
}

pub fn listen(self: Server) !void {
    const net = std.net;
    var readBuffer: [4096]u8 = undefined;
    var writeBuffer: [4096]u8 = undefined;
    const address = try net.Address.parseIp("127.0.0.1", self.port);
    var server = try address.listen(.{ .reuse_address = true });
    defer server.deinit();
    // var stream = net.tcpConnectToAddress(address) catch |e| {
    //     log.err("Failed to tcp connect to port {d}: {}", .{ self.port, e });
    //     return e;
    // };
    log.info("SSH server started and listening at port: {d}", .{self.port});
    while (true) {
        const conn = try server.accept();
        var stream = conn.stream;
        defer {
            stream.close();
        }
        var sr = stream.reader(&readBuffer);
        var reader = &sr.file_reader.interface;
        var wr = stream.writer(&writeBuffer);
        const writer = &wr.interface;
        try writeProtocolVersionExchange("salamaShell_0.0.1", writer);
        readConn: while (reader.takeDelimiterInclusive('\n')) |read| {
            std.log.debug("read {s}", .{read});
        } else |err| {
            if (err == error.EndOfStream) break :readConn;
            log.err("Error reading connnection {}", .{err});
            return err;
        }
    }
}

fn writeProtocolVersionExchange(software_version: []const u8, writer: *IoWriter) !void {
    try writer.print("SSH-2.0-{s} This is still WIP product\r\n", .{software_version});
    try writer.flush();
}
