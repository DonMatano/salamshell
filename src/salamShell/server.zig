const std = @import("std");
const types = @import("types.zig");
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

pub fn arenaAlloc(self: *Server) Alloc {
    return self.arena.allocator();
}

pub fn deinit(self: *Server) void {
    self.arena.deinit();
}

pub fn listen(self: *Server) !void {
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
        const reader = &sr.file_reader.interface;
        var wr = stream.writer(&writeBuffer);
        const writer = &wr.interface;
        writeProtocolVersionExchange("salamaShell_0.0.1", writer) catch |err| {
            log.err("Got Error with version exchange: {}\n", .{err});
            stream.close();
            return err;
        };
        try readClientVersion(reader, writer);
        const ssh = try readPacket(reader, self.arenaAlloc());
        std.log.debug("ssh: {f}", .{ssh});
        try readPayload(ssh.payload);
    }
}

fn writeProtocolVersionExchange(software_version: []const u8, writer: *IoWriter) !void {
    try writer.print("SSH-2.0-{s} This is still WIP product\r\n", .{software_version});
    try writer.flush();
}

fn readClientVersion(reader: *IoReader, writer: *IoWriter) !void {
    const client_ssh_version = try reader.takeDelimiterInclusive('\n');
    try verifyClientVersion(client_ssh_version, writer);
    log.info("Connected to client {s}\n", .{client_ssh_version});
}

fn verifyClientVersion(client_ssh_protocol: []const u8, writer: *IoWriter) !void {
    // Max lenght should be 255
    if (client_ssh_protocol.len > 255) {
        try writer.print("Error: Client SSH version: {s} is longer than max length 255\r\n", .{client_ssh_protocol});
        return error.SalamShellLongClientVersion;
    }
}

fn readPacket(reader: *IoReader, alloc: Alloc) !types.SshPacket {
    _ = alloc;
    var packetLengthArray: [4]u8 = undefined;
    const readBytes = try reader.readSliceShort(&packetLengthArray);
    std.debug.assert(readBytes == 4);
    const packetLength = std.mem.readInt(u32, &packetLengthArray, .big);
    log.info("Packet length gotten {d}\n", .{packetLength});
    const paddingLength = try reader.takeByte();
    log.info("Padding byte {d}", .{paddingLength});
    std.debug.assert(paddingLength >= 4 and paddingLength <= 255);

    const payloadLength = packetLength - paddingLength - 1;
    log.info("Payload length {d}", .{payloadLength});

    // var payload: [payloadLength]u8 = undefined;

    const payload = try reader.take(payloadLength);
    log.info("payload {s}", .{payload});

    const randomPadding = try reader.take(paddingLength);
    log.info("random padding {s}", .{randomPadding});

    // const rem = try reader.allocRemaining(alloc, .unlimited);
    // log.info("rem {s}", .{rem});
    return .{
        .payload = payload,
        .padding = randomPadding,
        .packet_length = packetLength,
        .padding_length = paddingLength,
    };
}

fn readPayload(payload: []const u8) !void {
    var reader = std.Io.Reader.fixed(payload);

    const msg = try reader.takeByte();
    log.info("msg {d}", .{msg});
}
