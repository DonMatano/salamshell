const std = @import("std");
const types = @import("types.zig");
const message_handlers = @import("message_handlers.zig");
const Alloc = std.mem.Allocator;

const Server = @This();

alloc: Alloc,
arena: std.heap.ArenaAllocator,
port: u16,
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
    // var stream = net.tcpConnectToAddress(address) catch |e| {
    //     log.err("Failed to tcp connect to port {d}: {}", .{ self.port, e });
    //     return e;
    // };
    log.info("SSH server started and listening at port: {d}", .{self.port});
    while (true) {
        const conn = try server.accept();
        const thread = try std.Thread.spawn(.{}, handleConnection, .{ self, conn });
        thread.detach();
    }
}

pub fn handleConnection(self: *Server, connection: std.net.Server.Connection) !void {
    var stream = connection.stream;
    var readBuffer: [4096]u8 = undefined;
    var writeBuffer: [4096]u8 = undefined;
    var arena = std.heap.ArenaAllocator.init(self.arenaAlloc());
    defer arena.deinit();
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
    while (true) {
        const ssh = try readPacket(reader, arena.allocator());
        std.log.debug("ssh: {f}", .{ssh});
        // First byte is the msg code.
        const ssh_message = try getSSHMessageFromPayload(ssh.payload[0]);
        var r = IoReader.fixed(ssh.payload[1..]);
        try self.handleMessage(ssh_message, &r, writer, arena.allocator());
    }
}
/// Handle a message. Reader should not include the message code
fn handleMessage(self: *Server, message_code: types.SSH_MSG, reader: *IoReader, writer: *IoWriter, alloc: Alloc) !void {
    _ = self;
    _ = writer;
    switch (message_code) {
        .kexinit => {
            const kex_pay = try message_handlers.handleKexInit(reader, alloc);
            log.info("Kex payload: \n{f}", .{kex_pay});
            log.info("Client ex supported {s}", .{try kex_pay.kex_algorithms.getFormatSendableNameList(alloc)});
        },
        else => log.info("message: {d}. not yet handled.", .{@intFromEnum(message_code)}),
    }
}

fn writeProtocolVersionExchange(software_version: []const u8, writer: *IoWriter) !void {
    try writer.print("SSH-2.0-{s} This is still WIP product\r\n", .{software_version});
    try writer.flush();
}

// fn writeKexInit(self: *Server, writer: *IoWriter) !void {
//     writer.writeAll(kk)
//
//
//
// }

fn getCookie(cookie: *[16]u8) !void {
    std.crypto.random.bytes(cookie);
}

fn writeNameList(name_list: types.NameList, writer: *IoWriter, alloc: Alloc) !void {
    const sendable_name_list = try name_list.getFormatSendableNameList(alloc);
    try writer.writeInt(u32, sendable_name_list.len, .big);
    try writer.writeAll(sendable_name_list);
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
        .packet_length = packetLength,
        .padding_length = paddingLength,
    };
}

fn getSSHMessageFromPayload(msg_byte: u8) !types.SSH_MSG {
    const mess: types.SSH_MSG = @enumFromInt(msg_byte);
    log.info("msg {s}", .{@tagName(mess)});
    return mess;
}
