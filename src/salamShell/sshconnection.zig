const std = @import("std");
const types = @import("types.zig");
const message_handlers = @import("message_handlers.zig");
const SSHServer = @import("server.zig");
const Alloc = std.mem.Allocator;
const IoWriter = std.Io.Writer;
const IoReader = std.Io.Reader;

const SSHConnection = @This();
connection: *std.net.Server.Connection,
packets_received: usize = 0,
packets_sent: usize = 0,
arena: std.heap.ArenaAllocator,
server_info: *SSHServer,

const log = std.log.scoped(.SSHConnection);

pub fn init(conn: *std.net.Server.Connection, server: *SSHServer, alloc: Alloc) !SSHConnection {
    return .{
        .arena = std.heap.ArenaAllocator.init(alloc),
        .connection = conn,
        .server_info = server,
    };
}
pub fn arenaAlloc(self: *SSHConnection) Alloc {
    return self.arena.allocator();
}

pub fn deinit(self: *SSHConnection) void {
    self.arena.deinit();
}
fn writeProtocolVersionExchange(software_version: []const u8, writer: *IoWriter) !void {
    try writer.print("SSH-2.0-{s} This is still WIP product\r\n", .{software_version});
    try writer.flush();
}
pub fn handleConnection(
    self: *SSHConnection,
) !void {
    var stream = self.connection.stream;
    defer self.deinit();

    defer {
        stream.close();
    }
    const arenaAllocator = self.arenaAlloc();
    const readBuffer = try arenaAllocator.alloc(u8, 4096);
    const writeBuffer = try arenaAllocator.alloc(u8, 4096);
    var sr = stream.reader(readBuffer);
    const reader = &sr.file_reader.interface;
    var wr = stream.writer(writeBuffer);
    const writer = &wr.interface;
    const full_shell_name = try std.fmt.allocPrint(arenaAllocator, "{s}_{s}", .{ self.server_info.shell_name, self.server_info.protocol_version });
    writeProtocolVersionExchange(full_shell_name, writer) catch |err| {
        log.err("Got Error with version exchange: {}\n", .{err});
        stream.close();
        return err;
    };
    try readClientVersion(reader, writer);
    const kex_init_payload = try self.sendKexInit(writer, arenaAllocator);
    log.info("kex_init_payload: \n{s}", .{kex_init_payload});
    while (true) {
        const ssh = try readPacket(reader, arenaAllocator);
        std.log.debug("ssh: {f}", .{ssh});
        // First byte is the msg code.
        const ssh_message = try getSSHMessageFromPayload(ssh.payload[0]);
        var r = IoReader.fixed(ssh.payload[1..]);
        try self.handleMessage(ssh_message, &r, writer, arenaAllocator);
    }
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
fn getSSHMessageFromPayload(msg_byte: u8) !types.SSH_MSG {
    const mess: types.SSH_MSG = @enumFromInt(msg_byte);
    log.info("msg {s}", .{@tagName(mess)});
    return mess;
}
fn readPacket(reader: *IoReader, alloc: Alloc) !types.SshPacket {
    _ = alloc;
    var packetLengthArray: [4]u8 = undefined;
    const read_bytes = try reader.readSliceShort(&packetLengthArray);
    if (read_bytes != 4) {
        log.err("Expected to read 4 bytes but read :{d}", .{read_bytes});
        return error.ReadPacketWrongPacketFormat;
    }
    const packetLength = std.mem.readInt(u32, &packetLengthArray, .big);
    log.info("Packet length gotten {d}\n", .{packetLength});
    const paddingLength = try reader.takeByte();
    log.info("Padding byte {d}", .{paddingLength});
    if (paddingLength < 4 or paddingLength > 255) {
        log.err("Padding byte is more than 255 or less than 4: Got {d}", .{paddingLength});
        return error.ReadPacketWrongPaddingLength;
    }

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
/// Handle a message. Reader should not include the message code
fn handleMessage(self: *SSHConnection, message_code: types.SSH_MSG, reader: *IoReader, writer: *IoWriter, alloc: Alloc) !void {
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
fn sendKexInit(self: *SSHConnection, writer: *IoWriter, alloc: Alloc) ![]const u8 {
    _ = writer;
    var wr_allocating = try IoWriter.Allocating.initCapacity(alloc, 4096);
    defer wr_allocating.deinit();
    // errdefer string.deinit(alloc);
    var wr = &wr_allocating.writer;
    try wr.writeByte(@intCast(@intFromEnum(types.SSH_MSG.kexinit)));
    var cookie: [16]u8 = undefined;
    getCookie(&cookie);
    std.log.debug("Adding cookies {s}", .{cookie});
    try wr.writeAll(&cookie);
    std.log.debug("Just wrote {s}", .{wr_allocating.written()});
    try writeNameList(self.server_info.supported_kex_algo, wr, alloc);
    log.debug("Just wrote {s}", .{wr_allocating.written()});
    try writeNameList(self.server_info.supported_host_algo, wr, alloc);
    log.debug("Just wrote {s}", .{wr_allocating.written()});
    try writeNameList(self.server_info.supported_encryption_algo, wr, alloc);
    log.debug("Just wrote {s}", .{wr_allocating.written()});
    try writeNameList(self.server_info.supported_encryption_algo, wr, alloc);
    log.debug("Just wrote {s}", .{wr_allocating.written()});
    try writeNameList(self.server_info.supported_mac_algo, wr, alloc);
    log.debug("Just wrote {s}", .{wr_allocating.written()});
    try writeNameList(self.server_info.supported_mac_algo, wr, alloc);
    log.debug("Just wrote {s}", .{wr_allocating.written()});
    try writeNameList(self.server_info.supported_compression_algo, wr, alloc);
    log.debug("Just wrote {s}", .{wr_allocating.written()});
    try writeNameList(self.server_info.supported_compression_algo, wr, alloc);
    log.debug("Just wrote {s}", .{wr_allocating.written()});
    try writeNameList(self.server_info.supported_languages, wr, alloc);
    log.debug("Just wrote {s}", .{wr_allocating.written()});
    try writeNameList(self.server_info.supported_languages, wr, alloc);
    log.debug("Just wrote {s}", .{wr_allocating.written()});
    try wr.writeByte(0);
    try wr.writeInt(u32, @intCast(0), .big);
    try wr.flush();
    // log.info("written string: {s}\n", .{string.items});
    log.info("written wr: {s}: len {d}\n", .{ wr_allocating.written(), wr_allocating.written().len });
    // log.info("written wr: \n{s}", .{try string.toOwnedSlice(wr_allocating.allocator)});
    // try &wr.flush();
    return try wr_allocating.toOwnedSlice();
}
fn getCookie(cookie: *[16]u8) void {
    std.crypto.random.bytes(cookie);
}

fn writeNameList(name_list: types.NameList, writer: *IoWriter, alloc: Alloc) !void {
    const sendable_name_list = try name_list.getFormatSendableNameList(alloc);
    try writer.writeInt(u32, @intCast(sendable_name_list.len), .big);
    try writer.writeAll(sendable_name_list);
}
