const std = @import("std");
const types = @import("types.zig");
const message_handlers = @import("message_handlers.zig");
const SSHServer = @import("server.zig");
const BPP = @import("bpp.zig");
const Alloc = std.mem.Allocator;
const IoWriter = std.Io.Writer;
const IoReader = std.Io.Reader;

const SSHConnection = @This();
connection: *std.net.Server.Connection,
packets_received: usize = 0,
packets_sent: usize = 0,
arena: std.heap.ArenaAllocator,
server_info: *SSHServer,
supported_kex_algo: []const u8 = "",
supported_host_algo: []const u8 = "",
supported_encryption_algo: []const u8 = "",
supported_mac_algo: []const u8 = "",
supported_compression_algo: []const u8 = "none",

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
    const kex_init_payload = try self.getKexInitPayload(arenaAllocator);
    log.debug("kex_init_payload: \n{s}", .{kex_init_payload});
    try BPP.writeBPPPacket(writer, kex_init_payload, &self.packets_sent, arenaAllocator);
    while (true) {
        const ssh = try BPP.readBPPPacket(reader, &self.packets_received);
        log.debug("ssh: {f}", .{ssh});
        // First byte is the msg code.
        const ssh_message = try getSSHMessageFromPayload(ssh.payload[0]);
        var r = IoReader.fixed(ssh.payload[1..]);
        try self.handleMessage(ssh_message, &r, writer, arenaAllocator);
        log.debug("Packets total received: {d}\n total Packets sent: {d}", .{ self.packets_received, self.packets_sent });
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
    log.info("message code: {d}", .{msg_byte});
    const mess = std.enums.fromInt(types.SSH_MSG, msg_byte) orelse {
        log.err("Message code {d}, has not been handled yet", .{msg_byte});
        return error.MessageCodeUnimplemented;
    };
    log.info("msg {s}", .{@tagName(mess)});
    return mess;
}
/// Handle a message. Reader should not include the message code
fn handleMessage(self: *SSHConnection, message_code: types.SSH_MSG, reader: *IoReader, writer: *IoWriter, alloc: Alloc) !void {
    _ = writer;
    switch (message_code) {
        .kexinit => {
            const kex_pay = try message_handlers.handleKexInit(reader, alloc);
            try self.setSupportedAlgos(kex_pay);
        },
        .kexdh_init => {
            const supported_kex = types.KexAlgos.getEnumFromString(self.supported_kex_algo);
            if (supported_kex == .not_found) {
                log.err("Got an unsupported kex algo, {s}", .{self.supported_kex_algo});
                return error.KexAlgoUnsupported;
            }
            log.debug("handling kex dh init", .{});
            try message_handlers.handleKexDhInit(reader, supported_kex, alloc);
        },
        else => log.info("message: {d}. not yet handled.", .{@intFromEnum(message_code)}),
    }
}

fn getKexInitPayload(self: *SSHConnection, alloc: Alloc) ![]const u8 {
    var wr_allocating = try IoWriter.Allocating.initCapacity(alloc, 4096);
    defer wr_allocating.deinit();
    var wr = &wr_allocating.writer;
    try wr.writeByte(@intCast(@intFromEnum(types.SSH_MSG.kexinit)));
    var cookie: [16]u8 = undefined;
    getCookie(&cookie);
    try wr.writeAll(&cookie);
    try writeNameList(self.server_info.supported_kex_algo, wr, alloc);
    try writeNameList(self.server_info.supported_host_algo, wr, alloc);
    try writeNameList(self.server_info.supported_encryption_algo, wr, alloc);
    try writeNameList(self.server_info.supported_encryption_algo, wr, alloc);
    try writeNameList(self.server_info.supported_mac_algo, wr, alloc);
    try writeNameList(self.server_info.supported_mac_algo, wr, alloc);
    try writeNameList(self.server_info.supported_compression_algo, wr, alloc);
    try writeNameList(self.server_info.supported_compression_algo, wr, alloc);
    try writeNameList(self.server_info.supported_languages, wr, alloc);
    try writeNameList(self.server_info.supported_languages, wr, alloc);
    try wr.writeByte(0);
    try wr.writeInt(u32, @intCast(0), .big);
    try wr.flush();
    return try wr_allocating.toOwnedSlice();
}

fn setSupportedAlgos(self: *SSHConnection, client_kex_payload: types.KexInitPayload) !void {
    var selected_kex_payload: ?[]const u8 = null;
    if (client_kex_payload.kex_algorithms.length <= 0) {
        log.err("client kex algo list is empty", .{});
        return error.SupportedAlgosEmptyList;
    }
    kex: for (client_kex_payload.kex_algorithms.names) |client_supported_algo| {
        const name_list = try self.server_info.supported_kex_algo.getFormatSendableNameList(self.arenaAlloc());
        var name_list_it = std.mem.splitScalar(u8, name_list, ',');
        while (name_list_it.next()) |server_supported_algo| {
            if (std.mem.eql(u8, client_supported_algo, server_supported_algo)) {
                selected_kex_payload = server_supported_algo;
                break :kex;
            }
        }
    }
    if (selected_kex_payload == null) {
        log.err("Failed to get supported kex algo", .{});
        return error.MissingSupportedKexAlgo;
    }
    self.supported_kex_algo = selected_kex_payload.?;
}
fn getCookie(cookie: *[16]u8) void {
    std.crypto.random.bytes(cookie);
}

fn writeNameList(name_list: types.NameList, writer: *IoWriter, alloc: Alloc) !void {
    const sendable_name_list = try name_list.getFormatSendableNameList(alloc);
    try writer.writeInt(u32, @intCast(sendable_name_list.len), .big);
    try writer.writeAll(sendable_name_list);
}
