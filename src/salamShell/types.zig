const std = @import("std");
const utils = @import("../utils.zig");
pub const SshPacket = struct {
    packet_length: u32,
    padding_length: u8,
    payload: []const u8,
    padding: []const u8,
    mac: ?[]const u8 = null,

    pub fn format(self: SshPacket, w: *std.Io.Writer) !void {
        try w.print("{{ \n packet_length: {d}, \n padding_length: {d}, \n payload: {s}\n padding: {s}\n mac: {s}\n  }}", .{ self.packet_length, self.padding_length, self.payload, self.padding, utils.checkNullFormat(self.mac) });
        try w.flush();
    }
};
