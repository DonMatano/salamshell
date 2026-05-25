const std = @import("std");
const types = @import("types.zig");
const IoReader = std.Io.Reader;
const IoWriter = std.Io.Writer;
const Alloc = std.mem.Allocator;

const log = std.log.scoped(.BPP);

pub fn readBPPPacket(reader: *IoReader, in_packet_seq: *usize) !types.SshPacket {
    var packetLengthArray: [4]u8 = undefined;
    const read_bytes = try reader.readSliceShort(&packetLengthArray);
    if (read_bytes != 4) {
        log.err("Expected to read 4 bytes but read :{d}", .{read_bytes});
        return error.ReadPacketWrongPacketFormat;
    }
    const packetLength = std.mem.readInt(u32, &packetLengthArray, .big);
    if (packetLength > 35000) {
        log.err("Packet too large. Expected max 35kb but got {d}", .{packetLength});
        return error.InvalidPacketLength; // packet length is 35k
    }
    const paddingLength = try reader.takeByte();
    if (paddingLength < 4 or paddingLength > 255) {
        log.err("Padding byte is more than 255 or less than 4: Got {d}", .{paddingLength});
        return error.ReadPacketWrongPaddingLength;
    }
    if (packetLength < paddingLength - 1) {
        log.err("Invalid packet length, smaller than padding {d}", .{packetLength});
        return error.InvalidPacketLength;
    }

    const payloadLength = packetLength - paddingLength - 1;
    log.info("Payload length {d}", .{payloadLength});

    // var payload: [payloadLength]u8 = undefined;

    const payload = try reader.take(payloadLength);
    log.info("payload {s}", .{payload});

    const randomPadding = try reader.take(paddingLength);
    log.info("random padding {s}", .{randomPadding});
    in_packet_seq.* += 1;

    // const rem = try reader.allocRemaining(alloc, .unlimited);
    // log.info("rem {s}", .{rem});
    return .{
        .payload = payload,
        .packet_length = packetLength,
        .padding_length = paddingLength,
    };
}
pub fn writeBPPPacket(writer: *IoWriter, payload: []const u8, out_packet_seq: *usize, alloc: Alloc) !void {
    //  Note that the length of the concatenation of 'packet_length',
    // 'padding_length', 'payload', and 'random padding' MUST be a multiple
    // of the cipher block size or 8, whichever is larger.
    const block_size: usize = 8;

    // 1. Calculate padding
    // (4 bytes length(packet length) + 1 byte padding_len + payload + padding) % block_size == 0
    const header_plus_payload_len = 4 + 1 + payload.len;
    // Calculate how many bytes are needed to reach the next block
    var padding = block_size - (header_plus_payload_len % block_size);

    // If padding is less than 4, we must add another full block/ There must be atlease 4 bytes of padding
    if (padding < 4) {
        padding += block_size;
    }
    // Padding should be less than a byte
    if (padding > std.math.maxInt(u8)) {
        log.err("Expected padding to be >= {d} but got {}", .{ std.math.maxInt(u8), padding });
        return error.BPPErrorPacketPaddingSize;
    }
    const multiple = (5 + payload.len + padding) % block_size;

    if (multiple != 0) {
        log.err("Expected packet to be multiple of {d} but got {d}", .{ block_size, multiple });
        return error.BPPErrorPacketNotMultipleOfBlock;
    }

    const packetLength = payload.len + 1 + padding; // payload + padding_length byte + padding

    try writer.writeInt(u32, @intCast(packetLength), .big);
    try writer.writeByte(@intCast(padding));
    try writer.writeAll(payload);
    var randomPadding = try alloc.alloc(u8, padding);
    defer alloc.destroy(&randomPadding);
    std.crypto.random.bytes(randomPadding);
    try writer.writeAll(randomPadding);
    try writer.flush();
    out_packet_seq.* += 1;
}
