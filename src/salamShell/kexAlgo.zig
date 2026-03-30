const std = @import("std");
const IoReader = std.Io.Reader;
const crypto = std.crypto;
const X25519 = crypto.dh.X25519;
const MLKem768 = crypto.kem.ml_kem.MLKem768;

const log = std.log.scoped(.KexAlgo);

pub fn mlkem(reader: *IoReader, alloc: std.mem.Allocator) !void {
    _ = alloc;
    var client_x25519_pk: [X25519.public_length]u8 = undefined;
    var client_MLKem_pk: [1184]u8 = undefined;
    var packetLengthArray: [4]u8 = undefined;
    const read_bytes = try reader.readSliceShort(&packetLengthArray);
    if (read_bytes != 4) {
        log.err("Expected to read 4 bytes but read :{d}", .{read_bytes});
        return error.ReadPacketWrongPacketFormat;
    }
    const packetLength = std.mem.readInt(u32, &packetLengthArray, .big);
    log.debug("length {d}", .{packetLength});
    try readmlkemFromReader(reader, &client_MLKem_pk);
    log.debug("\n\n\nclient mlkem: {s}", .{client_MLKem_pk});
    try readX25519FromReader(reader, &client_x25519_pk);
    log.debug("\n\n\nclient x255 pk: {s}", .{client_x25519_pk});
    const server_x25519_pair = X25519.KeyPair.generate();
    // FIXME: Remove this log. Has secret key log.
    log.debug("pk: {s} \t sk: {s}", .{ server_x25519_pair.public_key, server_x25519_pair.secret_key });
    const shared_key = try X25519.scalarmult(server_x25519_pair.secret_key, client_x25519_pk);

    log.debug("shared key gotten: {s}", .{shared_key});
    var mlkem_seed: [32]u8 = undefined;
    crypto.random.bytes(&mlkem_seed);
    const client_PK = try MLKem768.PublicKey.fromBytes(&client_MLKem_pk);
    //
    const enc_sec = crypto.kem.ml_kem.MLKem768.PublicKey.encaps(client_PK, mlkem_seed);
    log.debug("Encapsulated shared secret: {s}", .{enc_sec.shared_secret});
    log.debug("Encapsulated ciphertext: {s}", .{enc_sec.ciphertext});
}

/// Read the X25519 From Reader. It's usually 32 bytes
fn readX25519FromReader(reader: *IoReader, buffer: *[32]u8) !void {
    const read = try reader.readSliceShort(buffer);
    if (read != 32) {
        log.err("Failed to read 32 bytes of x25519", .{});
        return error.KexAlgoX25519FailedToReadRightBytes;
    }
}
/// Read the mlkem From Reader. It's usually 1184 bytes
fn readmlkemFromReader(reader: *IoReader, buffer: *[1184]u8) !void {
    const read = try reader.readSliceShort(buffer);
    if (read != 1184) {
        log.err("Failed to read 1184 bytes of mlkem", .{});
        return error.KexAlgoMLKEMFailedToReadRightBytes;
    }
}
