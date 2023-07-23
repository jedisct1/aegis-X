const std = @import("std");
const Aegis128X2 = @import("aegis128x.zig").Aegis128X2;
const Aegis256X2 = @import("aegis256x.zig").Aegis256X2;

const fmt = std.fmt;
const debug = std.debug;
const testing = std.testing;

test "128X2 test vector" {
    const key = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const nonce = [_]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    const ad = [_]u8{ 1, 2, 3, 4 } ** 2;
    const msg = [_]u8{ 4, 5, 6, 7 } ** 3;
    var ct = [_]u8{0} ** msg.len;
    const tag = Aegis128X2.encrypt(&ct, &msg, &ad, key, nonce);
    std.debug.print("Key: {s}\n", .{std.fmt.bytesToHex(key, .lower)});
    std.debug.print("IV: {s}\n", .{std.fmt.bytesToHex(nonce, .lower)});
    std.debug.print("AD: {s}\n", .{std.fmt.bytesToHex(ad, .lower)});
    std.debug.print("Plaintext: {s}\n", .{std.fmt.bytesToHex(msg, .lower)});
    std.debug.print("Ciphertext: {s}\n", .{std.fmt.bytesToHex(ct, .lower)});
    std.debug.print("128-bit tag: {s}\n", .{std.fmt.bytesToHex(tag, .lower)});
    var msg2 = [_]u8{0} ** msg.len;
    try Aegis128X2.decrypt(&msg2, &ct, tag, &ad, key, nonce);
    try std.testing.expectEqualSlices(u8, &msg, &msg2);
}

test "256X2 test vector" {
    const key = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    const nonce = [_]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47 };
    const ad = [_]u8{ 1, 2, 3, 4 } ** 2;
    const msg = [_]u8{ 5, 6, 7, 8 } ** 3;
    var ct = [_]u8{0} ** msg.len;
    const tag = Aegis256X2.encrypt(&ct, &msg, &ad, key, nonce);
    std.debug.print("Key: {s}\n", .{std.fmt.bytesToHex(key, .lower)});
    std.debug.print("IV: {s}\n", .{std.fmt.bytesToHex(nonce, .lower)});
    std.debug.print("AD: {s}\n", .{std.fmt.bytesToHex(ad, .lower)});
    std.debug.print("Plaintext: {s}\n", .{std.fmt.bytesToHex(msg, .lower)});
    std.debug.print("Ciphertext: {s}\n", .{std.fmt.bytesToHex(ct, .lower)});
    std.debug.print("128-bit tag: {s}\n", .{std.fmt.bytesToHex(tag, .lower)});
    var msg2 = [_]u8{0} ** msg.len;
    try Aegis256X2.decrypt(&msg2, &ct, tag, &ad, key, nonce);
    try std.testing.expectEqualSlices(u8, &msg, &msg2);
}
