const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const AuthenticationError = std.crypto.errors.AuthenticationError;

const AesBlockX2 = @import("aes_block_x2.zig").AesBlockX2;

pub const Aegis256X = Aegis256Xt(128);
pub const Aegis256X_256 = Aegis256Xt(256);

fn Aegis256Xt(comptime tag_bits: u9) type {
    assert(tag_bits == 128 or tag_bits == 256); // tag bits must be 128 or 256

    return struct {
        const Self = @This();

        pub const key_length: usize = 32;
        pub const nonce_length: usize = 32;
        pub const tag_length: usize = tag_bits / 8;
        pub const ad_max_length: usize = 1 << 61;
        pub const msg_max_length: usize = 1 << 61;
        pub const ct_max_length: usize = msg_max_length + tag_length;

        const State = [6]AesBlockX2;

        s: State,

        inline fn aesround(in: AesBlockX2, rk: AesBlockX2) AesBlockX2 {
            return in.encrypt(rk);
        }

        fn update(self: *Self, m: AesBlockX2) void {
            const s = self.s;
            self.s = State{
                aesround(s[5], s[0].xorBlocks(m)),
                aesround(s[0], s[1]),
                aesround(s[1], s[2]),
                aesround(s[2], s[3]),
                aesround(s[3], s[4]),
                aesround(s[4], s[5]),
            };
        }

        fn init(key: [key_length]u8, nonce: [nonce_length]u8) Self {
            const c0 = AesBlockX2.fromBytes(&[16]u8{ 0x0, 0x1, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 } ** 2);
            const c1 = AesBlockX2.fromBytes(&[16]u8{ 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd } ** 2);

            var key0_x2: [32]u8 = undefined;
            var key1_x2: [32]u8 = undefined;
            var nonce0_x2: [32]u8 = undefined;
            var nonce1_x2: [32]u8 = undefined;
            mem.copy(u8, key0_x2[0..16], key[0..16]);
            mem.copy(u8, key0_x2[16..], key[0..16]);
            mem.copy(u8, key1_x2[0..16], key[16..]);
            mem.copy(u8, key1_x2[16..], key[16..]);
            mem.copy(u8, nonce0_x2[0..16], nonce[0..16]);
            mem.copy(u8, nonce0_x2[16..], nonce[0..16]);
            mem.copy(u8, nonce1_x2[0..16], nonce[16..]);
            mem.copy(u8, nonce1_x2[16..], nonce[16..]);

            const contexts = AesBlockX2.fromBytes(
                &[_]u8{0} ++ [_]u8{0} ** 15 ++ // context for first instance is 0
                    [_]u8{1} ++ [_]u8{0} ** 15, // context for second instance is 1
            );

            const k0 = AesBlockX2.fromBytes(&key0_x2);
            const k1 = AesBlockX2.fromBytes(&key1_x2);
            const n0 = AesBlockX2.fromBytes(&nonce0_x2);
            const n1 = AesBlockX2.fromBytes(&nonce1_x2);
            var self = Self{ .s = State{
                k0.xorBlocks(n0),
                k1.xorBlocks(n1),
                c1,
                c0,
                k0.xorBlocks(c0),
                k1.xorBlocks(c1),
            } };
            var i: usize = 0;
            while (i < 4) : (i += 1) {
                self.s[3] = self.s[3].xorBlocks(contexts);
                self.s[5] = self.s[5].xorBlocks(contexts);
                self.update(k0);
                self.s[3] = self.s[3].xorBlocks(contexts);
                self.s[5] = self.s[5].xorBlocks(contexts);
                self.update(k1);
                self.s[3] = self.s[3].xorBlocks(contexts);
                self.s[5] = self.s[5].xorBlocks(contexts);
                self.update(k0.xorBlocks(n0));
                self.s[3] = self.s[3].xorBlocks(contexts);
                self.s[5] = self.s[5].xorBlocks(contexts);
                self.update(k1.xorBlocks(n1));
            }
            return self;
        }

        fn enc(self: *Self, xi: *const [32]u8) [32]u8 {
            const s = self.s;
            const z = s[1].xorBlocks(s[4]).xorBlocks(s[5]).xorBlocks(s[2].andBlocks(s[3]));
            const t = AesBlockX2.fromBytes(xi);
            const ci = t.xorBlocks(z);
            self.update(t);
            return ci.toBytes();
        }

        fn dec(self: *Self, ci: *const [32]u8) [32]u8 {
            const s = self.s;
            const z = s[1].xorBlocks(s[4]).xorBlocks(s[5]).xorBlocks(s[2].andBlocks(s[3]));
            const t = AesBlockX2.fromBytes(ci);
            const xi = t.xorBlocks(z);
            self.update(xi);
            return xi.toBytes();
        }

        fn decLast(self: *Self, xn: []u8, cn: []const u8) void {
            const s = self.s;
            const z = s[1].xorBlocks(s[4]).xorBlocks(s[5]).xorBlocks(s[2].andBlocks(s[3]));
            var pad = [_]u8{0} ** 32;
            mem.copy(u8, pad[0..cn.len], cn);
            const t = AesBlockX2.fromBytes(&pad);
            const out = t.xorBlocks(z);
            mem.copy(u8, &pad, &out.toBytes());
            mem.copy(u8, xn, pad[0..cn.len]);
            mem.set(u8, pad[cn.len..], 0);
            const v = AesBlockX2.fromBytes(&pad);
            self.update(v);
        }

        fn finalize(self: *Self, ad_len: usize, msg_len: usize) [tag_length]u8 {
            var s = &self.s;
            var b: [32]u8 = undefined;
            mem.writeIntLittle(u64, b[0..8], @intCast(u64, ad_len) * 8);
            mem.writeIntLittle(u64, b[8..16], @intCast(u64, msg_len) * 8);
            mem.copy(u8, b[16..32], b[0..16]);
            const t = s[3].xorBlocks(AesBlockX2.fromBytes(&b));
            var i: usize = 0;
            while (i < 7) : (i += 1) {
                self.update(t);
            }
            if (tag_length == 16) {
                const tag32 = s[0].xorBlocks(s[1]).xorBlocks(s[2]).xorBlocks(s[3])
                    .xorBlocks(s[4]).xorBlocks(s[5]).toBytes();
                var tag: [tag_length]u8 = undefined;
                for (tag, 0..) |_, j| {
                    tag[j] = tag32[j] ^ tag32[j + 16];
                }
                return tag;
            } else {
                const tag32_0 = s[0].xorBlocks(s[1]).xorBlocks(s[2]).toBytes();
                const tag32_1 = s[3].xorBlocks(s[4]).xorBlocks(s[5]).toBytes();
                var tag: [tag_length]u8 = undefined;
                for (tag[0 .. tag_length / 2], 0..) |_, j| {
                    tag[j] = tag32_0[j] ^ tag32_0[j + 16];
                }
                for (tag[tag_length / 2 ..], 0..) |_, j| {
                    tag[tag_length / 2 + j] = tag32_1[j] ^ tag32_1[j + 16];
                }
                return tag;
            }
        }

        pub fn encrypt(
            ct: []u8,
            msg: []const u8,
            ad: []const u8,
            key: [key_length]u8,
            nonce: [nonce_length]u8,
        ) [tag_length]u8 {
            assert(msg.len <= msg_max_length);
            assert(ad.len <= ad_max_length);
            assert(ct.len == msg.len);
            var aegis = init(key, nonce);

            var i: usize = 0;
            while (i + 32 <= ad.len) : (i += 32) {
                _ = aegis.enc(ad[i..][0..32]);
            }
            if (ad.len % 32 != 0) {
                var pad = [_]u8{0} ** 32;
                mem.copy(u8, pad[0 .. ad.len % 32], ad[i..]);
                _ = aegis.enc(&pad);
            }

            i = 0;
            while (i + 32 <= msg.len) : (i += 32) {
                mem.copy(u8, ct[i..][0..32], &aegis.enc(msg[i..][0..32]));
            }
            if (msg.len % 32 != 0) {
                var pad = [_]u8{0} ** 32;
                mem.copy(u8, pad[0 .. msg.len % 32], msg[i..]);
                mem.copy(u8, ct[i..], aegis.enc(&pad)[0 .. msg.len % 32]);
            }

            return aegis.finalize(ad.len, msg.len);
        }

        pub fn decrypt(
            msg: []u8,
            ct: []const u8,
            tag: [tag_length]u8,
            ad: []const u8,
            key: [key_length]u8,
            nonce: [nonce_length]u8,
        ) AuthenticationError!void {
            assert(ct.len <= ct_max_length);
            assert(ad.len <= ad_max_length);
            assert(ct.len == msg.len);
            var aegis = init(key, nonce);

            var i: usize = 0;
            while (i + 32 <= ad.len) : (i += 32) {
                _ = aegis.enc(ad[i..][0..32]);
            }
            if (ad.len % 32 != 0) {
                var pad = [_]u8{0} ** 32;
                mem.copy(u8, pad[0 .. ad.len % 32], ad[i..]);
                _ = aegis.enc(&pad);
            }

            i = 0;
            while (i + 32 <= ct.len) : (i += 32) {
                mem.copy(u8, msg[i..][0..32], &aegis.dec(ct[i..][0..32]));
            }
            if (ct.len % 32 != 0) {
                aegis.decLast(msg[i..], ct[i..]);
            }

            const expected_tag = aegis.finalize(ad.len, msg.len);
            if (!crypto.utils.timingSafeEql([expected_tag.len]u8, expected_tag, tag)) {
                crypto.utils.secureZero(u8, msg);
                return error.AuthenticationFailed;
            }
        }
    };
}

test "aegis256x" {
    const key = [_]u8{0} ** Aegis256X.key_length;
    const nonce = [_]u8{0} ** Aegis256X.nonce_length;
    const ad = [_]u8{0} ** 64;
    const msg = [_]u8{0} ** 64;
    var ct = [_]u8{0} ** msg.len;
    const tag = Aegis256X.encrypt(&ct, &msg, &ad, key, nonce);
    var msg2 = [_]u8{0} ** msg.len;
    try Aegis256X.decrypt(&msg2, &ct, tag, &ad, key, nonce);
    try std.testing.expectEqualSlices(u8, &msg, &msg2);
}

test "test vector" {
    const key = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    const nonce = [_]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47 };
    const ad = [_]u8{ 1, 2, 3, 4 } ** 0;
    const msg = [_]u8{ 5, 6, 7, 8 } ** 0;
    var ct = [_]u8{0} ** msg.len;
    const tag = Aegis256X.encrypt(&ct, &msg, &ad, key, nonce);
    std.debug.print("key: {s}\n", .{std.fmt.bytesToHex(key, .lower)});
    std.debug.print("nonce: {s}\n", .{std.fmt.bytesToHex(nonce, .lower)});
    std.debug.print("ad: {s}\n", .{std.fmt.bytesToHex(ad, .lower)});
    std.debug.print("msg: {s}\n", .{std.fmt.bytesToHex(msg, .lower)});
    std.debug.print("ct: {s}\n", .{std.fmt.bytesToHex(ct, .lower)});
    std.debug.print("tag: {s}\n", .{std.fmt.bytesToHex(tag, .lower)});
    var msg2 = [_]u8{0} ** msg.len;
    try Aegis256X.decrypt(&msg2, &ct, tag, &ad, key, nonce);
    try std.testing.expectEqualSlices(u8, &msg, &msg2);
}
