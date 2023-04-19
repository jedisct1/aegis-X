const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const AuthenticationError = std.crypto.errors.AuthenticationError;

const AesBlockX4 = @import("aes_block_x4.zig").AesBlockX4;

pub const Aegis128X = Aegis128Xt(128);
pub const Aegis128X_256 = Aegis128Xt(256);

fn Aegis128Xt(comptime tag_bits: u9) type {
    assert(tag_bits == 128 or tag_bits == 256); // tag bits must be 128 or 256

    return struct {
        const Self = @This();
        pub const key_length: usize = 16;
        pub const nonce_length: usize = 16;
        pub const tag_length: usize = 16;
        pub const ad_max_length: usize = 1 << 61;
        pub const msg_max_length: usize = 1 << 61;
        pub const ct_max_length: usize = msg_max_length + tag_length;

        const State = [8]AesBlockX4;

        s: State,

        inline fn aesround(in: AesBlockX4, rk: AesBlockX4) AesBlockX4 {
            return in.encrypt(rk);
        }

        fn update(self: *Aegis128X, m0: AesBlockX4, m1: AesBlockX4) void {
            const s = self.s;
            self.s = State{
                aesround(s[7], s[0].xorBlocks(m0)),
                aesround(s[0], s[1]),
                aesround(s[1], s[2]),
                aesround(s[2], s[3]),
                aesround(s[3], s[4].xorBlocks(m1)),
                aesround(s[4], s[5]),
                aesround(s[5], s[6]),
                aesround(s[6], s[7]),
            };
        }

        fn init(key: [key_length]u8, nonce: [nonce_length]u8) Self {
            const c0 = AesBlockX4.fromBytes(&[16]u8{ 0x0, 0x1, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 } ** 4);
            const c1 = AesBlockX4.fromBytes(&[16]u8{ 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd } ** 4);

            const key_x4 = key ** 4;
            const nonce_x4 = nonce ** 4;
            const key_block = AesBlockX4.fromBytes(&key_x4);
            const nonce_block = AesBlockX4.fromBytes(&nonce_x4);

            const contexts = AesBlockX4.fromBytes(
                &[_]u8{0} ++ [_]u8{0} ** 15 ++ // context for first instance is 0
                    [_]u8{1} ++ [_]u8{0} ** 15 ++ // context for second instance is 1
                    [_]u8{2} ++ [_]u8{0} ** 15 ++ // context for second instance is 2
                    [_]u8{3} ++ [_]u8{0} ** 15, // context for second instance is 3
            );

            var self = Self{ .s = State{
                key_block.xorBlocks(nonce_block),
                c1,
                c0,
                c1,
                key_block.xorBlocks(nonce_block),
                key_block.xorBlocks(c0),
                key_block.xorBlocks(c1),
                key_block.xorBlocks(c0),
            } };
            var i: usize = 0;
            while (i < 10) : (i += 1) {
                self.s[3] = self.s[3].xorBlocks(contexts);
                self.s[7] = self.s[7].xorBlocks(contexts);
                self.update(nonce_block, key_block);
            }
            return self;
        }

        fn enc(self: *Self, xi: *const [128]u8) [128]u8 {
            const s = self.s;
            const z0 = s[6].xorBlocks(s[1]).xorBlocks(s[2].andBlocks(s[3]));
            const z1 = s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7]));
            const t0 = AesBlockX4.fromBytes(xi[0..64]);
            const t1 = AesBlockX4.fromBytes(xi[64..128]);
            const out0 = t0.xorBlocks(z0);
            const out1 = t1.xorBlocks(z1);
            self.update(t0, t1);
            var ci: [128]u8 = undefined;
            mem.copy(u8, ci[0..64], &out0.toBytes());
            mem.copy(u8, ci[64..128], &out1.toBytes());
            return ci;
        }

        fn dec(self: *Self, ci: *const [128]u8) [128]u8 {
            const s = self.s;
            const z0 = s[6].xorBlocks(s[1]).xorBlocks(s[2].andBlocks(s[3]));
            const z1 = s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7]));
            const t0 = AesBlockX4.fromBytes(ci[0..64]);
            const t1 = AesBlockX4.fromBytes(ci[64..128]);
            const out0 = t0.xorBlocks(z0);
            const out1 = t1.xorBlocks(z1);
            self.update(out0, out1);
            var xi: [128]u8 = undefined;
            mem.copy(u8, xi[0..64], &out0.toBytes());
            mem.copy(u8, xi[64..128], &out1.toBytes());
            return xi;
        }

        fn decLast(self: *Self, xn: []u8, cn: []const u8) void {
            const s = self.s;
            const z0 = s[6].xorBlocks(s[1]).xorBlocks(s[2].andBlocks(s[3]));
            const z1 = s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7]));
            var pad = [_]u8{0} ** 128;
            mem.copy(u8, pad[0..cn.len], cn);
            const t0 = AesBlockX4.fromBytes(pad[0..64]);
            const t1 = AesBlockX4.fromBytes(pad[64..128]);
            const out0 = t0.xorBlocks(z0);
            const out1 = t1.xorBlocks(z1);
            mem.copy(u8, pad[0..64], &out0.toBytes());
            mem.copy(u8, pad[64..128], &out1.toBytes());
            mem.copy(u8, xn, pad[0..cn.len]);
            mem.set(u8, pad[cn.len..], 0);
            const v0 = AesBlockX4.fromBytes(pad[0..64]);
            const v1 = AesBlockX4.fromBytes(pad[64..128]);
            self.update(v0, v1);
        }

        fn finalize(self: *Self, ad_len: usize, msg_len: usize) [tag_length]u8 {
            var s = &self.s;
            var b: [64]u8 = undefined;
            mem.writeIntLittle(u64, b[0..8], @intCast(u64, ad_len) * 8);
            mem.writeIntLittle(u64, b[8..16], @intCast(u64, msg_len) * 8);
            mem.copy(u8, b[16..32], b[0..16]);
            mem.copy(u8, b[32..48], b[0..16]);
            mem.copy(u8, b[48..64], b[0..16]);
            const t = s[2].xorBlocks(AesBlockX4.fromBytes(&b));
            var i: usize = 0;
            while (i < 7) : (i += 1) {
                self.update(t, t);
            }
            if (tag_length == 16) {
                const tag32 = s[0].xorBlocks(s[1]).xorBlocks(s[2]).xorBlocks(s[3])
                    .xorBlocks(s[4]).xorBlocks(s[5]).xorBlocks(s[6]).toBytes();
                var tag: [tag_length]u8 = undefined;
                for (tag, 0..) |_, j| {
                    tag[j] = tag32[j] ^ tag32[j + 16] ^ tag32[j + 32] ^ tag32[j + 48];
                }
                return tag;
            } else {
                const tag32_0 = s[0].xorBlocks(s[1]).xorBlocks(s[2]).xorBlocks(s[3]).toBytes();
                const tag32_1 = s[4].xorBlocks(s[5]).xorBlocks(s[6]).xorBlocks(s[7]).toBytes();
                var tag: [tag_length]u8 = undefined;
                for (tag[0 .. tag_length / 2], 0..) |_, j| {
                    tag[j] = tag32_0[j] ^ tag32_0[j + 16] ^ tag32_0[j + 32] ^ tag32_0[j + 48];
                }
                for (tag[tag_length / 2 ..], 0..) |_, j| {
                    tag[tag_length / 2 + j] = tag32_1[j] ^ tag32_1[j + 16] ^ tag32_1[j + 32] ^ tag32_1[j + 48];
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
            while (i + 128 <= ad.len) : (i += 128) {
                _ = aegis.enc(ad[i..][0..128]);
            }
            if (ad.len % 128 != 0) {
                var pad = [_]u8{0} ** 128;
                mem.copy(u8, pad[0 .. ad.len % 128], ad[i..]);
                _ = aegis.enc(&pad);
            }

            i = 0;
            while (i + 128 <= msg.len) : (i += 128) {
                mem.copy(u8, ct[i..][0..128], &aegis.enc(msg[i..][0..128]));
            }
            if (msg.len % 128 != 0) {
                var pad = [_]u8{0} ** 128;
                mem.copy(u8, pad[0 .. msg.len % 128], msg[i..]);
                mem.copy(u8, ct[i..], aegis.enc(&pad)[0 .. msg.len % 128]);
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
            while (i + 128 <= ad.len) : (i += 128) {
                _ = aegis.enc(ad[i..][0..128]);
            }
            if (ad.len % 128 != 0) {
                var pad = [_]u8{0} ** 128;
                mem.copy(u8, pad[0 .. ad.len % 128], ad[i..]);
                _ = aegis.enc(&pad);
            }

            i = 0;
            while (i + 128 <= ct.len) : (i += 128) {
                mem.copy(u8, msg[i..][0..128], &aegis.dec(ct[i..][0..128]));
            }
            if (ct.len % 128 != 0) {
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

test "aegis128x" {
    const key = [_]u8{0} ** Aegis128X.key_length;
    const nonce = [_]u8{0} ** Aegis128X.nonce_length;
    const ad = [_]u8{0} ** 64;
    const msg = [_]u8{0} ** 64;
    var ct = [_]u8{0} ** msg.len;
    const tag = Aegis128X.encrypt(&ct, &msg, &ad, key, nonce);
    var msg2 = [_]u8{0} ** msg.len;
    try Aegis128X.decrypt(&msg2, &ct, tag, &ad, key, nonce);
    try std.testing.expectEqualSlices(u8, &msg, &msg2);
}
