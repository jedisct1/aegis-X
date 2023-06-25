const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const AesBlock = std.crypto.core.aes.Block;
const AuthenticationError = std.crypto.errors.AuthenticationError;

pub const Aegis128X = Aegis128Xt(128);
pub const Aegis128X_256 = Aegis128Xt(256);

fn Aegis128Xt(comptime tag_bits: u9) type {
    return struct {
        const Self = @This();

        pub const key_length = 16;
        pub const nonce_length = 16;
        pub const tag_length: comptime_int = tag_bits / 8;
        pub const ad_max_length = 1 << 61;
        pub const msg_max_length = 1 << 61;
        pub const ct_max_length = msg_max_length + tag_length;

        const lanes = 2;
        const stride = lanes * 16;
        const width = lanes * 32;

        const Aegis128X1 = Aegis128L(tag_bits);
        const State = [lanes]Aegis128X1;

        s: State,

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

            var aegis_lanes: [lanes]Aegis128X1 = undefined;
            for (0..lanes) |lane| {
                aegis_lanes[lane] = Aegis128X1.init(key, nonce, @as(u8, @intCast(lane)));
            }
            for (0..lanes) |lane| {
                var aegis = &aegis_lanes[lane];
                var i = lane * 16;
                while (i + width <= ad.len) : (i += width) {
                    aegis.absorb(ad[i..][0..16].*, ad[i..][stride..][0..16].*);
                }
            }
            if (ad.len % width != 0) {
                var pad = [_]u8{0} ** width;
                const pos = ad.len - (ad.len % width);
                const left = @min(pad.len, ad.len - pos);
                @memcpy(pad[0..left], ad[pos..][0..left]);
                for (0..lanes) |lane| {
                    const i = lane * 16;
                    var aegis = &aegis_lanes[lane];
                    aegis.absorb(pad[i..][0..16].*, pad[i..][stride..][0..16].*);
                }
            }
            for (0..lanes) |lane| {
                var aegis = &aegis_lanes[lane];
                var i = lane * 16;
                while (i + width <= msg.len) : (i += width) {
                    const t = aegis.enc(msg[i..][0..16].*, msg[i..][stride..][0..16].*);
                    @memcpy(ct[i..][0..16], &t[0]);
                    @memcpy(ct[i..][stride..][0..16], &t[1]);
                }
            }
            if (msg.len % width != 0) {
                var pad = [_]u8{0} ** width;
                const pos = msg.len - (msg.len % width);
                const left = @min(pad.len, msg.len - pos);
                @memcpy(pad[0..left], msg[pos..][0..left]);
                for (0..lanes) |lane| {
                    const i = lane * 16;
                    var aegis = &aegis_lanes[lane];
                    const t = aegis.enc(pad[i..][0..16].*, pad[i..][stride..][0..16].*);
                    @memcpy(pad[i..][0..16], &t[0]);
                    @memcpy(pad[i..][stride..][0..16], &t[1]);
                }
                @memcpy(ct[pos..][0..left], pad[0..left]);
            }
            var tag = aegis_lanes[0].finalize(ad.len, msg.len);
            for (1..lanes) |lane| {
                var aegis = &aegis_lanes[lane];
                const tag_lane = aegis.finalize(ad.len, msg.len);
                for (&tag, tag_lane) |*t, x| {
                    t.* ^= x;
                }
            }
            return tag;
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

            var aegis_lanes: [lanes]Aegis128X1 = undefined;
            for (0..lanes) |lane| {
                aegis_lanes[lane] = Aegis128X1.init(key, nonce, @as(u8, @intCast(lane)));
            }

            for (0..lanes) |lane| {
                var aegis = &aegis_lanes[lane];
                var i = lane * 16;
                while (i + width <= ad.len) : (i += width) {
                    aegis.absorb(ad[i..][0..16].*, ad[i..][stride..][0..16].*);
                }
            }
            if (ad.len % width != 0) {
                var pad = [_]u8{0} ** width;
                const pos = ad.len - (ad.len % width);
                const left = @min(pad.len, ad.len - pos);
                @memcpy(pad[0..left], ad[pos..][0..left]);
                for (0..lanes) |lane| {
                    const i = lane * 16;
                    var aegis = &aegis_lanes[lane];
                    aegis.absorb(pad[i..][0..16].*, pad[i..][stride..][0..16].*);
                }
            }
            for (0..lanes) |lane| {
                var aegis = &aegis_lanes[lane];
                var i = lane * 16;
                while (i + width <= ct.len) : (i += width) {
                    const t = aegis.dec(ct[i..][0..16].*, ct[i..][stride..][0..16].*);
                    @memcpy(msg[i..][0..16], &t[0]);
                    @memcpy(msg[i..][stride..][0..16], &t[1]);
                }
            }
            if (ct.len % width != 0) {
                const pos = ct.len - (ct.len % width);
                for (0..lanes) |lane| {
                    var aegis = &aegis_lanes[lane];
                    var i = lane * 16;
                    const pos_lane = @min(msg.len, pos + i);
                    decLast2(aegis, msg[pos_lane..], ct[pos_lane..]);
                }
            }

            var expected_tag = aegis_lanes[0].finalize(ad.len, msg.len);
            for (1..lanes) |lane| {
                var aegis = &aegis_lanes[lane];
                const tag_lane = aegis.finalize(ad.len, msg.len);
                for (&expected_tag, tag_lane) |*t, x| {
                    t.* ^= x;
                }
            }
            if (!crypto.utils.timingSafeEql([expected_tag.len]u8, expected_tag, tag)) {
                crypto.utils.secureZero(u8, msg);
                return error.AuthenticationFailed;
            }
        }

        fn decLast2(aegis: *Aegis128X1, xn: []u8, cn: []const u8) void {
            const s = &aegis.s;
            const z0 = s[6].xorBlocks(s[1]).xorBlocks(s[2].andBlocks(s[3]));
            const z1 = s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7]));
            var pad = [_]u8{0} ** 64;
            @memcpy(pad[0..cn.len], cn);
            const t0 = AesBlock.fromBytes(pad[0..16]);
            const t1 = AesBlock.fromBytes(pad[stride..][0..16]);
            const out0 = t0.xorBlocks(z0);
            const out1 = t1.xorBlocks(z1);
            @memcpy(pad[0..16], &out0.toBytes());
            @memcpy(pad[stride..][0..16], &out1.toBytes());
            @memcpy(xn, pad[0..cn.len]);
            @memset(pad[cn.len..], 0);
            const v0 = AesBlock.fromBytes(pad[0..16]);
            const v1 = AesBlock.fromBytes(pad[stride..][0..16]);
            aegis.update(v0, v1);
        }
    };
}

fn Aegis128L(comptime tag_bits: u9) type {
    assert(tag_bits == 128 or tag_bits == 256); // tag bits must be 128 or 256

    return struct {
        const Self = @This();

        pub const key_length = 16;
        pub const nonce_length = 16;
        pub const tag_length: comptime_int = tag_bits / 8;
        pub const ad_max_length = 1 << 61;
        pub const msg_max_length = 1 << 61;
        pub const ct_max_length = msg_max_length + tag_length;

        const State = [8]AesBlock;

        s: State,

        inline fn aesround(in: AesBlock, rk: AesBlock) AesBlock {
            return in.encrypt(rk);
        }

        fn update(self: *Self, m0: AesBlock, m1: AesBlock) void {
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

        fn init(key: [key_length]u8, nonce: [nonce_length]u8, context: u8) Self {
            const c0 = AesBlock.fromBytes(&[16]u8{ 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 });
            const c1 = AesBlock.fromBytes(&[16]u8{ 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd });
            const key_block = AesBlock.fromBytes(&key);
            const nonce_block = AesBlock.fromBytes(&nonce);
            const context_block = AesBlock.fromBytes(&[_]u8{context} ++ [_]u8{0} ** 15);
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
                self.s[3] = self.s[3].xorBlocks(context_block);
                self.s[7] = self.s[7].xorBlocks(context_block);
                self.update(nonce_block, key_block);
            }
            return self;
        }

        fn absorb(self: *Self, ai0: [16]u8, ai1: [16]u8) void {
            const t0 = AesBlock.fromBytes(&ai0);
            const t1 = AesBlock.fromBytes(&ai1);
            self.update(t0, t1);
        }

        fn enc(self: *Self, xi0: [16]u8, xi1: [16]u8) struct { [16]u8, [16]u8 } {
            const s = &self.s;
            const z0 = s[6].xorBlocks(s[1]).xorBlocks(s[2].andBlocks(s[3]));
            const z1 = s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7]));
            const t0 = AesBlock.fromBytes(&xi0);
            const t1 = AesBlock.fromBytes(&xi1);
            const out0 = t0.xorBlocks(z0);
            const out1 = t1.xorBlocks(z1);
            self.update(t0, t1);
            return .{ out0.toBytes(), out1.toBytes() };
        }

        fn dec(self: *Self, ci0: [16]u8, ci1: [16]u8) struct { [16]u8, [16]u8 } {
            const s = &self.s;
            const z0 = s[6].xorBlocks(s[1]).xorBlocks(s[2].andBlocks(s[3]));
            const z1 = s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7]));
            const t0 = AesBlock.fromBytes(&ci0);
            const t1 = AesBlock.fromBytes(&ci1);
            const out0 = t0.xorBlocks(z0);
            const out1 = t1.xorBlocks(z1);
            self.update(out0, out1);
            return .{ out0.toBytes(), out1.toBytes() };
        }

        fn finalize(self: *Self, ad_len: usize, msg_len: usize) [tag_length]u8 {
            var s = &self.s;
            var b: [16]u8 = undefined;
            mem.writeIntLittle(u64, b[0..8], @as(u64, @intCast(ad_len)) * 8);
            mem.writeIntLittle(u64, b[8..16], @as(u64, @intCast(msg_len)) * 8);
            const t = s[2].xorBlocks(AesBlock.fromBytes(&b));
            var i: usize = 0;
            while (i < 7) : (i += 1) {
                self.update(t, t);
            }
            var tag: [tag_length]u8 = undefined;
            if (tag_length == 16) {
                mem.copy(
                    u8,
                    tag[0..],
                    &s[0].xorBlocks(s[1]).xorBlocks(s[2]).xorBlocks(s[3]).xorBlocks(s[4]).xorBlocks(s[5]).xorBlocks(s[6]).toBytes(),
                );
            } else {
                @memcpy(tag[0..16], &s[0].xorBlocks(s[1]).xorBlocks(s[2]).xorBlocks(s[3]).toBytes());
                @memcpy(tag[16..], &s[4].xorBlocks(s[5]).xorBlocks(s[6]).xorBlocks(s[7]).toBytes());
            }
            return tag;
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

test "test vector" {
    const key = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const nonce = [_]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    const ad = [_]u8{ 1, 2, 3, 4 } ** 2;
    const msg = [_]u8{ 4, 5, 6, 7 } ** 3;
    var ct = [_]u8{0} ** msg.len;
    const tag = Aegis128X.encrypt(&ct, &msg, &ad, key, nonce);
    std.debug.print("Key: {s}\n", .{std.fmt.bytesToHex(key, .lower)});
    std.debug.print("IV: {s}\n", .{std.fmt.bytesToHex(nonce, .lower)});
    std.debug.print("AD: {s}\n", .{std.fmt.bytesToHex(ad, .lower)});
    std.debug.print("Plaintext: {s}\n", .{std.fmt.bytesToHex(msg, .lower)});
    std.debug.print("Ciphertext: {s}\n", .{std.fmt.bytesToHex(ct, .lower)});
    std.debug.print("128-bit tag: {s}\n", .{std.fmt.bytesToHex(tag, .lower)});
    var msg2 = [_]u8{0} ** msg.len;
    try Aegis128X.decrypt(&msg2, &ct, tag, &ad, key, nonce);
    try std.testing.expectEqualSlices(u8, &msg, &msg2);
}
