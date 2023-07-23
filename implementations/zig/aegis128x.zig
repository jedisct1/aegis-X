const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const AuthenticationError = std.crypto.errors.AuthenticationError;

pub const Aegis128X2 = Aegis128X_(2, 128);
pub const Aegis128X2_256 = Aegis128X_(2, 256);
pub const Aegis128X4 = Aegis128X_(4, 128);
pub const Aegis128X4_256 = Aegis128X_(4, 256);

// Let S = { s0, s1, s2, s3, s4, s5, s6, s7 } represent a regular AEGIS-128L state.
//
// An AEGIS-128X2 state uses two AEGIS-128L states { S0, S1 } represented as:
// { { S0_s0, S1_s0 }, { S0_s1, S1_s1 }, { S0_s2, S1_s2 }, { S0_s3, S1_s3 },
//   { S0_s0, S1_s0 }, { S0_s1, S1_s1 }, { S0_s6, S1_s6 }, { S0_s7, S1_s7 } }
//
// This is the native representation when using VAES instructions with 256 bit vectors.
// That can be generalized to other degrees.
//
// The following AEGIS-128X implementation is pretty much identical to the AEGIS-128L
// one, the main difference being that `AesBlock` (a single AES block) is replaced with
// `AesBlockX` (a vector of `degree` AES blocks).

fn Aegis128X_(comptime degree: u7, comptime tag_bits: u9) type {
    assert(tag_bits == 128 or tag_bits == 256); // tag bits must be 128 or 256
    assert(degree > 0); // degree can't be 0

    return struct {
        const Self = @This();

        pub const key_length = 16;
        pub const nonce_length = 16;
        pub const tag_length: comptime_int = tag_bits / 8;
        pub const ad_max_length = 1 << 61;
        pub const msg_max_length = 1 << 61;
        pub const ct_max_length = msg_max_length + tag_length;

        const AesBlockX = @import("aes_block_multi.zig").AesBlockMulti(degree);
        const blockx_length = AesBlockX.block_length;
        const rate = blockx_length * 2;

        const State = [8]AesBlockX;

        s: State,

        inline fn aesround(in: AesBlockX, rk: AesBlockX) AesBlockX {
            return in.encrypt(rk);
        }

        fn update(self: *Self, m0: AesBlockX, m1: AesBlockX) void {
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
            const c0 = AesBlockX.fromBytes(&[16]u8{ 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 } ** degree);
            const c1 = AesBlockX.fromBytes(&[16]u8{ 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd } ** degree);
            const key_block = AesBlockX.fromBytes(&(key ** degree));
            const nonce_block = AesBlockX.fromBytes(&(nonce ** degree));
            const contexts = ctx: {
                var contexts_bytes = [_]u8{0} ** blockx_length;
                for (1..degree) |i| {
                    contexts_bytes[i * 16] = @intCast(i);
                }
                break :ctx AesBlockX.fromBytes(&contexts_bytes);
            };
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
            for (0..10) |_| {
                self.s[3] = self.s[3].xorBlocks(contexts);
                self.s[7] = self.s[7].xorBlocks(contexts);
                self.update(nonce_block, key_block);
            }
            return self;
        }

        fn absorb(self: *Self, ai: *const [rate]u8) void {
            const t0 = AesBlockX.fromBytes(ai[0..blockx_length]);
            const t1 = AesBlockX.fromBytes(ai[blockx_length..rate]);
            self.update(t0, t1);
        }

        fn enc(self: *Self, xi: *const [rate]u8) [rate]u8 {
            const s = self.s;
            const z0 = s[6].xorBlocks(s[1]).xorBlocks(s[2].andBlocks(s[3]));
            const z1 = s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7]));
            const t0 = AesBlockX.fromBytes(xi[0..blockx_length]);
            const t1 = AesBlockX.fromBytes(xi[blockx_length..rate]);
            const out0 = t0.xorBlocks(z0);
            const out1 = t1.xorBlocks(z1);
            self.update(t0, t1);
            var ci: [rate]u8 = undefined;
            @memcpy(ci[0..blockx_length], &out0.toBytes());
            @memcpy(ci[blockx_length..rate], &out1.toBytes());
            return ci;
        }

        fn dec(self: *Self, ci: *const [rate]u8) [rate]u8 {
            const s = self.s;
            const z0 = s[6].xorBlocks(s[1]).xorBlocks(s[2].andBlocks(s[3]));
            const z1 = s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7]));
            const t0 = AesBlockX.fromBytes(ci[0..blockx_length]);
            const t1 = AesBlockX.fromBytes(ci[blockx_length..rate]);
            const out0 = t0.xorBlocks(z0);
            const out1 = t1.xorBlocks(z1);
            self.update(out0, out1);
            var xi: [rate]u8 = undefined;
            @memcpy(xi[0..blockx_length], &out0.toBytes());
            @memcpy(xi[blockx_length..rate], &out1.toBytes());
            return xi;
        }

        fn decLast(self: *Self, xn: []u8, cn: []const u8) void {
            const s = self.s;
            const z0 = s[6].xorBlocks(s[1]).xorBlocks(s[2].andBlocks(s[3]));
            const z1 = s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7]));
            var pad = [_]u8{0} ** rate;
            @memcpy(pad[0..cn.len], cn);
            const t0 = AesBlockX.fromBytes(pad[0..blockx_length]);
            const t1 = AesBlockX.fromBytes(pad[blockx_length..rate]);
            const out0 = t0.xorBlocks(z0);
            const out1 = t1.xorBlocks(z1);
            @memcpy(pad[0..blockx_length], &out0.toBytes());
            @memcpy(pad[blockx_length..rate], &out1.toBytes());
            @memcpy(xn, pad[0..cn.len]);
            @memset(pad[cn.len..], 0);
            const v0 = AesBlockX.fromBytes(pad[0..blockx_length]);
            const v1 = AesBlockX.fromBytes(pad[blockx_length..rate]);
            self.update(v0, v1);
        }

        fn finalize(self: *Self, ad_len: usize, msg_len: usize) [tag_length]u8 {
            var s = &self.s;
            var b: [blockx_length]u8 = undefined;
            mem.writeIntLittle(u64, b[0..8], @as(u64, @intCast(ad_len)) * 8);
            mem.writeIntLittle(u64, b[8..16], @as(u64, @intCast(msg_len)) * 8);
            inline for (1..degree) |i| {
                @memcpy(b[i * 16 ..][0..16], b[0..16]);
            }
            const t = s[2].xorBlocks(AesBlockX.fromBytes(&b));
            for (0..7) |_| {
                self.update(t, t);
            }
            var tag: [tag_length]u8 = undefined;
            if (tag_length == 16) {
                var tag_multi = s[0].xorBlocks(s[1]).xorBlocks(s[2]).xorBlocks(s[3]).xorBlocks(s[4]).xorBlocks(s[5]).xorBlocks(s[6]).toBytes();
                @memcpy(tag[0..], tag_multi[0..16]);
                for (1..degree) |d| {
                    for (0..16) |i| {
                        tag[i] ^= tag_multi[d * 16 + i];
                    }
                }
            } else {
                var tag_multi_0 = s[0].xorBlocks(s[1]).xorBlocks(s[2]).xorBlocks(s[3]).toBytes();
                var tag_multi_1 = s[4].xorBlocks(s[5]).xorBlocks(s[6]).xorBlocks(s[7]).toBytes();
                @memcpy(tag[0..16], tag_multi_0[0..16]);
                @memcpy(tag[16..32], tag_multi_1[0..16]);
                for (1..degree) |d| {
                    for (0..16) |i| {
                        tag[i] ^= tag_multi_0[d * 16 + i];
                        tag[i + 16] ^= tag_multi_1[d * 16 + i];
                    }
                }
            }
            return tag;
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
            while (i + rate <= ad.len) : (i += rate) {
                aegis.absorb(ad[i..][0..rate]);
            }
            if (ad.len % rate != 0) {
                var pad = [_]u8{0} ** rate;
                @memcpy(pad[0 .. ad.len % rate], ad[i..]);
                aegis.absorb(&pad);
            }

            i = 0;
            while (i + rate <= msg.len) : (i += rate) {
                @memcpy(ct[i..][0..rate], &aegis.enc(msg[i..][0..rate]));
            }
            if (msg.len % rate != 0) {
                var pad = [_]u8{0} ** rate;
                @memcpy(pad[0 .. msg.len % rate], msg[i..]);
                @memcpy(ct[i..], aegis.enc(&pad)[0 .. msg.len % rate]);
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
            while (i + rate <= ad.len) : (i += rate) {
                aegis.absorb(ad[i..][0..rate]);
            }
            if (ad.len % rate != 0) {
                var pad = [_]u8{0} ** rate;
                @memcpy(pad[0 .. ad.len % rate], ad[i..]);
                aegis.absorb(&pad);
            }

            i = 0;
            while (i + rate <= ct.len) : (i += rate) {
                @memcpy(msg[i..][0..rate], &aegis.dec(ct[i..][0..rate]));
            }
            if (ct.len % rate != 0) {
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
