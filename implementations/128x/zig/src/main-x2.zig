const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const AuthenticationError = std.crypto.errors.AuthenticationError;

const AesBlockX2 = @import("aes_block_x2.zig").AesBlockX2;

pub const Aegis128X = Aegis128Xt(128);
pub const Aegis128X_256 = Aegis128Xt(256);

fn Aegis128Xt(comptime tag_bits: u9) type {
    assert(tag_bits == 128 or tag_bits == 256); // tag bits must be 128 or 256

    return struct {
        const Self = @This();
        pub const block_length: usize = 64;
        pub const key_length: usize = 16;
        pub const nonce_length: usize = 16;
        pub const tag_length: usize = 16;
        pub const ad_max_length: usize = 1 << 61;
        pub const msg_max_length: usize = 1 << 61;
        pub const ct_max_length: usize = msg_max_length + tag_length;

        const State = [8]AesBlockX2;

        s: State,

        inline fn aesround(in: AesBlockX2, rk: AesBlockX2) AesBlockX2 {
            return in.encrypt(rk);
        }

        fn update(self: *Aegis128X, m0: AesBlockX2, m1: AesBlockX2) void {
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
            const c0 = AesBlockX2.fromBytes(&[16]u8{ 0x0, 0x1, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 } ** 2);
            const c1 = AesBlockX2.fromBytes(&[16]u8{ 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd } ** 2);

            const key_x2 = key ** 2;
            const nonce_x2 = nonce ** 2;
            const key_block = AesBlockX2.fromBytes(&key_x2);
            const nonce_block = AesBlockX2.fromBytes(&nonce_x2);

            const contexts = AesBlockX2.fromBytes(
                &[_]u8{0} ++ [_]u8{0} ** 15 ++ // context for first instance is 0
                    [_]u8{1} ++ [_]u8{0} ** 15, // context for second instance is 1
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

        fn absorb(state: *Self, src: *const [64]u8) void {
            const msg0 = AesBlockX2.fromBytes(src[0..32]);
            const msg1 = AesBlockX2.fromBytes(src[32..64]);
            state.update(msg0, msg1);
        }

        fn enc(self: *Self, xi: *const [64]u8) [64]u8 {
            const s = &self.s;
            const z0 = s[6].xorBlocks(s[1]).xorBlocks(s[2].andBlocks(s[3]));
            const z1 = s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7]));
            const t0 = AesBlockX2.fromBytes(xi[0..32]);
            const t1 = AesBlockX2.fromBytes(xi[32..64]);
            const out0 = t0.xorBlocks(z0);
            const out1 = t1.xorBlocks(z1);
            self.update(t0, t1);
            var ci: [64]u8 = undefined;
            @memcpy(ci[0..32], &out0.toBytes());
            @memcpy(ci[32..64], &out1.toBytes());
            return ci;
        }

        fn dec(self: *Self, ci: *const [64]u8) [64]u8 {
            const s = &self.s;
            const z0 = s[6].xorBlocks(s[1]).xorBlocks(s[2].andBlocks(s[3]));
            const z1 = s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7]));
            const t0 = AesBlockX2.fromBytes(ci[0..32]);
            const t1 = AesBlockX2.fromBytes(ci[32..64]);
            const out0 = t0.xorBlocks(z0);
            const out1 = t1.xorBlocks(z1);
            self.update(out0, out1);
            var xi: [64]u8 = undefined;
            @memcpy(xi[0..32], &out0.toBytes());
            @memcpy(xi[32..64], &out1.toBytes());
            return xi;
        }

        fn decLast(self: *Self, xn: []u8, cn: []const u8) void {
            const s = &self.s;
            const z0 = s[6].xorBlocks(s[1]).xorBlocks(s[2].andBlocks(s[3]));
            const z1 = s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7]));
            var pad = [_]u8{0} ** 64;
            @memcpy(pad[0..cn.len], cn);
            const t0 = AesBlockX2.fromBytes(pad[0..32]);
            const t1 = AesBlockX2.fromBytes(pad[32..64]);
            const out0 = t0.xorBlocks(z0);
            const out1 = t1.xorBlocks(z1);
            @memcpy(pad[0..32], &out0.toBytes());
            @memcpy(pad[32..64], &out1.toBytes());
            @memcpy(xn, pad[0..cn.len]);
            @memset(pad[cn.len..], 0);
            const v0 = AesBlockX2.fromBytes(pad[0..32]);
            const v1 = AesBlockX2.fromBytes(pad[32..64]);
            self.update(v0, v1);
        }

        fn finalize(self: *Self, ad_len: usize, msg_len: usize) [tag_length]u8 {
            var s = &self.s;
            var b: [32]u8 = undefined;
            mem.writeIntLittle(u64, b[0..8], @intCast(u64, ad_len) * 8);
            mem.writeIntLittle(u64, b[8..16], @intCast(u64, msg_len) * 8);
            @memcpy(b[16..32], b[0..16]);
            const t = s[2].xorBlocks(AesBlockX2.fromBytes(&b));
            var i: usize = 0;
            while (i < 7) : (i += 1) {
                self.update(t, t);
            }
            if (tag_length == 16) {
                const tag32 = s[0].xorBlocks(s[1]).xorBlocks(s[2]).xorBlocks(s[3])
                    .xorBlocks(s[4]).xorBlocks(s[5]).xorBlocks(s[6]).toBytes();
                var tag: [tag_length]u8 = undefined;
                for (tag, 0..) |_, j| {
                    tag[j] = tag32[j] ^ tag32[j + 16];
                }
                return tag;
            } else {
                const tag32_0 = s[0].xorBlocks(s[1]).xorBlocks(s[2]).xorBlocks(s[3]).toBytes();
                const tag32_1 = s[4].xorBlocks(s[5]).xorBlocks(s[6]).xorBlocks(s[7]).toBytes();
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
            while (i + 64 <= ad.len) : (i += 64) {
                aegis.absorb(ad[i..][0..64]);
            }
            if (ad.len % 64 != 0) {
                var pad = [_]u8{0} ** 64;
                @memcpy(pad[0 .. ad.len % 64], ad[i..]);
                aegis.absorb(&pad);
            }

            i = 0;
            while (i + 64 <= msg.len) : (i += 64) {
                @memcpy(ct[i..][0..64], &aegis.enc(msg[i..][0..64]));
            }
            if (msg.len % 64 != 0) {
                var pad = [_]u8{0} ** 64;
                @memcpy(pad[0 .. msg.len % 64], msg[i..]);
                const ks = aegis.enc(&pad);
                @memcpy(ct[i..], ks[0 .. msg.len % 64]);
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
            while (i + 64 <= ad.len) : (i += 64) {
                aegis.absorb(ad[i..][0..64]);
            }
            if (ad.len % 64 != 0) {
                var pad = [_]u8{0} ** 64;
                @memcpy(pad[0 .. ad.len % 64], ad[i..]);
                aegis.absorb(&pad);
            }

            i = 0;
            while (i + 64 <= ct.len) : (i += 64) {
                @memcpy(msg[i..][0..64], &aegis.dec(ct[i..][0..64]));
            }
            if (ct.len % 64 != 0) {
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

pub const Aegis128XMac = struct {
    const Self = @This();
    const T = Aegis128X;

    pub const mac_length = T.tag_length;
    pub const key_length = T.key_length;
    pub const block_length = T.block_length;

    state: T,
    buf: [block_length]u8 = undefined,
    off: usize = 0,
    msg_len: usize = 0,

    /// Initialize a state for the MAC function
    pub fn init(key: *const [key_length]u8) Self {
        const nonce = [_]u8{0} ** T.nonce_length;
        return Self{
            .state = T.init(key.*, nonce),
        };
    }

    /// Add data to the state
    pub fn update(self: *Self, b: []const u8) void {
        self.msg_len += b.len;

        const len_partial = @min(b.len, block_length - self.off);
        @memcpy(self.buf[self.off..][0..len_partial], b[0..len_partial]);
        self.off += len_partial;
        if (self.off < block_length) {
            return;
        }
        self.state.absorb(&self.buf);

        var i = len_partial;
        self.off = 0;
        while (i + block_length <= b.len) : (i += block_length) {
            self.state.absorb(b[i..][0..block_length]);
        }
        if (i != b.len) {
            self.off = b.len - i;
            @memcpy(self.buf[0..self.off], b[i..]);
        }
    }

    /// Return an authentication tag for the current state
    pub fn final(self: *Self, out: *[mac_length]u8) void {
        if (self.off > 0) {
            var pad = [_]u8{0} ** block_length;
            @memcpy(pad[0..self.off], self.buf[0..self.off]);
            self.state.absorb(&pad);
        }
        out.* = self.state.finalize(self.msg_len, 0);
    }

    /// Return an authentication tag for a message and a key
    pub fn create(out: *[mac_length]u8, msg: []const u8, key: *const [key_length]u8) void {
        var ctx = Self.init(key);
        ctx.update(msg);
        ctx.final(out);
    }

    pub const Error = error{};
    pub const Writer = std.io.Writer(*Self, Error, write);

    fn write(self: *Self, bytes: []const u8) Error!usize {
        self.update(bytes);
        return bytes.len;
    }

    pub fn writer(self: *Self) Writer {
        return .{ .context = self };
    }
};

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

test "aegis MAC" {
    const key = [_]u8{0x00} ** Aegis128XMac.key_length;
    var msg: [64]u8 = undefined;
    for (&msg, 0..) |*m, i| {
        m.* = @truncate(u8, i);
    }
    const st_init = Aegis128XMac.init(&key);
    var st = st_init;
    var tag: [Aegis128XMac.mac_length]u8 = undefined;

    st.update(msg[0..32]);
    st.update(msg[32..]);
    st.final(&tag);
}
