const std = @import("std");
const assert = std.debug.assert;
const builtin = @import("builtin");
const crypto = std.crypto;
const mem = std.mem;
const AuthenticationError = std.crypto.errors.AuthenticationError;

const has_vaes = std.Target.x86.featureSetHas(builtin.cpu.features, .vaes);
const AesBlockX2 = if (builtin.cpu.arch == .x86_64 and has_vaes) IntelAesBlockX2 else GenericAesBlockX2;

pub const IntelAesBlockX2 = struct {
    const Self = @This();
    const BlockVec = @Vector(4, u64);
    repr: BlockVec,

    pub inline fn fromBytes(bytes: *const [32]u8) Self {
        const repr = mem.bytesToValue(BlockVec, bytes);
        return Self{ .repr = repr };
    }

    pub inline fn toBytes(block: Self) [32]u8 {
        return mem.toBytes(block.repr);
    }

    pub inline fn xorBytes(block: Self, bytes: *const [32]u8) [32]u8 {
        const x = block.repr ^ fromBytes(bytes).repr;
        return mem.toBytes(x);
    }

    pub inline fn encrypt(block: Self, round_key: Self) Self {
        return Self{
            .repr = asm (
                \\ vaesenc %[rk], %[in], %[out]
                : [out] "=x" (-> BlockVec),
                : [in] "x" (block.repr),
                  [rk] "x" (round_key.repr),
            ),
        };
    }

    pub inline fn xorBlocks(block1: Self, block2: Self) Self {
        return Self{ .repr = block1.repr ^ block2.repr };
    }

    pub inline fn andBlocks(block1: Self, block2: Self) Self {
        return Self{ .repr = block1.repr & block2.repr };
    }

    pub inline fn orBlocks(block1: Self, block2: Self) Self {
        return Self{ .repr = block1.repr | block2.repr };
    }
};

pub const GenericAesBlockX2 = struct {
    const Self = @This();
    const BlockVec = crypto.core.aes.Block;
    repr: [2]BlockVec,

    pub inline fn fromBytes(bytes: *const [32]u8) Self {
        return Self{ .repr = .{
            BlockVec.fromBytes(bytes[0..16]),
            BlockVec.fromBytes(bytes[16..32]),
        } };
    }

    pub inline fn toBytes(block: Self) [32]u8 {
        var out: [32]u8 = undefined;
        mem.copy(u8, out[0..16], &block.repr[0].toBytes());
        mem.copy(u8, out[16..32], &block.repr[1].toBytes());
        return out;
    }

    pub inline fn xorBytes(block: Self, bytes: *const [32]u8) [32]u8 {
        return BlockVec{
            .repr = .{
                block.repr[0].xorBytes(bytes[0..16]),
                block.repr[1].xorBytes(bytes[16..32]),
            },
        };
    }

    pub inline fn encrypt(block: Self, round_key: Self) Self {
        return Self{
            .repr = .{
                block.repr[0].encrypt(round_key.repr[0]),
                block.repr[1].encrypt(round_key.repr[1]),
            },
        };
    }

    pub inline fn xorBlocks(block1: Self, block2: Self) Self {
        return Self{
            .repr = .{
                block1.repr[0].xorBlocks(block2.repr[0]),
                block1.repr[1].xorBlocks(block2.repr[1]),
            },
        };
    }

    pub inline fn andBlocks(block1: Self, block2: Self) Self {
        return Self{
            .repr = .{
                block1.repr[0].andBlocks(block2.repr[0]),
                block1.repr[1].andBlocks(block2.repr[1]),
            },
        };
    }

    pub inline fn orBlocks(block1: Self, block2: Self) Self {
        return Self{
            .repr = .{
                block1.repr[0].orBlocks(block2.repr[0]),
                block1.repr[1].orBlocks(block2.repr[1]),
            },
        };
    }
};

pub const Aegis128X = struct {
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

    fn init(key: [key_length]u8, nonce: [nonce_length]u8) Aegis128X {
        const c0 = AesBlockX2.fromBytes(&[16]u8{ 0x0, 0x1, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 } ** 2);
        const c1 = AesBlockX2.fromBytes(&[16]u8{ 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd } ** 2);

        var key_x2 = key ** 2;
        var nonce_x2 = nonce ** 2;
        const key_block = AesBlockX2.fromBytes(&key_x2);
        const nonce_block = AesBlockX2.fromBytes(&nonce_x2);

        const contexts = AesBlockX2.fromBytes(
            &[_]u8{0x0} ** 15 ++ &[_]u8{0x01} ++
                [_]u8{0x0} ** 15 ++ &[_]u8{0x02},
        );

        var self = Aegis128X{ .s = State{
            key_block.xorBlocks(nonce_block),
            c1,
            c0,
            c1,
            key_block.xorBlocks(nonce_block),
            key_block.xorBlocks(c0),
            key_block.xorBlocks(c1),
            key_block.xorBlocks(c0.xorBlocks(contexts)),
        } };
        var i: usize = 0;
        while (i < 10) : (i += 1) {
            self.update(nonce_block, key_block);
        }
        return self;
    }

    fn enc(self: *Aegis128X, xi: *const [64]u8) [64]u8 {
        const s = self.s;
        const z0 = s[6].xorBlocks(s[1]).xorBlocks(s[2].andBlocks(s[3]));
        const z1 = s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7]));
        const t0 = AesBlockX2.fromBytes(xi[0..32]);
        const t1 = AesBlockX2.fromBytes(xi[32..64]);
        const out0 = t0.xorBlocks(z0);
        const out1 = t1.xorBlocks(z1);
        self.update(t0, t1);
        var ci: [64]u8 = undefined;
        mem.copy(u8, ci[0..32], &out0.toBytes());
        mem.copy(u8, ci[32..64], &out1.toBytes());
        return ci;
    }

    fn dec(self: *Aegis128X, ci: *const [64]u8) [64]u8 {
        const s = self.s;
        const z0 = s[6].xorBlocks(s[1]).xorBlocks(s[2].andBlocks(s[3]));
        const z1 = s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7]));
        const t0 = AesBlockX2.fromBytes(ci[0..32]);
        const t1 = AesBlockX2.fromBytes(ci[32..64]);
        const out0 = t0.xorBlocks(z0);
        const out1 = t1.xorBlocks(z1);
        self.update(out0, out1);
        var xi: [64]u8 = undefined;
        mem.copy(u8, xi[0..32], &out0.toBytes());
        mem.copy(u8, xi[32..64], &out1.toBytes());
        return xi;
    }

    fn decLast(self: *Aegis128X, xn: []u8, cn: []const u8) void {
        const s = self.s;
        const z0 = s[6].xorBlocks(s[1]).xorBlocks(s[2].andBlocks(s[3]));
        const z1 = s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7]));
        var pad = [_]u8{0} ** 64;
        mem.copy(u8, pad[0..cn.len], cn);
        const t0 = AesBlockX2.fromBytes(pad[0..32]);
        const t1 = AesBlockX2.fromBytes(pad[32..64]);
        const out0 = t0.xorBlocks(z0);
        const out1 = t1.xorBlocks(z1);
        mem.copy(u8, pad[0..32], &out0.toBytes());
        mem.copy(u8, pad[32..64], &out1.toBytes());
        mem.copy(u8, xn, pad[0..cn.len]);
        mem.set(u8, pad[cn.len..], 0);
        const v0 = AesBlockX2.fromBytes(pad[0..32]);
        const v1 = AesBlockX2.fromBytes(pad[32..64]);
        self.update(v0, v1);
    }

    fn finalize(self: *Aegis128X, ad_len: usize, msg_len: usize) [tag_length]u8 {
        var s = &self.s;
        var b: [32]u8 = undefined;
        mem.writeIntLittle(u64, b[0..8], @intCast(u64, ad_len) * 8);
        mem.writeIntLittle(u64, b[8..16], @intCast(u64, msg_len) * 8);
        mem.copy(u8, b[16..32], b[0..16]);
        const t = s[2].xorBlocks(AesBlockX2.fromBytes(&b));
        var i: usize = 0;
        while (i < 7) : (i += 1) {
            self.update(t, t);
        }
        const tag32 = s[0].xorBlocks(s[1]).xorBlocks(s[2]).xorBlocks(s[3])
            .xorBlocks(s[4]).xorBlocks(s[5]).xorBlocks(s[6]).toBytes();
        var tag: [tag_length]u8 = undefined;
        for (tag, 0..) |_, j| {
            tag[j] = tag32[j] ^ tag32[j + 16];
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
        while (i + 64 <= ad.len) : (i += 64) {
            _ = aegis.enc(ad[i..][0..64]);
        }
        if (ad.len % 64 != 0) {
            var pad = [_]u8{0} ** 64;
            mem.copy(u8, pad[0 .. ad.len % 64], ad[i..]);
            _ = aegis.enc(&pad);
        }

        i = 0;
        while (i + 64 <= msg.len) : (i += 64) {
            mem.copy(u8, ct[i..][0..64], &aegis.enc(msg[i..][0..64]));
        }
        if (msg.len % 64 != 0) {
            var pad = [_]u8{0} ** 64;
            mem.copy(u8, pad[0 .. msg.len % 64], msg[i..]);
            mem.copy(u8, ct[i..], aegis.enc(&pad)[0 .. msg.len % 64]);
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
            _ = aegis.enc(ad[i..][0..64]);
        }
        if (ad.len % 64 != 0) {
            var pad = [_]u8{0} ** 64;
            mem.copy(u8, pad[0 .. ad.len % 64], ad[i..]);
            _ = aegis.enc(&pad);
        }

        i = 0;
        while (i + 64 <= ct.len) : (i += 64) {
            mem.copy(u8, msg[i..][0..64], &aegis.dec(ct[i..][0..64]));
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
