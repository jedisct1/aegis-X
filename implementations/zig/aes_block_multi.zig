const std = @import("std");
const builtin = @import("builtin");
const crypto = std.crypto;
const mem = std.mem;

const has_vaes = builtin.cpu.arch == .x86_64 and std.Target.x86.featureSetHas(builtin.cpu.features, .vaes);
const has_avx512f = builtin.cpu.arch == .x86_64 and std.Target.x86.featureSetHas(builtin.cpu.features, .avx512f);

pub fn AesBlockMulti(comptime degree: u7) type {
    const IntelAesBlockX = struct {
        const Self = @This();
        const BlockVec = @Vector(degree * 2, u64);
        repr: BlockVec,

        pub const block_length = @as(usize, degree) * 16;

        pub inline fn fromBytes(bytes: *const [degree * 16]u8) Self {
            const repr = mem.bytesToValue(BlockVec, bytes);
            return Self{ .repr = repr };
        }

        pub inline fn toBytes(block: Self) [degree * 16]u8 {
            return mem.toBytes(block.repr);
        }

        pub inline fn xorBytes(block: Self, bytes: *const [degree * 16]u8) [32]u8 {
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
    };

    const GenericAesBlockX = struct {
        const Self = @This();
        const BlockVec = crypto.core.aes.Block;
        repr: [degree]BlockVec,

        pub const block_length = @as(usize, degree) * 16;

        pub inline fn fromBytes(bytes: *const [degree * 16]u8) Self {
            var out: Self = undefined;
            inline for (0..degree) |i| {
                out.repr[i] = BlockVec.fromBytes(bytes[i * 16 ..][0..16]);
            }
            return out;
        }

        pub inline fn toBytes(block: Self) [degree * 16]u8 {
            var out: [degree * 16]u8 = undefined;
            inline for (0..degree) |i| {
                @memcpy(out[i * 16 ..][0..16], &block.repr[i].toBytes());
            }
            return out;
        }

        pub inline fn xorBytes(block: Self, bytes: *const [degree * 16]u8) [32]u8 {
            var out: Self = undefined;
            inline for (0..degree) |i| {
                out.repr[i] = block.repr[i].xorBytes(bytes[i * 16 ..][0..16]);
            }
            return out;
        }

        pub inline fn encrypt(block: Self, round_key: Self) Self {
            var out: Self = undefined;
            inline for (0..degree) |i| {
                out.repr[i] = block.repr[i].encrypt(round_key.repr[i]);
            }
            return out;
        }

        pub inline fn xorBlocks(block1: Self, block2: Self) Self {
            var out: Self = undefined;
            inline for (0..degree) |i| {
                out.repr[i] = block1.repr[i].xorBlocks(block2.repr[i]);
            }
            return out;
        }

        pub inline fn andBlocks(block1: Self, block2: Self) Self {
            var out: Self = undefined;
            inline for (0..degree) |i| {
                out.repr[i] = block1.repr[i].andBlocks(block2.repr[i]);
            }
            return out;
        }
    };

    if (has_vaes) {
        if (degree == 2) return IntelAesBlockX;
        if (degree == 4 and has_avx512f) return IntelAesBlockX;
    }
    return GenericAesBlockX;
}
