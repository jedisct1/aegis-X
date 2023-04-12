const std = @import("std");
const builtin = @import("builtin");
const crypto = std.crypto;
const mem = std.mem;

const has_vaes = std.Target.x86.featureSetHas(builtin.cpu.features, .vaes);
const has_avx512f = std.Target.x86.featureSetHas(builtin.cpu.features, .avx512f);
pub const AesBlockX4 = if (builtin.cpu.arch == .x86_64 and has_vaes and has_avx512f) IntelAesBlockX4 else GenericAesBlockX4;

const IntelAesBlockX4 = struct {
    const Self = @This();
    const BlockVec = @Vector(8, u64);
    repr: BlockVec,

    pub inline fn fromBytes(bytes: *const [64]u8) Self {
        const repr = mem.bytesToValue(BlockVec, bytes);
        return Self{ .repr = repr };
    }

    pub inline fn toBytes(block: Self) [64]u8 {
        return mem.toBytes(block.repr);
    }

    pub inline fn xorBytes(block: Self, bytes: *const [64]u8) [64]u8 {
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

const GenericAesBlockX4 = struct {
    const Self = @This();
    const BlockVec = crypto.core.aes.Block;
    repr: [4]BlockVec,

    pub inline fn fromBytes(bytes: *const [64]u8) Self {
        return Self{ .repr = .{
            BlockVec.fromBytes(bytes[0..16]),
            BlockVec.fromBytes(bytes[16..32]),
            BlockVec.fromBytes(bytes[32..48]),
            BlockVec.fromBytes(bytes[48..64]),
        } };
    }

    pub inline fn toBytes(block: Self) [64]u8 {
        var out: [64]u8 = undefined;
        mem.copy(u8, out[0..16], &block.repr[0].toBytes());
        mem.copy(u8, out[16..32], &block.repr[1].toBytes());
        mem.copy(u8, out[32..48], &block.repr[2].toBytes());
        mem.copy(u8, out[48..64], &block.repr[3].toBytes());
        return out;
    }

    pub inline fn xorBytes(block: Self, bytes: *const [64]u8) [64]u8 {
        return BlockVec{
            .repr = .{
                block.repr[0].xorBytes(bytes[0..16]),
                block.repr[1].xorBytes(bytes[16..32]),
                block.repr[2].xorBytes(bytes[32..48]),
                block.repr[3].xorBytes(bytes[48..64]),
            },
        };
    }

    pub inline fn encrypt(block: Self, round_key: Self) Self {
        return Self{
            .repr = .{
                block.repr[0].encrypt(round_key.repr[0]),
                block.repr[1].encrypt(round_key.repr[1]),
                block.repr[2].encrypt(round_key.repr[2]),
                block.repr[3].encrypt(round_key.repr[3]),
            },
        };
    }

    pub inline fn xorBlocks(block1: Self, block2: Self) Self {
        return Self{
            .repr = .{
                block1.repr[0].xorBlocks(block2.repr[0]),
                block1.repr[1].xorBlocks(block2.repr[1]),
                block1.repr[2].xorBlocks(block2.repr[2]),
                block1.repr[3].xorBlocks(block2.repr[3]),
            },
        };
    }

    pub inline fn andBlocks(block1: Self, block2: Self) Self {
        return Self{
            .repr = .{
                block1.repr[0].andBlocks(block2.repr[0]),
                block1.repr[1].andBlocks(block2.repr[1]),
                block1.repr[2].andBlocks(block2.repr[2]),
                block1.repr[3].andBlocks(block2.repr[3]),
            },
        };
    }

    pub inline fn orBlocks(block1: Self, block2: Self) Self {
        return Self{
            .repr = .{
                block1.repr[0].orBlocks(block2.repr[0]),
                block1.repr[1].orBlocks(block2.repr[1]),
                block1.repr[2].orBlocks(block2.repr[2]),
                block1.repr[3].orBlocks(block2.repr[3]),
            },
        };
    }
};
