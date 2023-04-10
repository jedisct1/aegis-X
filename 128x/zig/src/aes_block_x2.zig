const std = @import("std");
const builtin = @import("builtin");
const crypto = std.crypto;
const mem = std.mem;

const has_vaes = std.Target.x86.featureSetHas(builtin.cpu.features, .vaes);
pub const AesBlockX2 = if (builtin.cpu.arch == .x86_64 and has_vaes) IntelAesBlockX2 else GenericAesBlockX2;

const IntelAesBlockX2 = struct {
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

const GenericAesBlockX2 = struct {
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
