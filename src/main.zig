//! Areion is a family of AES-based permutations optimized for speed on small inputs.
//!
//! The Areion512 and Areion256 variants provide 512-bit and 256-bit permutations respectively,
//! along with hash functions built using the Merkle-Damgård construction.
//!
//! The Areion-OPP modes provide authenticated encryption with associated data (AEAD)
//! using the Offset Public Permutation construction.
//!
//! https://eprint.iacr.org/2023/794

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const assert = std.debug.assert;
const AuthenticationError = crypto.errors.AuthenticationError;

const AesBlock = crypto.core.aes.Block;
const AesBlockVec = crypto.core.aes.BlockVec;

pub const och = @import("och.zig");
pub const AreionOCH = och.AreionOCH;

/// Vectorized Areion512 permutation for parallel processing of multiple states.
///
/// Processes `count` independent 512-bit states simultaneously using SIMD,
/// providing significant throughput improvements on supported hardware.
pub fn Areion512Vec(comptime count: usize) type {
    const BlockVec = AesBlockVec(count);

    return struct {
        const State = @This();

        /// Total block length in bytes across all parallel states.
        pub const block_length = Areion512.block_length * count;
        /// Total digest length in bytes across all parallel states.
        pub const digest_length = Areion512.digest_length * count;

        blocks: [4]BlockVec,

        fn broadcast(block: AesBlock) BlockVec {
            const single = block.toBytes();
            var repeated: [16 * count]u8 = undefined;
            inline for (0..count) |i| {
                repeated[i * 16 ..][0..16].* = single;
            }
            return BlockVec.fromBytes(&repeated);
        }

        /// Creates a vectorized state from concatenated byte arrays.
        /// Input should contain `count` consecutive 64-byte blocks.
        pub fn fromBytes(bytes: *const [64 * count]u8) State {
            var transposed: [4][16 * count]u8 = undefined;
            inline for (0..count) |i| {
                inline for (0..4) |j| {
                    transposed[j][i * 16 ..][0..16].* = bytes[i * 64 + j * 16 ..][0..16].*;
                }
            }
            return .{
                .blocks = .{
                    BlockVec.fromBytes(&transposed[0]),
                    BlockVec.fromBytes(&transposed[1]),
                    BlockVec.fromBytes(&transposed[2]),
                    BlockVec.fromBytes(&transposed[3]),
                },
            };
        }

        /// Serializes the vectorized state to concatenated byte arrays.
        pub fn toBytes(state: State) [64 * count]u8 {
            const t0 = state.blocks[0].toBytes();
            const t1 = state.blocks[1].toBytes();
            const t2 = state.blocks[2].toBytes();
            const t3 = state.blocks[3].toBytes();
            var bytes: [64 * count]u8 = undefined;
            inline for (0..count) |i| {
                bytes[i * 64 + 0 ..][0..16].* = t0[i * 16 ..][0..16].*;
                bytes[i * 64 + 16 ..][0..16].* = t1[i * 16 ..][0..16].*;
                bytes[i * 64 + 32 ..][0..16].* = t2[i * 16 ..][0..16].*;
                bytes[i * 64 + 48 ..][0..16].* = t3[i * 16 ..][0..16].*;
            }
            return bytes;
        }

        /// XORs two vectorized states element-wise.
        pub fn xorBlocks(state: State, other: State) State {
            return .{
                .blocks = .{
                    state.blocks[0].xorBlocks(other.blocks[0]),
                    state.blocks[1].xorBlocks(other.blocks[1]),
                    state.blocks[2].xorBlocks(other.blocks[2]),
                    state.blocks[3].xorBlocks(other.blocks[3]),
                },
            };
        }

        fn round(x0: *BlockVec, x1: *BlockVec, x2: *BlockVec, x3: *BlockVec, rc_vec: BlockVec, rc1_vec: BlockVec) void {
            const orig_x0 = x0.*;
            const orig_x2 = x2.*;
            x1.* = orig_x0.encrypt(x1.*);
            x3.* = orig_x2.encrypt(x3.*);
            x0.* = orig_x0.encryptLast(rc1_vec);
            x2.* = orig_x2.encryptLast(rc_vec).encrypt(rc1_vec);
        }

        /// Applies the 15-round Areion512 permutation to all parallel states.
        pub fn permute(state: *State) void {
            const rcs = comptime rcs: {
                const ints = [15]u128{
                    0x243f6a8885a308d313198a2e03707344, 0xa4093822299f31d0082efa98ec4e6c89, 0x452821e638d01377be5466cf34e90c6c, 0xc0ac29b7c97c50dd3f84d5b5b5470917, 0x9216d5d98979fb1bd1310ba698dfb5ac, 0x2ffd72dbd01adfb7b8e1afed6a267e96, 0xba7c9045f12c7f9924a19947b3916cf7, 0x801f2e2858efc16636920d871574e690, 0xa458fea3f4933d7e0d95748f728eb658, 0x718bcd5882154aee7b54a41dc25a59b5, 0x9c30d5392af26013c5d1b023286085f0, 0xca417918b8db38ef8e79dcb0603a180e, 0x6c9e0e8bb01e8a3ed71577c1bd314b27, 0x78af2fda55605c60e65525f3aa55ab94, 0x5748986263e8144055ca396a2aab10b6,
                };
                var rcs: [ints.len]BlockVec = undefined;
                for (&rcs, ints) |*rc, v| {
                    var b: [16]u8 = undefined;
                    mem.writeInt(u128, &b, v, .little);
                    rc.* = broadcast(AesBlock.fromBytes(&b));
                }
                break :rcs rcs;
            };
            const rc1_vec = comptime broadcast(AesBlock.fromBytes(&([_]u8{0} ** 16)));

            var i: usize = 0;
            while (i < 12) : (i += 4) {
                round(&state.blocks[0], &state.blocks[1], &state.blocks[2], &state.blocks[3], rcs[i + 0], rc1_vec);
                round(&state.blocks[1], &state.blocks[2], &state.blocks[3], &state.blocks[0], rcs[i + 1], rc1_vec);
                round(&state.blocks[2], &state.blocks[3], &state.blocks[0], &state.blocks[1], rcs[i + 2], rc1_vec);
                round(&state.blocks[3], &state.blocks[0], &state.blocks[1], &state.blocks[2], rcs[i + 3], rc1_vec);
            }

            round(&state.blocks[0], &state.blocks[1], &state.blocks[2], &state.blocks[3], rcs[12], rc1_vec);
            round(&state.blocks[1], &state.blocks[2], &state.blocks[3], &state.blocks[0], rcs[13], rc1_vec);
            round(&state.blocks[2], &state.blocks[3], &state.blocks[0], &state.blocks[1], rcs[14], rc1_vec);

            const temp = state.blocks[0];
            state.blocks[0] = state.blocks[3];
            state.blocks[3] = state.blocks[2];
            state.blocks[2] = state.blocks[1];
            state.blocks[1] = temp;
        }

        /// Applies the inverse of the Areion512 permutation.
        pub fn inversePermute(state: *State) void {
            const temp = state.blocks[0];
            state.blocks[0] = state.blocks[1];
            state.blocks[1] = state.blocks[2];
            state.blocks[2] = state.blocks[3];
            state.blocks[3] = temp;

            const rcs = comptime rcs: {
                const ints = [15]u128{
                    0x243f6a8885a308d313198a2e03707344, 0xa4093822299f31d0082efa98ec4e6c89, 0x452821e638d01377be5466cf34e90c6c, 0xc0ac29b7c97c50dd3f84d5b5b5470917, 0x9216d5d98979fb1bd1310ba698dfb5ac, 0x2ffd72dbd01adfb7b8e1afed6a267e96, 0xba7c9045f12c7f9924a19947b3916cf7, 0x801f2e2858efc16636920d871574e690, 0xa458fea3f4933d7e0d95748f728eb658, 0x718bcd5882154aee7b54a41dc25a59b5, 0x9c30d5392af26013c5d1b023286085f0, 0xca417918b8db38ef8e79dcb0603a180e, 0x6c9e0e8bb01e8a3ed71577c1bd314b27, 0x78af2fda55605c60e65525f3aa55ab94, 0x5748986263e8144055ca396a2aab10b6,
                };
                var rcs: [ints.len]BlockVec = undefined;
                for (&rcs, ints) |*rc, v| {
                    var b: [16]u8 = undefined;
                    mem.writeInt(u128, &b, v, .little);
                    rc.* = broadcast(AesBlock.fromBytes(&b));
                }
                break :rcs rcs;
            };
            const rc1_vec = comptime broadcast(AesBlock.fromBytes(&([_]u8{0} ** 16)));

            const invRound = struct {
                fn f(x0: *BlockVec, x1: *BlockVec, x2: *BlockVec, x3: *BlockVec, rc_vec: BlockVec, zero_vec: BlockVec) void {
                    x0.* = x0.decryptLast(zero_vec);
                    x2.* = x2.invMixColumns().decryptLast(rc_vec).decryptLast(zero_vec);
                    x1.* = x0.encrypt(x1.*);
                    x3.* = x2.encrypt(x3.*);
                }
            }.f;

            invRound(&state.blocks[2], &state.blocks[3], &state.blocks[0], &state.blocks[1], rcs[14], rc1_vec);
            invRound(&state.blocks[1], &state.blocks[2], &state.blocks[3], &state.blocks[0], rcs[13], rc1_vec);
            invRound(&state.blocks[0], &state.blocks[1], &state.blocks[2], &state.blocks[3], rcs[12], rc1_vec);

            var i: usize = 0;
            while (i < 12) : (i += 4) {
                invRound(&state.blocks[3], &state.blocks[0], &state.blocks[1], &state.blocks[2], rcs[11 - i], rc1_vec);
                invRound(&state.blocks[2], &state.blocks[3], &state.blocks[0], &state.blocks[1], rcs[10 - i], rc1_vec);
                invRound(&state.blocks[1], &state.blocks[2], &state.blocks[3], &state.blocks[0], rcs[9 - i], rc1_vec);
                invRound(&state.blocks[0], &state.blocks[1], &state.blocks[2], &state.blocks[3], rcs[8 - i], rc1_vec);
            }
        }
    };
}

/// Vectorized Areion256 permutation for parallel processing of multiple states.
///
/// Processes `count` independent 256-bit states simultaneously using SIMD,
/// providing significant throughput improvements on supported hardware.
pub fn Areion256Vec(comptime count: usize) type {
    const BlockVec = AesBlockVec(count);

    return struct {
        const State = @This();

        /// Total block length in bytes across all parallel states.
        pub const block_length = Areion256.block_length * count;
        /// Total digest length in bytes across all parallel states.
        pub const digest_length = Areion256.digest_length * count;

        blocks: [2]BlockVec,

        fn broadcast(block: AesBlock) BlockVec {
            const single = block.toBytes();
            var repeated: [16 * count]u8 = undefined;
            inline for (0..count) |i| {
                repeated[i * 16 ..][0..16].* = single;
            }
            return BlockVec.fromBytes(&repeated);
        }

        /// Creates a vectorized state from concatenated byte arrays.
        /// Input should contain `count` consecutive 32-byte blocks.
        pub fn fromBytes(bytes: *const [32 * count]u8) State {
            var transposed: [2][16 * count]u8 = undefined;
            inline for (0..count) |i| {
                inline for (0..2) |j| {
                    transposed[j][i * 16 ..][0..16].* = bytes[i * 32 + j * 16 ..][0..16].*;
                }
            }
            return .{
                .blocks = .{
                    BlockVec.fromBytes(&transposed[0]),
                    BlockVec.fromBytes(&transposed[1]),
                },
            };
        }

        /// Serializes the vectorized state to concatenated byte arrays.
        pub fn toBytes(state: State) [32 * count]u8 {
            const t0 = state.blocks[0].toBytes();
            const t1 = state.blocks[1].toBytes();
            var bytes: [32 * count]u8 = undefined;
            inline for (0..count) |i| {
                bytes[i * 32 + 0 ..][0..16].* = t0[i * 16 ..][0..16].*;
                bytes[i * 32 + 16 ..][0..16].* = t1[i * 16 ..][0..16].*;
            }
            return bytes;
        }

        /// XORs two vectorized states element-wise.
        pub fn xorBlocks(state: State, other: State) State {
            return .{
                .blocks = .{
                    state.blocks[0].xorBlocks(other.blocks[0]),
                    state.blocks[1].xorBlocks(other.blocks[1]),
                },
            };
        }

        /// Applies the 10-round Areion256 permutation to all parallel states.
        pub fn permute(state: *State) void {
            const rcs = comptime rcs: {
                const ints = [10]u128{
                    0x243f6a8885a308d313198a2e03707344, 0xa4093822299f31d0082efa98ec4e6c89, 0x452821e638d01377be5466cf34e90c6c, 0xc0ac29b7c97c50dd3f84d5b5b5470917, 0x9216d5d98979fb1bd1310ba698dfb5ac, 0x2ffd72dbd01adfb7b8e1afed6a267e96, 0xba7c9045f12c7f9924a19947b3916cf7, 0x801f2e2858efc16636920d871574e690, 0xa458fea3f4933d7e0d95748f728eb658, 0x718bcd5882154aee7b54a41dc25a59b5,
                };
                var rcs: [ints.len]BlockVec = undefined;
                for (&rcs, ints) |*rc, v| {
                    var b: [16]u8 = undefined;
                    mem.writeInt(u128, &b, v, .little);
                    rc.* = broadcast(AesBlock.fromBytes(&b));
                }
                break :rcs rcs;
            };
            const rc1_vec = comptime broadcast(AesBlock.fromBytes(&([_]u8{0} ** 16)));

            inline for (rcs, 0..) |rc_vec, r| {
                if (r % 2 == 0) {
                    const new_x1 = state.blocks[0].encrypt(rc_vec).encrypt(state.blocks[1]);
                    const new_x0 = state.blocks[0].encryptLast(rc1_vec);
                    state.blocks[0] = new_x0;
                    state.blocks[1] = new_x1;
                } else {
                    const new_x0 = state.blocks[1].encrypt(rc_vec).encrypt(state.blocks[0]);
                    const new_x1 = state.blocks[1].encryptLast(rc1_vec);
                    state.blocks[0] = new_x0;
                    state.blocks[1] = new_x1;
                }
            }
        }

        /// Applies the inverse of the Areion256 permutation.
        pub fn inversePermute(state: *State) void {
            const rcs = comptime rcs: {
                const ints = [10]u128{
                    0x243f6a8885a308d313198a2e03707344, 0xa4093822299f31d0082efa98ec4e6c89, 0x452821e638d01377be5466cf34e90c6c, 0xc0ac29b7c97c50dd3f84d5b5b5470917, 0x9216d5d98979fb1bd1310ba698dfb5ac, 0x2ffd72dbd01adfb7b8e1afed6a267e96, 0xba7c9045f12c7f9924a19947b3916cf7, 0x801f2e2858efc16636920d871574e690, 0xa458fea3f4933d7e0d95748f728eb658, 0x718bcd5882154aee7b54a41dc25a59b5,
                };
                var rcs: [ints.len]BlockVec = undefined;
                for (&rcs, ints) |*rc, v| {
                    var b: [16]u8 = undefined;
                    mem.writeInt(u128, &b, v, .little);
                    rc.* = broadcast(AesBlock.fromBytes(&b));
                }
                break :rcs rcs;
            };
            const rc1_vec = comptime broadcast(AesBlock.fromBytes(&([_]u8{0} ** 16)));

            var round_idx: usize = 0;
            while (round_idx < 10) : (round_idx += 2) {
                {
                    const rc_vec = rcs[9 - round_idx];
                    const new_x1 = state.blocks[1].decryptLast(rc1_vec);
                    const new_x0 = new_x1.encrypt(rc_vec).encrypt(state.blocks[0]);
                    state.blocks[0] = new_x0;
                    state.blocks[1] = new_x1;
                }
                {
                    const rc_vec = rcs[8 - round_idx];
                    const new_x0 = state.blocks[0].decryptLast(rc1_vec);
                    const new_x1 = new_x0.encrypt(rc_vec).encrypt(state.blocks[1]);
                    state.blocks[0] = new_x0;
                    state.blocks[1] = new_x1;
                }
            }
        }
    };
}

/// Areion512 is a 512-bit AES-based cryptographic permutation.
///
/// The permutation operates on a 64-byte state using 15 rounds of AES-based
/// transformations. It provides a hash function via Merkle-Damgård construction
/// with a 32-byte digest. Optimized for hardware AES acceleration.
pub const Areion512 = struct {
    /// Input block size in bytes for the hash function (rate portion).
    pub const block_length = 32;
    /// Output digest size in bytes.
    pub const digest_length = 32;
    /// Hash options (currently unused, for API compatibility).
    pub const Options = struct {};

    blocks: [4]AesBlock = blocks: {
        const ints = [_]u128{ 0x0, 0x0, 0x6a09e667bb67ae853c6ef372a54ff53a, 0x510e527f9b05688c1f83d9ab5be0cd19 };
        var blocks: [4]AesBlock = undefined;
        for (&blocks, ints) |*rc, v| {
            var b: [16]u8 = undefined;
            mem.writeInt(u128, &b, v, .little);
            rc.* = AesBlock.fromBytes(&b);
        }
        break :blocks blocks;
    },

    /// Creates a state from a 64-byte array.
    pub fn fromBytes(bytes: [64]u8) Areion512 {
        var blocks: [4]AesBlock = undefined;
        inline for (&blocks, 0..) |*b, i| {
            b.* = AesBlock.fromBytes(bytes[i * 16 ..][0..16]);
        }
        return .{ .blocks = blocks };
    }

    /// Sets the rate portion of the sponge state (first 32 bytes).
    pub fn setRate(d: *Areion512, bytes: [32]u8) void {
        d.blocks[0] = AesBlock.fromBytes(bytes[0..16]);
        d.blocks[1] = AesBlock.fromBytes(bytes[16..32]);
    }

    /// Sets the capacity portion of the sponge state (last 32 bytes).
    pub fn setCapacity(d: *Areion512, s: [32]u8) void {
        d.blocks[2] = AesBlock.fromBytes(s[0..16]);
        d.blocks[3] = AesBlock.fromBytes(s[16..32]);
    }

    /// Returns the capacity portion of the sponge state.
    pub fn getCapacity(d: Areion512) [32]u8 {
        var s: [32]u8 = undefined;
        @memcpy(s[0..16], &d.blocks[2].toBytes());
        @memcpy(s[16..32], &d.blocks[3].toBytes());
        return s;
    }

    /// XORs input bytes into the rate portion of the state.
    pub fn absorb(d: *Areion512, bytes: [32]u8) void {
        const block0_bytes = d.blocks[0].toBytes();
        const block1_bytes = d.blocks[1].toBytes();

        var new_block0_bytes: [16]u8 = undefined;
        var new_block1_bytes: [16]u8 = undefined;

        inline for (block0_bytes, new_block0_bytes[0..], bytes[0..16]) |old, *new, input| {
            new.* = old ^ input;
        }
        inline for (block1_bytes, new_block1_bytes[0..], bytes[16..32]) |old, *new, input| {
            new.* = old ^ input;
        }

        d.blocks[0] = AesBlock.fromBytes(&new_block0_bytes);
        d.blocks[1] = AesBlock.fromBytes(&new_block1_bytes);
    }

    /// Extracts the rate portion of the state as output bytes.
    pub fn squeeze(d: Areion512) [32]u8 {
        var rate: [32]u8 = undefined;
        @memcpy(rate[0..16], &d.blocks[0].toBytes());
        @memcpy(rate[16..32], &d.blocks[1].toBytes());
        return rate;
    }

    fn compress(d: *Areion512) void {
        const original_blocks = d.blocks;
        d.permute();
        inline for (0..4) |i| {
            const original_bytes = original_blocks[i].toBytes();
            const permuted_bytes = d.blocks[i].toBytes();
            var result_bytes: [16]u8 = undefined;
            inline for (permuted_bytes, original_bytes, result_bytes[0..]) |perm, orig, *result| {
                result.* = perm ^ orig;
            }
            d.blocks[i] = AesBlock.fromBytes(&result_bytes);
        }
    }

    fn extractOutput(d: Areion512, output: *[32]u8) void {
        const block0_bytes = d.blocks[0].toBytes();
        const block1_bytes = d.blocks[1].toBytes();
        const block2_bytes = d.blocks[2].toBytes();
        const block3_bytes = d.blocks[3].toBytes();

        @memcpy(output[0..8], block0_bytes[8..16]);
        @memcpy(output[8..16], block1_bytes[8..16]);
        @memcpy(output[16..24], block2_bytes[0..8]);
        @memcpy(output[24..32], block3_bytes[0..8]);
    }

    /// Serializes the full 64-byte state to a byte array.
    pub fn toBytes(d: Areion512) [64]u8 {
        var bytes: [64]u8 = undefined;
        inline for (d.blocks, 0..) |b, i| {
            @memcpy(bytes[i * 16 ..][0..16], &b.toBytes());
        }
        return bytes;
    }

    fn round(x0: *AesBlock, x1: *AesBlock, x2: *AesBlock, x3: *AesBlock, rc: AesBlock, rc1: AesBlock) void {
        x1.* = x0.encrypt(x1.*);
        x3.* = x2.encrypt(x3.*);
        x0.* = x0.encryptLast(rc1);
        x2.* = x2.encryptLast(rc).encrypt(rc1);
    }

    /// Applies the 15-round Areion512 permutation in-place.
    pub fn permute(d: *Areion512) void {
        const rcs = comptime rcs: {
            const ints = [15]u128{
                0x243f6a8885a308d313198a2e03707344, 0xa4093822299f31d0082efa98ec4e6c89, 0x452821e638d01377be5466cf34e90c6c, 0xc0ac29b7c97c50dd3f84d5b5b5470917, 0x9216d5d98979fb1bd1310ba698dfb5ac, 0x2ffd72dbd01adfb7b8e1afed6a267e96, 0xba7c9045f12c7f9924a19947b3916cf7, 0x801f2e2858efc16636920d871574e690, 0xa458fea3f4933d7e0d95748f728eb658, 0x718bcd5882154aee7b54a41dc25a59b5, 0x9c30d5392af26013c5d1b023286085f0, 0xca417918b8db38ef8e79dcb0603a180e, 0x6c9e0e8bb01e8a3ed71577c1bd314b27, 0x78af2fda55605c60e65525f3aa55ab94, 0x5748986263e8144055ca396a2aab10b6,
            };
            var rcs: [ints.len]AesBlock = undefined;
            for (&rcs, ints) |*rc, v| {
                var b: [16]u8 = undefined;
                mem.writeInt(u128, &b, v, .little);
                rc.* = AesBlock.fromBytes(&b);
            }
            break :rcs rcs;
        };
        const rc1 = comptime rc1: {
            const b = [_]u8{0} ** 16;
            break :rc1 AesBlock.fromBytes(&b);
        };

        var i: usize = 0;
        while (i < 12) : (i += 4) {
            round(&d.blocks[0], &d.blocks[1], &d.blocks[2], &d.blocks[3], rcs[i + 0], rc1);
            round(&d.blocks[1], &d.blocks[2], &d.blocks[3], &d.blocks[0], rcs[i + 1], rc1);
            round(&d.blocks[2], &d.blocks[3], &d.blocks[0], &d.blocks[1], rcs[i + 2], rc1);
            round(&d.blocks[3], &d.blocks[0], &d.blocks[1], &d.blocks[2], rcs[i + 3], rc1);
        }

        round(&d.blocks[0], &d.blocks[1], &d.blocks[2], &d.blocks[3], rcs[12], rc1);
        round(&d.blocks[1], &d.blocks[2], &d.blocks[3], &d.blocks[0], rcs[13], rc1);
        round(&d.blocks[2], &d.blocks[3], &d.blocks[0], &d.blocks[1], rcs[14], rc1);

        const temp = d.blocks[0];
        d.blocks[0] = d.blocks[3];
        d.blocks[3] = d.blocks[2];
        d.blocks[2] = d.blocks[1];
        d.blocks[1] = temp;
    }

    /// Applies the inverse of the Areion512 permutation.
    pub fn inversePermute(d: *Areion512) void {
        const temp = d.blocks[0];
        d.blocks[0] = d.blocks[1];
        d.blocks[1] = d.blocks[2];
        d.blocks[2] = d.blocks[3];
        d.blocks[3] = temp;

        const rcs = comptime rcs: {
            const ints = [15]u128{
                0x243f6a8885a308d313198a2e03707344, 0xa4093822299f31d0082efa98ec4e6c89, 0x452821e638d01377be5466cf34e90c6c, 0xc0ac29b7c97c50dd3f84d5b5b5470917, 0x9216d5d98979fb1bd1310ba698dfb5ac, 0x2ffd72dbd01adfb7b8e1afed6a267e96, 0xba7c9045f12c7f9924a19947b3916cf7, 0x801f2e2858efc16636920d871574e690, 0xa458fea3f4933d7e0d95748f728eb658, 0x718bcd5882154aee7b54a41dc25a59b5, 0x9c30d5392af26013c5d1b023286085f0, 0xca417918b8db38ef8e79dcb0603a180e, 0x6c9e0e8bb01e8a3ed71577c1bd314b27, 0x78af2fda55605c60e65525f3aa55ab94, 0x5748986263e8144055ca396a2aab10b6,
            };
            var rcs: [ints.len]AesBlock = undefined;
            for (&rcs, ints) |*rc, v| {
                var b: [16]u8 = undefined;
                mem.writeInt(u128, &b, v, .little);
                rc.* = AesBlock.fromBytes(&b);
            }
            break :rcs rcs;
        };
        const rc1 = comptime rc1: {
            const b = [_]u8{0} ** 16;
            break :rc1 AesBlock.fromBytes(&b);
        };

        const invRound = struct {
            fn f(x0: *AesBlock, x1: *AesBlock, x2: *AesBlock, x3: *AesBlock, rc: AesBlock, zero: AesBlock) void {
                x0.* = x0.decryptLast(zero);
                x2.* = x2.invMixColumns().decryptLast(rc).decryptLast(zero);
                x1.* = x0.encrypt(x1.*);
                x3.* = x2.encrypt(x3.*);
            }
        }.f;
        invRound(&d.blocks[2], &d.blocks[3], &d.blocks[0], &d.blocks[1], rcs[14], rc1);
        invRound(&d.blocks[1], &d.blocks[2], &d.blocks[3], &d.blocks[0], rcs[13], rc1);
        invRound(&d.blocks[0], &d.blocks[1], &d.blocks[2], &d.blocks[3], rcs[12], rc1);

        var i: usize = 0;
        while (i < 12) : (i += 4) {
            invRound(&d.blocks[3], &d.blocks[0], &d.blocks[1], &d.blocks[2], rcs[11 - i], rc1);
            invRound(&d.blocks[2], &d.blocks[3], &d.blocks[0], &d.blocks[1], rcs[10 - i], rc1);
            invRound(&d.blocks[1], &d.blocks[2], &d.blocks[3], &d.blocks[0], rcs[9 - i], rc1);
            invRound(&d.blocks[0], &d.blocks[1], &d.blocks[2], &d.blocks[3], rcs[8 - i], rc1);
        }
    }

    /// Computes a 32-byte Davies-Meyer hash of a fixed 64-byte input.
    ///
    /// DM(m) = P(m) XOR m, with 32-byte output extracted from the
    /// high halves of blocks 0,1 and low halves of blocks 2,3.
    pub fn dm(message: [64]u8) [32]u8 {
        var d = Areion512.fromBytes(message);
        d.compress();
        var out: [32]u8 = undefined;
        d.extractOutput(&out);
        return out;
    }

    /// Computes a 32-byte hash of the input using Merkle-Damgård construction.
    ///
    /// The hash uses SHA-256's IV as the initial state and applies MD-compliant
    /// padding with length encoding.
    pub fn hash(b: []const u8, out: *[digest_length]u8, options: Options) void {
        _ = options;

        var hash_state: [32]u8 = undefined;
        const sha256_iv = [_]u8{ 0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb, 0x72, 0xf3, 0x6e, 0x3c, 0x3a, 0xf5, 0x4f, 0xa5, 0x7f, 0x52, 0x0e, 0x51, 0x8c, 0x68, 0x05, 0x9b, 0xab, 0xd9, 0x83, 0x1f, 0x19, 0xcd, 0xe0, 0x5b };
        @memcpy(&hash_state, &sha256_iv);

        const end = b.len - b.len % 32;
        var i: usize = 0;
        while (i < end) : (i += 32) {
            var d = Areion512{};
            d.setRate(b[i..][0..32].*);
            d.setCapacity(hash_state);
            d.compress();
            hash_state = d.getCapacity();
        }

        var padded = [_]u8{0} ** 32;
        const left = b.len - end;
        @memcpy(padded[0..left], b[end..]);
        padded[left] = 0x80;
        const bits: u32 = @intCast(b.len * 8);

        var final_state = Areion512{};
        if (left < 32 - 4) {
            mem.writeInt(u32, padded[32 - 4 ..][0..4], bits, .big);
            final_state.setRate(padded);
            final_state.setCapacity(hash_state);
            final_state.compress();
        } else {
            final_state.setRate(padded);
            final_state.setCapacity(hash_state);
            final_state.compress();
            hash_state = final_state.getCapacity();

            @memset(&padded, 0);
            mem.writeInt(u32, padded[32 - 4 ..][0..4], bits, .big);
            final_state = Areion512{};
            final_state.setRate(padded);
            final_state.setCapacity(hash_state);
            final_state.compress();
        }

        final_state.extractOutput(out);
    }
};

/// Areion256 is a 256-bit AES-based cryptographic permutation.
///
/// The permutation operates on a 32-byte state using 10 rounds of AES-based
/// transformations. It provides a hash function via Merkle-Damgård construction
/// with a 16-byte digest. Optimized for hardware AES acceleration.
pub const Areion256 = struct {
    /// Input block size in bytes for the hash function (rate portion).
    pub const block_length = 16;
    /// Output digest size in bytes.
    pub const digest_length = 16;
    /// Hash options (currently unused, for API compatibility).
    pub const Options = struct {};

    blocks: [2]AesBlock = blocks: {
        const ints = [_]u128{ 0x0, 0x6a09e667bb67ae853c6ef372a54ff53a };
        var blocks: [2]AesBlock = undefined;
        for (&blocks, ints) |*rc, v| {
            var b: [16]u8 = undefined;
            mem.writeInt(u128, &b, v, .little);
            rc.* = AesBlock.fromBytes(&b);
        }
        break :blocks blocks;
    },

    /// Creates a state from a 32-byte array.
    pub fn fromBytes(bytes: [32]u8) Areion256 {
        var blocks: [2]AesBlock = undefined;
        inline for (&blocks, 0..) |*b, i| {
            b.* = AesBlock.fromBytes(bytes[i * 16 ..][0..16]);
        }
        return .{ .blocks = blocks };
    }

    /// Sets the rate portion of the sponge state (first 16 bytes).
    pub fn setRate(d: *Areion256, bytes: [16]u8) void {
        d.blocks[0] = AesBlock.fromBytes(bytes[0..16]);
    }

    /// Sets the capacity portion of the sponge state (last 16 bytes).
    pub fn setCapacity(d: *Areion256, s: [16]u8) void {
        d.blocks[1] = AesBlock.fromBytes(s[0..16]);
    }

    /// Returns the capacity portion of the sponge state.
    pub fn getCapacity(d: Areion256) [16]u8 {
        return d.blocks[1].toBytes();
    }

    /// XORs input bytes into the rate portion of the state.
    pub fn absorb(d: *Areion256, bytes: [16]u8) void {
        const block0_bytes = d.blocks[0].toBytes();
        var new_block0_bytes: [16]u8 = undefined;
        inline for (block0_bytes, new_block0_bytes[0..], bytes) |old, *new, input| {
            new.* = old ^ input;
        }
        d.blocks[0] = AesBlock.fromBytes(&new_block0_bytes);
    }

    /// Extracts the rate portion of the state as output bytes.
    pub fn squeeze(d: Areion256) [16]u8 {
        return d.blocks[0].toBytes();
    }

    fn compress(d: *Areion256) void {
        const original_blocks = d.blocks;
        d.permute();
        inline for (0..2) |i| {
            const original_bytes = original_blocks[i].toBytes();
            const permuted_bytes = d.blocks[i].toBytes();
            var result_bytes: [16]u8 = undefined;
            inline for (permuted_bytes, original_bytes, result_bytes[0..]) |perm, orig, *result| {
                result.* = perm ^ orig;
            }
            d.blocks[i] = AesBlock.fromBytes(&result_bytes);
        }
    }

    fn extractOutput(d: Areion256, output: *[16]u8) void {
        @memcpy(output[0..16], &d.blocks[1].toBytes());
    }

    /// Serializes the full 32-byte state to a byte array.
    pub fn toBytes(d: Areion256) [32]u8 {
        var bytes: [32]u8 = undefined;
        inline for (d.blocks, 0..) |b, i| {
            @memcpy(bytes[i * 16 ..][0..16], &b.toBytes());
        }
        return bytes;
    }

    /// Applies the 10-round Areion256 permutation in-place.
    pub fn permute(d: *Areion256) void {
        const rcs = comptime rcs: {
            const ints = [10]u128{
                0x243f6a8885a308d313198a2e03707344, 0xa4093822299f31d0082efa98ec4e6c89, 0x452821e638d01377be5466cf34e90c6c, 0xc0ac29b7c97c50dd3f84d5b5b5470917, 0x9216d5d98979fb1bd1310ba698dfb5ac, 0x2ffd72dbd01adfb7b8e1afed6a267e96, 0xba7c9045f12c7f9924a19947b3916cf7, 0x801f2e2858efc16636920d871574e690, 0xa458fea3f4933d7e0d95748f728eb658, 0x718bcd5882154aee7b54a41dc25a59b5,
            };
            var rcs: [ints.len]AesBlock = undefined;
            for (&rcs, ints) |*rc, v| {
                var b: [16]u8 = undefined;
                mem.writeInt(u128, &b, v, .little);
                rc.* = AesBlock.fromBytes(&b);
            }
            break :rcs rcs;
        };
        const rc1 = comptime rc1: {
            const b = [_]u8{0} ** 16;
            break :rc1 AesBlock.fromBytes(&b);
        };

        inline for (rcs, 0..) |rc, r| {
            if (r % 2 == 0) {
                const new_x1 = d.blocks[0].encrypt(rc).encrypt(d.blocks[1]);
                const new_x0 = d.blocks[0].encryptLast(rc1);
                d.blocks = [2]AesBlock{ new_x0, new_x1 };
            } else {
                const new_x0 = d.blocks[1].encrypt(rc).encrypt(d.blocks[0]);
                const new_x1 = d.blocks[1].encryptLast(rc1);
                d.blocks = [2]AesBlock{ new_x0, new_x1 };
            }
        }
    }

    /// Applies the inverse of the Areion256 permutation.
    pub fn inversePermute(d: *Areion256) void {
        const rcs = comptime rcs: {
            const ints = [10]u128{
                0x243f6a8885a308d313198a2e03707344, 0xa4093822299f31d0082efa98ec4e6c89, 0x452821e638d01377be5466cf34e90c6c, 0xc0ac29b7c97c50dd3f84d5b5b5470917, 0x9216d5d98979fb1bd1310ba698dfb5ac, 0x2ffd72dbd01adfb7b8e1afed6a267e96, 0xba7c9045f12c7f9924a19947b3916cf7, 0x801f2e2858efc16636920d871574e690, 0xa458fea3f4933d7e0d95748f728eb658, 0x718bcd5882154aee7b54a41dc25a59b5,
            };
            var rcs: [ints.len]AesBlock = undefined;
            for (&rcs, ints) |*rc, v| {
                var b: [16]u8 = undefined;
                mem.writeInt(u128, &b, v, .little);
                rc.* = AesBlock.fromBytes(&b);
            }
            break :rcs rcs;
        };
        const rc1 = comptime rc1: {
            const b = [_]u8{0} ** 16;
            break :rc1 AesBlock.fromBytes(&b);
        };

        var i: usize = 0;
        while (i < 10) : (i += 2) {
            {
                const rc = rcs[9 - i];
                d.blocks[1] = d.blocks[1].decryptLast(rc1);
                d.blocks[0] = d.blocks[1].encrypt(rc).encrypt(d.blocks[0]);
            }
            {
                const rc = rcs[8 - i];
                d.blocks[0] = d.blocks[0].decryptLast(rc1);
                d.blocks[1] = d.blocks[0].encrypt(rc).encrypt(d.blocks[1]);
            }
        }
    }

    /// Computes a 32-byte Davies-Meyer hash of a fixed 32-byte input.
    ///
    /// DM(m) = P(m) XOR m, outputting the full 32-byte state.
    pub fn dm(message: [32]u8) [32]u8 {
        var d = Areion256.fromBytes(message);
        d.compress();
        return d.toBytes();
    }

    /// Computes a 16-byte hash of the input using Merkle-Damgård construction.
    ///
    /// The hash uses the first half of SHA-256's IV as the initial state and
    /// applies MD-compliant padding with length encoding.
    pub fn hash(b: []const u8, out: *[digest_length]u8, options: Options) void {
        _ = options;

        var hash_state: [16]u8 = undefined;
        const sha256_iv = [_]u8{ 0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb, 0x72, 0xf3, 0x6e, 0x3c, 0x3a, 0xf5, 0x4f, 0xa5 };
        @memcpy(&hash_state, &sha256_iv);

        const end = b.len - b.len % 16;
        var i: usize = 0;
        while (i < end) : (i += 16) {
            var d = Areion256{};
            d.setRate(b[i..][0..16].*);
            d.setCapacity(hash_state);
            d.compress();
            hash_state = d.getCapacity();
        }

        var padded = [_]u8{0} ** 16;
        const left = b.len - end;
        @memcpy(padded[0..left], b[end..]);
        padded[left] = 0x80;
        const bits: u32 = @intCast(b.len * 8);

        var final_state = Areion256{};
        if (left < 16 - 4) {
            mem.writeInt(u32, padded[16 - 4 ..][0..4], bits, .big);
            final_state.setRate(padded);
            final_state.setCapacity(hash_state);
            final_state.compress();
        } else {
            final_state.setRate(padded);
            final_state.setCapacity(hash_state);
            final_state.compress();
            hash_state = final_state.getCapacity();

            @memset(&padded, 0);
            mem.writeInt(u32, padded[16 - 4 ..][0..4], bits, .big);
            final_state = Areion256{};
            final_state.setRate(padded);
            final_state.setCapacity(hash_state);
            final_state.compress();
        }

        final_state.extractOutput(out);
    }
};

const OppState256 = struct {
    a: u64,
    b: u64,
    c: u64,
    d: u64,

    fn fromBytes(bytes: [32]u8) OppState256 {
        return .{
            .a = mem.readInt(u64, bytes[0..8], .little),
            .b = mem.readInt(u64, bytes[8..16], .little),
            .c = mem.readInt(u64, bytes[16..24], .little),
            .d = mem.readInt(u64, bytes[24..32], .little),
        };
    }

    fn toBytes(s: OppState256) [32]u8 {
        var bytes: [32]u8 = undefined;
        mem.writeInt(u64, bytes[0..8], s.a, .little);
        mem.writeInt(u64, bytes[8..16], s.b, .little);
        mem.writeInt(u64, bytes[16..24], s.c, .little);
        mem.writeInt(u64, bytes[24..32], s.d, .little);
        return bytes;
    }

    fn xorState(s: OppState256, other: OppState256) OppState256 {
        return .{
            .a = s.a ^ other.a,
            .b = s.b ^ other.b,
            .c = s.c ^ other.c,
            .d = s.d ^ other.d,
        };
    }
};

const OppState512 = struct {
    s: [8]u64,

    fn fromBytes(bytes: [64]u8) OppState512 {
        var s: [8]u64 = undefined;
        for (&s, 0..) |*word, i| {
            word.* = mem.readInt(u64, bytes[i * 8 ..][0..8], .little);
        }
        return .{ .s = s };
    }

    fn toBytes(state: OppState512) [64]u8 {
        var bytes: [64]u8 = undefined;
        for (state.s, 0..) |word, i| {
            mem.writeInt(u64, bytes[i * 8 ..][0..8], word, .little);
        }
        return bytes;
    }

    fn xorState(state: OppState512, other: OppState512) OppState512 {
        var result: [8]u64 = undefined;
        for (&result, state.s, other.s) |*r, a, b| {
            r.* = a ^ b;
        }
        return .{ .s = result };
    }
};

/// Areion256-OPP authenticated encryption with associated data (AEAD).
///
/// Uses the Offset Public Permutation construction with Areion256 as the
/// underlying permutation. Provides 128-bit security for both confidentiality
/// and authenticity. Supports streaming encryption/decryption.
pub const Areion256Opp = struct {
    /// Secret key length in bytes.
    pub const key_length = 16;
    /// Nonce length in bytes.
    pub const nonce_length = 16;
    /// Authentication tag length in bytes.
    pub const tag_length = 16;
    /// Internal block length in bytes.
    pub const block_length = 32;

    sa: OppState256,
    se: OppState256,
    la: OppState256,
    le: OppState256,
    ad_buf: [32]u8,
    buf: [32]u8,
    ad_partial_len: usize,
    partial_len: usize,
    is_encrypt: bool,
    ad_finalized: bool,

    /// Initializes the AEAD state for encryption or decryption.
    pub fn init(key: [key_length]u8, nonce: [nonce_length]u8, is_encrypt: bool) Areion256Opp {
        const la = initMask256(key, nonce);
        const le = gamma256(la);

        return .{
            .sa = .{ .a = 0, .b = 0, .c = 0, .d = 0 },
            .se = .{ .a = 0, .b = 0, .c = 0, .d = 0 },
            .la = la,
            .le = le,
            .ad_buf = [_]u8{0} ** 32,
            .buf = [_]u8{0} ** 32,
            .ad_partial_len = 0,
            .partial_len = 0,
            .is_encrypt = is_encrypt,
            .ad_finalized = false,
        };
    }

    /// Processes associated data. May be called multiple times before `update`.
    pub fn updateAd(self: *Areion256Opp, ad: []const u8) void {
        var offset: usize = 0;

        if (self.ad_partial_len > 0) {
            const needed = @min(ad.len, block_length - self.ad_partial_len);
            @memcpy(self.ad_buf[self.ad_partial_len .. self.ad_partial_len + needed], ad[0..needed]);
            self.ad_partial_len += needed;
            offset = needed;

            if (self.ad_partial_len == block_length) {
                const block_state = OppState256.fromBytes(self.ad_buf);
                const outb = oppMem256(block_state, self.la);
                self.sa = self.sa.xorState(outb);
                self.la = alpha256(self.la);
                self.ad_partial_len = 0;
            }
        }

        while (offset + block_length <= ad.len) {
            const block_state = OppState256.fromBytes(ad[offset .. offset + block_length][0..block_length].*);
            const outb = oppMem256(block_state, self.la);
            self.sa = self.sa.xorState(outb);
            self.la = alpha256(self.la);
            offset += block_length;
        }

        if (offset < ad.len) {
            const remaining = ad.len - offset;
            @memcpy(self.ad_buf[0..remaining], ad[offset..]);
            self.ad_partial_len = remaining;
        }
    }

    fn finalizeAd(self: *Areion256Opp) void {
        if (!self.ad_finalized) {
            self.ad_finalized = true;
            if (self.ad_partial_len > 0) {
                @memset(self.ad_buf[self.ad_partial_len..], 0);
                self.ad_buf[self.ad_partial_len] = 0x01;

                const mask = beta256(self.la);
                const block_state = OppState256.fromBytes(self.ad_buf);
                const outb = oppMem256(block_state, mask);
                self.sa = self.sa.xorState(outb);
                self.la = alpha256(mask);
            }
        }
    }

    /// Encrypts or decrypts message data, writing to the output buffer.
    /// Output buffer must be at least as large as input.
    pub fn update(self: *Areion256Opp, output: []u8, input: []const u8) void {
        self.finalizeAd();

        var offset: usize = 0;

        if (self.partial_len > 0) {
            const needed = @min(input.len, block_length - self.partial_len);
            @memcpy(self.buf[self.partial_len .. self.partial_len + needed], input[0..needed]);
            self.partial_len += needed;
            offset = needed;

            if (self.partial_len == block_length) {
                const block_state = OppState256.fromBytes(self.buf);

                if (self.is_encrypt) {
                    const outb = oppMem256(block_state, self.le);
                    const result_bytes = outb.toBytes();
                    @memcpy(output[0..block_length], &result_bytes);
                    self.se = self.se.xorState(block_state);
                } else {
                    const outb = oppMemInverse256(block_state, self.le);
                    const result_bytes = outb.toBytes();
                    @memcpy(output[0..block_length], &result_bytes);
                    self.se = self.se.xorState(outb);
                }

                self.le = alpha256(self.le);
                self.partial_len = 0;
            }
        }

        while (offset + block_length <= input.len) {
            const block_state = OppState256.fromBytes(input[offset .. offset + block_length][0..block_length].*);
            if (self.is_encrypt) {
                const outb = oppMem256(block_state, self.le);
                const result_bytes = outb.toBytes();
                @memcpy(output[offset .. offset + block_length], &result_bytes);
                self.se = self.se.xorState(block_state);
            } else {
                const outb = oppMemInverse256(block_state, self.le);
                const result_bytes = outb.toBytes();
                @memcpy(output[offset .. offset + block_length], &result_bytes);
                self.se = self.se.xorState(outb);
            }

            self.le = alpha256(self.le);
            offset += block_length;
        }

        if (offset < input.len) {
            const remaining = input.len - offset;
            @memcpy(self.buf[0..remaining], input[offset..]);
            self.partial_len = remaining;
        }
    }

    /// Finalizes encryption/decryption and computes the authentication tag.
    /// Processes any remaining buffered data.
    pub fn finalize(self: *Areion256Opp, output: []u8, tag: *[tag_length]u8) void {
        self.finalizeAd();

        if (self.partial_len > 0) {
            self.le = beta256(self.le);
            @memset(self.buf[self.partial_len..], 0);
            self.buf[self.partial_len] = 0x01;

            const inb = OppState256.fromBytes(self.buf);
            const zero_state = OppState256{ .a = 0, .b = 0, .c = 0, .d = 0 };
            const block = oppMem256(zero_state, self.le);
            const outb = block.xorState(inb);

            const result_bytes = outb.toBytes();
            if (output.len >= self.partial_len) {
                @memcpy(output[0..self.partial_len], result_bytes[0..self.partial_len]);
            }

            if (self.is_encrypt) {
                self.se = self.se.xorState(inb);
            } else {
                var plain_buf = [_]u8{0} ** 32;
                @memcpy(plain_buf[0..self.partial_len], result_bytes[0..self.partial_len]);
                plain_buf[self.partial_len] = 0x01;
                const plainb = OppState256.fromBytes(plain_buf);
                self.se = self.se.xorState(plainb);
            }
        }

        const final_mask = beta256(beta256(self.le));
        const tag_state = self.sa.xorState(oppMem256(self.se, final_mask));
        const tag_bytes = tag_state.toBytes();
        @memcpy(tag, tag_bytes[0..tag_length]);
    }

    /// One-shot encryption: encrypts plaintext and computes authentication tag.
    pub fn encrypt(key: [key_length]u8, nonce: [nonce_length]u8, ad: []const u8, plaintext: []const u8, ciphertext: []u8, tag: *[tag_length]u8) void {
        var state = Areion256Opp.init(key, nonce, true);
        state.updateAd(ad);

        const full_blocks = plaintext.len / block_length;
        const processed_len = full_blocks * block_length;

        state.update(ciphertext, plaintext);

        var empty_output: [0]u8 = undefined;
        const remaining_output = if (processed_len < ciphertext.len) ciphertext[processed_len..] else &empty_output;
        state.finalize(remaining_output, tag);
    }

    /// One-shot decryption: decrypts and verifies the authentication tag.
    /// Returns `AuthenticationFailed` if the tag doesn't match.
    pub fn decrypt(key: [key_length]u8, nonce: [nonce_length]u8, ad: []const u8, ciphertext: []const u8, tag: [tag_length]u8, plaintext: []u8) AuthenticationError!void {
        var state = Areion256Opp.init(key, nonce, false);
        state.updateAd(ad);

        const full_blocks = ciphertext.len / block_length;
        const processed_len = full_blocks * block_length;

        state.update(plaintext, ciphertext);

        var empty_output: [0]u8 = undefined;
        const remaining_output = if (processed_len < plaintext.len) plaintext[processed_len..] else &empty_output;
        var computed_tag: [tag_length]u8 = undefined;
        state.finalize(remaining_output, &computed_tag);

        const verify = crypto.timing_safe.eql([tag_length]u8, computed_tag, tag);
        if (!verify) {
            crypto.secureZero(u8, &computed_tag);
            @memset(plaintext, undefined);
            return error.AuthenticationFailed;
        }
    }
};

/// Areion512-OPP authenticated encryption with associated data (AEAD).
///
/// Uses the Offset Public Permutation construction with Areion512 as the
/// underlying permutation. Provides 128-bit security for both confidentiality
/// and authenticity. Supports streaming encryption.
pub const Areion512Opp = struct {
    /// Secret key length in bytes.
    pub const key_length = 16;
    /// Nonce length in bytes.
    pub const nonce_length = 16;
    /// Authentication tag length in bytes.
    pub const tag_length = 16;
    /// Internal block length in bytes.
    pub const block_length = 64;

    sa: OppState512,
    se: OppState512,
    la: OppState512,
    le: OppState512,
    ad_buf: [64]u8,
    buf: [64]u8,
    ad_partial_len: usize,
    partial_len: usize,
    ad_finalized: bool,

    /// Initializes the AEAD state for encryption.
    pub fn init(key: [key_length]u8, nonce: [nonce_length]u8) Areion512Opp {
        const la = initMask512(key, nonce);
        const le = gamma512(la);

        return .{
            .sa = .{ .s = [_]u64{0} ** 8 },
            .se = .{ .s = [_]u64{0} ** 8 },
            .la = la,
            .le = le,
            .ad_buf = [_]u8{0} ** 64,
            .buf = [_]u8{0} ** 64,
            .ad_partial_len = 0,
            .partial_len = 0,
            .ad_finalized = false,
        };
    }

    /// Processes associated data. May be called multiple times before `update`.
    pub fn updateAd(self: *Areion512Opp, ad: []const u8) void {
        var offset: usize = 0;

        if (self.ad_partial_len > 0) {
            const needed = @min(ad.len, block_length - self.ad_partial_len);
            @memcpy(self.ad_buf[self.ad_partial_len .. self.ad_partial_len + needed], ad[0..needed]);
            self.ad_partial_len += needed;
            offset = needed;

            if (self.ad_partial_len == block_length) {
                const block_state = OppState512.fromBytes(self.ad_buf);
                const outb = oppMem512(block_state, self.la);
                self.sa = self.sa.xorState(outb);
                self.la = alpha512(self.la);
                self.ad_partial_len = 0;
            }
        }

        while (offset + block_length <= ad.len) {
            const block_state = OppState512.fromBytes(ad[offset .. offset + block_length][0..block_length].*);
            const outb = oppMem512(block_state, self.la);
            self.sa = self.sa.xorState(outb);
            self.la = alpha512(self.la);
            offset += block_length;
        }

        if (offset < ad.len) {
            const remaining = ad.len - offset;
            @memcpy(self.ad_buf[0..remaining], ad[offset..]);
            self.ad_partial_len = remaining;
        }
    }

    fn finalizeAd(self: *Areion512Opp) void {
        if (!self.ad_finalized) {
            self.ad_finalized = true;
            if (self.ad_partial_len > 0) {
                @memset(self.ad_buf[self.ad_partial_len..], 0);
                self.ad_buf[self.ad_partial_len] = 0x01;

                const mask = beta512(self.la);
                const block_state = OppState512.fromBytes(self.ad_buf);
                const outb = oppMem512(block_state, mask);
                self.sa = self.sa.xorState(outb);
                self.la = alpha512(mask);
            }
        }
    }

    /// Encrypts message data, writing to the output buffer.
    pub fn update(self: *Areion512Opp, output: []u8, input: []const u8) void {
        self.finalizeAd();

        var offset: usize = 0;

        if (self.partial_len > 0) {
            const needed = @min(input.len, block_length - self.partial_len);
            @memcpy(self.buf[self.partial_len .. self.partial_len + needed], input[0..needed]);
            self.partial_len += needed;
            offset = needed;

            if (self.partial_len == block_length) {
                const block_state = OppState512.fromBytes(self.buf);

                const outb = oppMem512(block_state, self.le);
                const result_bytes = outb.toBytes();
                @memcpy(output[0..block_length], &result_bytes);
                self.se = self.se.xorState(block_state);

                self.le = alpha512(self.le);
                self.partial_len = 0;
            }
        }

        while (offset + block_length <= input.len) {
            const block_state = OppState512.fromBytes(input[offset .. offset + block_length][0..block_length].*);

            const outb = oppMem512(block_state, self.le);
            const result_bytes = outb.toBytes();
            @memcpy(output[offset .. offset + block_length], &result_bytes);
            self.se = self.se.xorState(block_state);

            self.le = alpha512(self.le);
            offset += block_length;
        }

        if (offset < input.len) {
            const remaining = input.len - offset;
            @memcpy(self.buf[0..remaining], input[offset..]);
            self.partial_len = remaining;
        }
    }

    /// Finalizes encryption and computes the authentication tag.
    pub fn finalize(self: *Areion512Opp, output: []u8, tag: *[tag_length]u8) void {
        self.finalizeAd();

        if (self.partial_len > 0) {
            self.le = beta512(self.le);
            @memset(self.buf[self.partial_len..], 0);
            self.buf[self.partial_len] = 0x01;

            const inb = OppState512.fromBytes(self.buf);
            const zero_state = OppState512{ .s = [_]u64{0} ** 8 };
            const block = oppMem512(zero_state, self.le);
            const outb = block.xorState(inb);

            const result_bytes = outb.toBytes();
            if (output.len >= self.partial_len) {
                @memcpy(output[0..self.partial_len], result_bytes[0..self.partial_len]);
            }

            self.se = self.se.xorState(inb);
        }

        const final_mask = beta512(beta512(self.le));
        const tag_state = self.sa.xorState(oppMem512(self.se, final_mask));
        const tag_bytes = tag_state.toBytes();
        @memcpy(tag, tag_bytes[0..tag_length]);
    }

    /// One-shot encryption: encrypts plaintext and computes authentication tag.
    pub fn encrypt(key: [key_length]u8, nonce: [nonce_length]u8, ad: []const u8, plaintext: []const u8, ciphertext: []u8, tag: *[tag_length]u8) void {
        var state = Areion512Opp.init(key, nonce);
        state.updateAd(ad);

        const full_blocks = plaintext.len / block_length;
        const processed_len = full_blocks * block_length;

        state.update(ciphertext, plaintext);

        var empty_output: [0]u8 = undefined;
        const remaining_output = if (processed_len < ciphertext.len) ciphertext[processed_len..] else &empty_output;
        state.finalize(remaining_output, tag);
    }
};

fn phi256(x: OppState256) OppState256 {
    return OppState256{
        .a = x.b,
        .b = x.c,
        .c = x.d,
        .d = std.math.rotl(u64, x.a, 3) ^ (x.d >> 5),
    };
}

fn alpha256(x: OppState256) OppState256 {
    return phi256(x);
}

fn beta256(x: OppState256) OppState256 {
    return phi256(x).xorState(x);
}

fn gamma256(x: OppState256) OppState256 {
    const phi_x = phi256(x);
    const phi2_x = phi256(phi_x);
    return phi2_x.xorState(phi_x).xorState(x);
}

fn phi512(x: OppState512) OppState512 {
    var s: [8]u64 = undefined;
    s[0] = x.s[1];
    s[1] = x.s[2];
    s[2] = x.s[3];
    s[3] = x.s[4];
    s[4] = x.s[5];
    s[5] = x.s[6];
    s[6] = x.s[7];
    s[7] = std.math.rotl(u64, x.s[0], 29) ^ (x.s[1] << 9);
    return OppState512{ .s = s };
}

fn alpha512(x: OppState512) OppState512 {
    return phi512(x);
}

fn beta512(x: OppState512) OppState512 {
    return phi512(x).xorState(x);
}

fn gamma512(x: OppState512) OppState512 {
    const phi_x = phi512(x);
    const phi2_x = phi512(phi_x);
    return phi2_x.xorState(phi_x).xorState(x);
}

fn oppMem256(x: OppState256, m: OppState256) OppState256 {
    const xor_result = x.xorState(m);
    const bytes = xor_result.toBytes();

    var areion_state = Areion256.fromBytes(bytes);
    areion_state.permute();
    const permuted_bytes = areion_state.toBytes();

    const permuted_state = OppState256.fromBytes(permuted_bytes);
    return permuted_state.xorState(m);
}

fn oppMemInverse256(x: OppState256, m: OppState256) OppState256 {
    const xor_result = x.xorState(m);
    const bytes = xor_result.toBytes();

    var areion_state = Areion256.fromBytes(bytes);
    areion_state.inversePermute();
    const permuted_bytes = areion_state.toBytes();

    const permuted_state = OppState256.fromBytes(permuted_bytes);
    return permuted_state.xorState(m);
}

fn oppMem512(x: OppState512, m: OppState512) OppState512 {
    const xor_result = x.xorState(m);
    const bytes = xor_result.toBytes();

    var areion_state = Areion512.fromBytes(bytes);
    areion_state.permute();
    const permuted_bytes = areion_state.toBytes();

    const permuted_state = OppState512.fromBytes(permuted_bytes);
    return permuted_state.xorState(m);
}

fn initMask256(key: [16]u8, nonce: [16]u8) OppState256 {
    var block: [32]u8 = undefined;
    @memcpy(block[0..16], &nonce);
    @memcpy(block[16..32], &key);

    var mask = OppState256.fromBytes(block);
    const mask_bytes = mask.toBytes();

    var areion_state = Areion256.fromBytes(mask_bytes);
    areion_state.permute();
    const permuted_bytes = areion_state.toBytes();

    return OppState256.fromBytes(permuted_bytes);
}

fn initMask512(key: [16]u8, nonce: [16]u8) OppState512 {
    var block: [64]u8 = undefined;
    @memcpy(block[0..16], &nonce);
    @memset(block[16..48], 0);
    @memcpy(block[48..64], &key);

    var mask = OppState512.fromBytes(block);
    const mask_bytes = mask.toBytes();

    var areion_state = Areion512.fromBytes(mask_bytes);
    areion_state.permute();
    const permuted_bytes = areion_state.toBytes();

    return OppState512.fromBytes(permuted_bytes);
}

const testing = std.testing;

test {
    _ = och;
}

test "areion512 permutation test vectors" {
    var state = Areion512.fromBytes([_]u8{0} ** 64);
    state.permute();
    const result = state.toBytes();

    const expected_hex = "b2adb04fa91f901559367122cb3c96a978cf3ee4b73c6a543fe6dc85779102e7e3f5501016ceed1dd2c48d0bc212fb07ad168794bd96cff35909cdd8e2274928";
    var expected_bytes: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_bytes, expected_hex);
    try testing.expectEqualSlices(u8, &expected_bytes, &result);
}

test "areion512 basic functionality" {
    var out1: [32]u8 = undefined;
    var out2: [32]u8 = undefined;

    Areion512.hash("test", &out1, .{});
    Areion512.hash("test", &out2, .{});
    try testing.expectEqualSlices(u8, &out1, &out2);

    var out3: [32]u8 = undefined;
    Areion512.hash("different", &out3, .{});
    try testing.expect(!mem.eql(u8, &out1, &out3));

    var empty_out: [32]u8 = undefined;
    Areion512.hash("", &empty_out, .{});
    try testing.expect(!mem.allEqual(u8, &empty_out, 0));
}

test "areion256 permutation test vectors" {
    var state = Areion256.fromBytes([_]u8{0} ** 32);
    state.permute();
    const result = state.toBytes();

    const expected_hex = "2812a72465b26e9fca7583f6e4123aa1490e35e7d5203e4ba2e927b0482f4db8";
    var expected_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_bytes, expected_hex);
    try testing.expectEqualSlices(u8, &expected_bytes, &result);
}

test "areion256 basic functionality" {
    var out1: [16]u8 = undefined;
    var out2: [16]u8 = undefined;

    Areion256.hash("test", &out1, .{});
    Areion256.hash("test", &out2, .{});
    try testing.expectEqualSlices(u8, &out1, &out2);

    var out3: [16]u8 = undefined;
    Areion256.hash("different", &out3, .{});
    try testing.expect(!mem.eql(u8, &out1, &out3));

    var empty_out: [16]u8 = undefined;
    Areion256.hash("", &empty_out, .{});
    try testing.expect(!mem.allEqual(u8, &empty_out, 0));
}

test "areion512 additional test vectors" {
    var seq_input: [64]u8 = undefined;
    for (0..64) |i| {
        seq_input[i] = @intCast(i);
    }

    var state = Areion512.fromBytes(seq_input);
    state.permute();
    const result = state.toBytes();

    const expected_hex = "b690b88297ec470b07dda92b91959cff135e9ac5fc3dc9b647a43f4daa8da7a4e0afbdd8e6e255c24527736b298bd61de460bab9ea7915c6d6ddbe05fe8dde40";
    var expected_bytes_64: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_bytes_64, expected_hex);
    try testing.expectEqualSlices(u8, &expected_bytes_64, &result);
}

test "areion256 additional test vectors" {
    var seq_input: [32]u8 = undefined;
    for (0..32) |i| {
        seq_input[i] = @intCast(i);
    }

    var state = Areion256.fromBytes(seq_input);
    state.permute();
    const result = state.toBytes();

    const expected_hex = "68845f132ee4616066c702d942a3b2c3a377f65b13bb05c7cd1fb29c89afa185";
    var expected_bytes_32: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_bytes_32, expected_hex);
    try testing.expectEqualSlices(u8, &expected_bytes_32, &result);
}

test "areion state management" {
    const original_bytes_512 = [_]u8{0x12} ** 64;
    const state512 = Areion512.fromBytes(original_bytes_512);
    const result_bytes_512 = state512.toBytes();
    try testing.expectEqualSlices(u8, &original_bytes_512, &result_bytes_512);

    const original_bytes_256 = [_]u8{0x34} ** 32;
    const state256 = Areion256.fromBytes(original_bytes_256);
    const result_bytes_256 = state256.toBytes();
    try testing.expectEqualSlices(u8, &original_bytes_256, &result_bytes_256);
}

test "areion deterministic behavior" {
    const input = "test";

    var out1_512: [32]u8 = undefined;
    var out2_512: [32]u8 = undefined;
    var out1_256: [16]u8 = undefined;
    var out2_256: [16]u8 = undefined;

    Areion512.hash(input, &out1_512, .{});
    Areion512.hash(input, &out2_512, .{});
    Areion256.hash(input, &out1_256, .{});
    Areion256.hash(input, &out2_256, .{});

    try testing.expectEqualSlices(u8, &out1_512, &out2_512);
    try testing.expectEqualSlices(u8, &out1_256, &out2_256);

    try testing.expect(!mem.eql(u8, out1_512[0..16], &out1_256));
}

test "areion256-opp encrypt/decrypt consistency" {
    const key = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const nonce = [_]u8{ 0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00 };
    const ad: []const u8 = &[_]u8{};
    const plaintext: []const u8 = &[_]u8{};

    var ciphertext: [0]u8 = undefined;
    var tag: [16]u8 = undefined;

    Areion256Opp.encrypt(key, nonce, ad, plaintext, &ciphertext, &tag);

    var decrypted: [0]u8 = undefined;
    try Areion256Opp.decrypt(key, nonce, ad, &ciphertext, tag, &decrypted);
}

test "areion512-opp encrypt/decrypt consistency" {
    const key = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const nonce = [_]u8{ 0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00 };
    const ad: []const u8 = &[_]u8{};
    const plaintext: []const u8 = &[_]u8{};

    var ciphertext: [0]u8 = undefined;
    var tag: [16]u8 = undefined;

    Areion512Opp.encrypt(key, nonce, ad, plaintext, &ciphertext, &tag);
}

test "areion256-opp empty ad and message" {
    const key = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const nonce = [_]u8{ 0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00 };
    const ad: []const u8 = &[_]u8{};
    const plaintext: []const u8 = &[_]u8{};

    var ciphertext: [0]u8 = undefined;
    var tag: [16]u8 = undefined;

    Areion256Opp.encrypt(key, nonce, ad, plaintext, &ciphertext, &tag);

    var decrypted: [0]u8 = undefined;
    try Areion256Opp.decrypt(key, nonce, ad, &ciphertext, tag, &decrypted);
}

test "areion256-opp authentication failure" {
    const key = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const nonce = [_]u8{ 0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00 };
    const ad = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const plaintext = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    var ciphertext: [16]u8 = undefined;
    var tag: [16]u8 = undefined;

    Areion256Opp.encrypt(key, nonce, &ad, &plaintext, &ciphertext, &tag);

    tag[0] ^= 1;

    var decrypted: [16]u8 = undefined;
    try testing.expectError(error.AuthenticationFailed, Areion256Opp.decrypt(key, nonce, &ad, &ciphertext, tag, &decrypted));
}

test "areion256-opp reference test vector #1" {
    const key = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const nonce = [_]u8{ 0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00 };
    const ad = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const plaintext = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const expected_ciphertext = [_]u8{
        0xCF, 0x48, 0xBE, 0x2E, 0x80, 0xF8, 0x1E, 0x74,
        0xCC, 0xE2, 0x07, 0xE8, 0x22, 0x0C, 0xD4, 0x9E,
        0xD9, 0x54, 0x45, 0xF7, 0x63, 0x0F, 0xC8, 0x1C,
        0xFE, 0xC2, 0xE4, 0x56, 0x10, 0x16, 0x0C, 0x00,
    };
    const expected_tag = [_]u8{
        0xE8, 0x4A, 0xB7, 0x94, 0x4E, 0xE1, 0x9F, 0xC5,
        0x60, 0x6F, 0xD3, 0x92, 0x88, 0x28, 0xB4, 0x07,
    };

    var ciphertext: [32]u8 = undefined;
    var tag: [16]u8 = undefined;

    Areion256Opp.encrypt(key, nonce, &ad, &plaintext, &ciphertext, &tag);

    try testing.expectEqualSlices(u8, &expected_ciphertext, &ciphertext);
    try testing.expectEqualSlices(u8, &expected_tag, &tag);

    var decrypted: [32]u8 = undefined;
    try Areion256Opp.decrypt(key, nonce, &ad, &ciphertext, tag, &decrypted);
    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "areion256 permutation reference test vector #1" {
    const input = [_]u8{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const expected = [_]u8{
        0x28, 0x12, 0xa7, 0x24, 0x65, 0xb2, 0x6e, 0x9f,
        0xca, 0x75, 0x83, 0xf6, 0xe4, 0x12, 0x3a, 0xa1,
        0x49, 0x0e, 0x35, 0xe7, 0xd5, 0x20, 0x3e, 0x4b,
        0xa2, 0xe9, 0x27, 0xb0, 0x48, 0x2f, 0x4d, 0xb8,
    };

    var state = Areion256.fromBytes(input);
    state.permute();
    const result = state.toBytes();

    try testing.expectEqualSlices(u8, &expected, &result);
}

test "areion512 permute/inversePermute roundtrip" {
    var input: [64]u8 = undefined;
    for (0..64) |i| {
        input[i] = @truncate(i *% 7 +% 13);
    }

    var state = Areion512.fromBytes(input);
    state.permute();
    state.inversePermute();
    const result = state.toBytes();

    try testing.expectEqualSlices(u8, &input, &result);
}

test "areion256 permute/inversePermute roundtrip" {
    var input: [32]u8 = undefined;
    for (0..32) |i| {
        input[i] = @truncate(i *% 7 +% 13);
    }

    var state = Areion256.fromBytes(input);
    state.permute();
    state.inversePermute();
    const result = state.toBytes();

    try testing.expectEqualSlices(u8, &input, &result);
}

test "areion512Vec matches scalar implementation" {
    const Vec2 = Areion512Vec(2);

    var input0: [64]u8 = undefined;
    var input1: [64]u8 = undefined;
    for (0..64) |i| {
        input0[i] = @truncate(i);
        input1[i] = @truncate(i *% 3 +% 17);
    }

    var scalar0 = Areion512.fromBytes(input0);
    var scalar1 = Areion512.fromBytes(input1);
    scalar0.permute();
    scalar1.permute();

    var combined_input: [128]u8 = undefined;
    @memcpy(combined_input[0..64], &input0);
    @memcpy(combined_input[64..128], &input1);

    var vec_state = Vec2.fromBytes(&combined_input);
    vec_state.permute();
    const vec_result = vec_state.toBytes();

    try testing.expectEqualSlices(u8, &scalar0.toBytes(), vec_result[0..64]);
    try testing.expectEqualSlices(u8, &scalar1.toBytes(), vec_result[64..128]);
}

test "areion256Vec matches scalar implementation" {
    const Vec2 = Areion256Vec(2);

    var input0: [32]u8 = undefined;
    var input1: [32]u8 = undefined;
    for (0..32) |i| {
        input0[i] = @truncate(i);
        input1[i] = @truncate(i *% 5 +% 23);
    }

    var scalar0 = Areion256.fromBytes(input0);
    var scalar1 = Areion256.fromBytes(input1);
    scalar0.permute();
    scalar1.permute();

    var combined_input: [64]u8 = undefined;
    @memcpy(combined_input[0..32], &input0);
    @memcpy(combined_input[32..64], &input1);

    var vec_state = Vec2.fromBytes(&combined_input);
    vec_state.permute();
    const vec_result = vec_state.toBytes();

    try testing.expectEqualSlices(u8, &scalar0.toBytes(), vec_result[0..32]);
    try testing.expectEqualSlices(u8, &scalar1.toBytes(), vec_result[32..64]);
}

test "areion512Vec permute/inversePermute roundtrip" {
    const Vec2 = Areion512Vec(2);

    var input: [128]u8 = undefined;
    for (0..128) |i| {
        input[i] = @truncate(i *% 11 +% 7);
    }

    var state = Vec2.fromBytes(&input);
    state.permute();
    state.inversePermute();
    const result = state.toBytes();

    try testing.expectEqualSlices(u8, &input, &result);
}

test "areion256Vec permute/inversePermute roundtrip" {
    const Vec2 = Areion256Vec(2);

    var input: [64]u8 = undefined;
    for (0..64) |i| {
        input[i] = @truncate(i *% 13 +% 3);
    }

    var state = Vec2.fromBytes(&input);
    state.permute();
    state.inversePermute();
    const result = state.toBytes();

    try testing.expectEqualSlices(u8, &input, &result);
}

test "areion512Vec with 4 parallel states" {
    const Vec4 = Areion512Vec(4);

    var inputs: [4][64]u8 = undefined;
    for (0..4) |idx| {
        for (0..64) |i| {
            inputs[idx][i] = @truncate(i *% (idx + 1) +% idx);
        }
    }

    var scalars: [4]Areion512 = undefined;
    for (0..4) |idx| {
        scalars[idx] = Areion512.fromBytes(inputs[idx]);
        scalars[idx].permute();
    }

    var combined: [256]u8 = undefined;
    for (0..4) |idx| {
        @memcpy(combined[idx * 64 ..][0..64], &inputs[idx]);
    }

    var vec_state = Vec4.fromBytes(&combined);
    vec_state.permute();
    const vec_result = vec_state.toBytes();

    for (0..4) |idx| {
        try testing.expectEqualSlices(u8, &scalars[idx].toBytes(), vec_result[idx * 64 ..][0..64]);
    }
}

test "areion256Vec with 4 parallel states" {
    const Vec4 = Areion256Vec(4);

    var inputs: [4][32]u8 = undefined;
    for (0..4) |idx| {
        for (0..32) |i| {
            inputs[idx][i] = @truncate(i *% (idx + 2) +% (idx * 7));
        }
    }

    var scalars: [4]Areion256 = undefined;
    for (0..4) |idx| {
        scalars[idx] = Areion256.fromBytes(inputs[idx]);
        scalars[idx].permute();
    }

    var combined: [128]u8 = undefined;
    for (0..4) |idx| {
        @memcpy(combined[idx * 32 ..][0..32], &inputs[idx]);
    }

    var vec_state = Vec4.fromBytes(&combined);
    vec_state.permute();
    const vec_result = vec_state.toBytes();

    for (0..4) |idx| {
        try testing.expectEqualSlices(u8, &scalars[idx].toBytes(), vec_result[idx * 32 ..][0..32]);
    }
}

test "areion256-dm test vector #1 (zeros)" {
    const input = [_]u8{0} ** 32;
    const expected = [_]u8{
        0x28, 0x12, 0xa7, 0x24, 0x65, 0xb2, 0x6e, 0x9f,
        0xca, 0x75, 0x83, 0xf6, 0xe4, 0x12, 0x3a, 0xa1,
        0x49, 0x0e, 0x35, 0xe7, 0xd5, 0x20, 0x3e, 0x4b,
        0xa2, 0xe9, 0x27, 0xb0, 0x48, 0x2f, 0x4d, 0xb8,
    };
    try testing.expectEqualSlices(u8, &expected, &Areion256.dm(input));
}

test "areion256-dm test vector #2 (sequential)" {
    const input = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const expected = [_]u8{
        0x68, 0x85, 0x5d, 0x10, 0x2a, 0xe1, 0x67, 0x67,
        0x6e, 0xce, 0x08, 0xd2, 0x4e, 0xae, 0xbc, 0xcc,
        0xb3, 0x66, 0xe4, 0x48, 0x07, 0xae, 0x13, 0xd0,
        0xd5, 0x06, 0xa8, 0x87, 0x95, 0xb2, 0xbf, 0x9a,
    };
    try testing.expectEqualSlices(u8, &expected, &Areion256.dm(input));
}

test "areion512-dm test vector #1 (zeros)" {
    const input = [_]u8{0} ** 64;
    const expected = [_]u8{
        0x59, 0x36, 0x71, 0x22, 0xcb, 0x3c, 0x96, 0xa9,
        0x3f, 0xe6, 0xdc, 0x85, 0x77, 0x91, 0x02, 0xe7,
        0xe3, 0xf5, 0x50, 0x10, 0x16, 0xce, 0xed, 0x1d,
        0xad, 0x16, 0x87, 0x94, 0xbd, 0x96, 0xcf, 0xf3,
    };
    try testing.expectEqualSlices(u8, &expected, &Areion512.dm(input));
}

test "areion512-dm test vector #2 (sequential)" {
    const input = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    };
    const expected = [_]u8{
        0x0f, 0xd4, 0xa3, 0x20, 0x9d, 0x98, 0x92, 0xf0,
        0x5f, 0xbd, 0x25, 0x56, 0xb6, 0x90, 0xb9, 0xbb,
        0xc0, 0x8e, 0x9f, 0xfb, 0xc2, 0xc7, 0x73, 0xe5,
        0xd4, 0x51, 0x88, 0x8a, 0xde, 0x4c, 0x23, 0xf1,
    };
    try testing.expectEqualSlices(u8, &expected, &Areion512.dm(input));
}
