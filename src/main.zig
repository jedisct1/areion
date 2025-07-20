const std = @import("std");
const AesBlock = std.crypto.core.aes.Block;

/// Areion512 implements the 512-bit variant of the Areion permutation family.
/// It uses a 512-bit state (4 AES blocks) with 32-byte input absorption and 32-byte output.
/// This variant is optimized for speed, particularly on small inputs.
pub const Areion512 = struct {
    const Self = @This();

    /// Block length for input absorption (32 bytes)
    pub const block_length = 32;
    /// Digest length for hash output (32 bytes)
    pub const digest_length = 32;
    /// Options for hash function (currently unused)
    pub const Options = struct {};

    /// Internal state consisting of 4 AES blocks (512 bits total)
    /// blocks[0] and blocks[1] form the "rate" part for input absorption
    /// blocks[2] and blocks[3] form the "capacity" part initialized with SHA-256 constants
    blocks: [4]AesBlock = blocks: {
        const ints = [_]u128{ 0x0, 0x0, 0x6a09e667bb67ae853c6ef372a54ff53a, 0x510e527f9b05688c1f83d9ab5be0cd19 };
        var blocks: [4]AesBlock = undefined;
        for (&blocks, ints) |*rc, v| {
            var b: [16]u8 = undefined;
            std.mem.writeInt(u128, &b, v, .little);
            rc.* = AesBlock.fromBytes(&b);
        }
        break :blocks blocks;
    },

    /// Creates an Areion512 instance from a 64-byte array.
    /// The bytes are interpreted as 4 consecutive AES blocks.
    /// @param bytes 64-byte array representing the full state
    /// @return New Areion512 instance with the given state
    pub fn fromBytes(bytes: [64]u8) Self {
        var blocks: [4]AesBlock = undefined;
        inline for (&blocks, 0..) |*b, i| {
            b.* = AesBlock.fromBytes(bytes[i * 16 ..][0..16]);
        }
        return Self{ .blocks = blocks };
    }

    /// Sets the rate portion (first 2 blocks) of the state.
    /// The rate portion is used for input absorption.
    /// @param bytes 32-byte array to set as the rate
    pub fn setRate(self: *Self, bytes: [32]u8) void {
        self.blocks[0] = AesBlock.fromBytes(bytes[0..16]);
        self.blocks[1] = AesBlock.fromBytes(bytes[16..32]);
    }

    /// Sets the capacity portion (last 2 blocks) of the state.
    /// The capacity portion maintains the internal hash state.
    /// @param state 32-byte array to set as the capacity
    pub fn setCapacity(self: *Self, state: [32]u8) void {
        self.blocks[2] = AesBlock.fromBytes(state[0..16]);
        self.blocks[3] = AesBlock.fromBytes(state[16..32]);
    }

    /// Extracts the capacity portion (last 2 blocks) of the state.
    /// @return 32-byte array containing the capacity state
    pub fn getCapacity(self: Self) [32]u8 {
        var state: [32]u8 = undefined;
        @memcpy(state[0..16], &self.blocks[2].toBytes());
        @memcpy(state[16..32], &self.blocks[3].toBytes());
        return state;
    }

    /// Absorbs 32 bytes of input into the rate portion of the state.
    /// The input is XORed with the current rate (first 2 blocks).
    /// @param bytes 32-byte input block to absorb
    pub fn absorb(self: *Self, bytes: [32]u8) void {
        const block0_bytes = self.blocks[0].toBytes();
        const block1_bytes = self.blocks[1].toBytes();

        var new_block0_bytes: [16]u8 = undefined;
        var new_block1_bytes: [16]u8 = undefined;

        inline for (block0_bytes, new_block0_bytes[0..], bytes[0..16]) |old, *new, input| {
            new.* = old ^ input;
        }
        inline for (block1_bytes, new_block1_bytes[0..], bytes[16..32]) |old, *new, input| {
            new.* = old ^ input;
        }

        self.blocks[0] = AesBlock.fromBytes(&new_block0_bytes);
        self.blocks[1] = AesBlock.fromBytes(&new_block1_bytes);
    }

    /// Squeezes 32 bytes from the rate portion of the state.
    /// Returns the current rate (first 2 blocks) as output.
    /// @return 32-byte output extracted from the rate
    pub fn squeeze(self: Self) [32]u8 {
        var rate: [32]u8 = undefined;
        @memcpy(rate[0..16], &self.blocks[0].toBytes());
        @memcpy(rate[16..32], &self.blocks[1].toBytes());
        return rate;
    }

    /// Applies Davies-Meyer compression to the state.
    /// Performs permutation and XORs the result with the original state.
    /// This is used in the hash function's compression phase.
    fn compress(self: *Self) void {
        const original_blocks = self.blocks;
        self.permute();
        inline for (0..4) |i| {
            const original_bytes = original_blocks[i].toBytes();
            const permuted_bytes = self.blocks[i].toBytes();
            var result_bytes: [16]u8 = undefined;
            inline for (permuted_bytes, original_bytes, result_bytes[0..]) |perm, orig, *result| {
                result.* = perm ^ orig;
            }
            self.blocks[i] = AesBlock.fromBytes(&result_bytes);
        }
    }

    /// Extracts the final hash output from the state.
    /// Takes specific byte ranges from all 4 blocks to form the 32-byte output.
    /// @param output Pointer to 32-byte array to store the extracted output
    fn extractOutput(self: Self, output: *[32]u8) void {
        const block0_bytes = self.blocks[0].toBytes();
        const block1_bytes = self.blocks[1].toBytes();
        const block2_bytes = self.blocks[2].toBytes();
        const block3_bytes = self.blocks[3].toBytes();

        @memcpy(output[0..8], block0_bytes[8..16]);
        @memcpy(output[8..16], block1_bytes[8..16]);
        @memcpy(output[16..24], block2_bytes[0..8]);
        @memcpy(output[24..32], block3_bytes[0..8]);
    }

    /// Converts the entire state to a 64-byte array.
    /// All 4 AES blocks are concatenated into a single byte array.
    /// @return 64-byte array representing the complete state
    pub fn toBytes(self: Self) [64]u8 {
        var bytes: [64]u8 = undefined;
        inline for (self.blocks, 0..) |b, i| {
            @memcpy(bytes[i * 16 ..][0..16], &b.toBytes());
        }
        return bytes;
    }

    /// Applies the Areion512 permutation to the state.
    /// Performs 15 rounds of AES-based transformations using precomputed round constants.
    /// The permutation consists of 12 regular rounds followed by 3 final rounds,
    /// with a final block rotation.
    pub fn permute(self: *Self) void {
        const rcs = comptime rcs: {
            const ints = [15]u128{
                0x243f6a8885a308d313198a2e03707344, 0xa4093822299f31d0082efa98ec4e6c89, 0x452821e638d01377be5466cf34e90c6c, 0xc0ac29b7c97c50dd3f84d5b5b5470917, 0x9216d5d98979fb1bd1310ba698dfb5ac, 0x2ffd72dbd01adfb7b8e1afed6a267e96, 0xba7c9045f12c7f9924a19947b3916cf7, 0x801f2e2858efc16636920d871574e690, 0xa458fea3f4933d7e0d95748f728eb658, 0x718bcd5882154aee7b54a41dc25a59b5, 0x9c30d5392af26013c5d1b023286085f0, 0xca417918b8db38ef8e79dcb0603a180e, 0x6c9e0e8bb01e8a3ed71577c1bd314b27, 0x78af2fda55605c60e65525f3aa55ab94, 0x5748986263e8144055ca396a2aab10b6,
            };
            var rcs: [ints.len]AesBlock = undefined;
            for (&rcs, ints) |*rc, v| {
                var b: [16]u8 = undefined;
                std.mem.writeInt(u128, &b, v, .little);
                rc.* = AesBlock.fromBytes(&b);
            }
            break :rcs rcs;
        };
        const rc1 = comptime rc1: {
            const b = [_]u8{0} ** 16;
            break :rc1 AesBlock.fromBytes(&b);
        };

        inline for (0..12) |round| {
            const rc = rcs[round];
            switch (@rem(round, 4)) {
                0 => {
                    const new_x1 = self.blocks[0].encrypt(self.blocks[1]);
                    const new_x3 = self.blocks[2].encrypt(self.blocks[3]);
                    const new_x0 = self.blocks[0].encryptLast(rc1);
                    const new_x2 = self.blocks[2].encryptLast(rc).encrypt(rc1);
                    self.blocks = [4]AesBlock{ new_x0, new_x1, new_x2, new_x3 };
                },
                1 => {
                    const new_x2 = self.blocks[1].encrypt(self.blocks[2]);
                    const new_x0 = self.blocks[3].encrypt(self.blocks[0]);
                    const new_x1 = self.blocks[1].encryptLast(rc1);
                    const new_x3 = self.blocks[3].encryptLast(rc).encrypt(rc1);
                    self.blocks = [4]AesBlock{ new_x0, new_x1, new_x2, new_x3 };
                },
                2 => {
                    const new_x3 = self.blocks[2].encrypt(self.blocks[3]);
                    const new_x1 = self.blocks[0].encrypt(self.blocks[1]);
                    const new_x2 = self.blocks[2].encryptLast(rc1);
                    const new_x0 = self.blocks[0].encryptLast(rc).encrypt(rc1);
                    self.blocks = [4]AesBlock{ new_x0, new_x1, new_x2, new_x3 };
                },
                3 => {
                    const new_x0 = self.blocks[3].encrypt(self.blocks[0]);
                    const new_x2 = self.blocks[1].encrypt(self.blocks[2]);
                    const new_x3 = self.blocks[3].encryptLast(rc1);
                    const new_x1 = self.blocks[1].encryptLast(rc).encrypt(rc1);
                    self.blocks = [4]AesBlock{ new_x0, new_x1, new_x2, new_x3 };
                },
                else => unreachable,
            }
        }

        inline for (12..15) |round| {
            const rc = rcs[round];
            switch (@rem(round, 4)) {
                0 => {
                    const new_x1 = self.blocks[0].encrypt(self.blocks[1]);
                    const new_x3 = self.blocks[2].encrypt(self.blocks[3]);
                    const new_x0 = self.blocks[0].encryptLast(rc1);
                    const new_x2 = self.blocks[2].encryptLast(rc).encrypt(rc1);
                    self.blocks = [4]AesBlock{ new_x0, new_x1, new_x2, new_x3 };
                },
                1 => {
                    const new_x2 = self.blocks[1].encrypt(self.blocks[2]);
                    const new_x0 = self.blocks[3].encrypt(self.blocks[0]);
                    const new_x1 = self.blocks[1].encryptLast(rc1);
                    const new_x3 = self.blocks[3].encryptLast(rc).encrypt(rc1);
                    self.blocks = [4]AesBlock{ new_x0, new_x1, new_x2, new_x3 };
                },
                2 => {
                    const new_x3 = self.blocks[2].encrypt(self.blocks[3]);
                    const new_x1 = self.blocks[0].encrypt(self.blocks[1]);
                    const new_x2 = self.blocks[2].encryptLast(rc1);
                    const new_x0 = self.blocks[0].encryptLast(rc).encrypt(rc1);
                    self.blocks = [4]AesBlock{ new_x0, new_x1, new_x2, new_x3 };
                },
                else => unreachable,
            }
        }

        const temp = self.blocks[0];
        self.blocks[0] = self.blocks[3];
        self.blocks[3] = self.blocks[2];
        self.blocks[2] = self.blocks[1];
        self.blocks[1] = temp;
    }

    /// Computes the Areion512 hash of the input data.
    /// Uses Merkle-Damgård construction with Davies-Meyer compression.
    /// Processes input in 32-byte blocks with proper padding.
    /// @param b Input data to hash
    /// @param out Pointer to 32-byte array to store the hash digest
    /// @param options Hash options (currently unused)
    pub fn hash(b: []const u8, out: *[digest_length]u8, options: Options) void {
        _ = options;

        var hash_state: [32]u8 = undefined;
        const sha256_iv = [_]u8{ 0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb, 0x72, 0xf3, 0x6e, 0x3c, 0x3a, 0xf5, 0x4f, 0xa5, 0x7f, 0x52, 0x0e, 0x51, 0x8c, 0x68, 0x05, 0x9b, 0xab, 0xd9, 0x83, 0x1f, 0x19, 0xcd, 0xe0, 0x5b };
        @memcpy(&hash_state, &sha256_iv);

        const end = b.len - b.len % 32;
        var i: usize = 0;
        while (i < end) : (i += 32) {
            var state = Self{};
            state.setRate(b[i..][0..32].*);
            state.setCapacity(hash_state);
            state.compress();
            hash_state = state.getCapacity();
        }

        var padded = [_]u8{0} ** 32;
        const left = b.len - end;
        @memcpy(padded[0..left], b[end..]);
        padded[left] = 0x80;
        const bits: u32 = @intCast(b.len * 8);

        var final_state = Self{};
        if (left < 32 - 4) {
            std.mem.writeInt(u32, padded[32 - 4 ..][0..4], bits, .big);
            final_state.setRate(padded);
            final_state.setCapacity(hash_state);
            final_state.compress();
        } else {
            final_state.setRate(padded);
            final_state.setCapacity(hash_state);
            final_state.compress();
            hash_state = final_state.getCapacity();

            @memset(&padded, 0);
            std.mem.writeInt(u32, padded[32 - 4 ..][0..4], bits, .big);
            final_state = Self{};
            final_state.setRate(padded);
            final_state.setCapacity(hash_state);
            final_state.compress();
        }

        final_state.extractOutput(out);
    }
};

/// Areion256 implements the 256-bit variant of the Areion permutation family.
/// It uses a 256-bit state (2 AES blocks) with 16-byte input absorption and 16-byte output.
/// This variant is more compact than Areion512 while maintaining good performance.
pub const Areion256 = struct {
    const Self = @This();

    /// Block length for input absorption (16 bytes)
    pub const block_length = 16;
    /// Digest length for hash output (16 bytes)
    pub const digest_length = 16;
    /// Options for hash function (currently unused)
    pub const Options = struct {};

    /// Internal state consisting of 2 AES blocks (256 bits total)
    /// blocks[0] forms the "rate" part for input absorption
    /// blocks[1] forms the "capacity" part initialized with SHA-256 constant
    blocks: [2]AesBlock = blocks: {
        const ints = [_]u128{ 0x0, 0x6a09e667bb67ae853c6ef372a54ff53a };
        var blocks: [2]AesBlock = undefined;
        for (&blocks, ints) |*rc, v| {
            var b: [16]u8 = undefined;
            std.mem.writeInt(u128, &b, v, .little);
            rc.* = AesBlock.fromBytes(&b);
        }
        break :blocks blocks;
    },

    /// Creates an Areion256 instance from a 32-byte array.
    /// The bytes are interpreted as 2 consecutive AES blocks.
    /// @param bytes 32-byte array representing the full state
    /// @return New Areion256 instance with the given state
    pub fn fromBytes(bytes: [32]u8) Self {
        var blocks: [2]AesBlock = undefined;
        inline for (&blocks, 0..) |*b, i| {
            b.* = AesBlock.fromBytes(bytes[i * 16 ..][0..16]);
        }
        return Self{ .blocks = blocks };
    }

    /// Sets the rate portion (first block) of the state.
    /// The rate portion is used for input absorption.
    /// @param bytes 16-byte array to set as the rate
    pub fn setRate(self: *Self, bytes: [16]u8) void {
        self.blocks[0] = AesBlock.fromBytes(bytes[0..16]);
    }

    /// Sets the capacity portion (second block) of the state.
    /// The capacity portion maintains the internal hash state.
    /// @param state 16-byte array to set as the capacity
    pub fn setCapacity(self: *Self, state: [16]u8) void {
        self.blocks[1] = AesBlock.fromBytes(state[0..16]);
    }

    /// Extracts the capacity portion (second block) of the state.
    /// @return 16-byte array containing the capacity state
    pub fn getCapacity(self: Self) [16]u8 {
        return self.blocks[1].toBytes();
    }

    /// Absorbs 16 bytes of input into the rate portion of the state.
    /// The input is XORed with the current rate (first block).
    /// @param bytes 16-byte input block to absorb
    pub fn absorb(self: *Self, bytes: [16]u8) void {
        const block0_bytes = self.blocks[0].toBytes();

        var new_block0_bytes: [16]u8 = undefined;

        inline for (block0_bytes, new_block0_bytes[0..], bytes) |old, *new, input| {
            new.* = old ^ input;
        }

        self.blocks[0] = AesBlock.fromBytes(&new_block0_bytes);
    }

    /// Squeezes 16 bytes from the rate portion of the state.
    /// Returns the current rate (first block) as output.
    /// @return 16-byte output extracted from the rate
    pub fn squeeze(self: Self) [16]u8 {
        return self.blocks[0].toBytes();
    }

    /// Applies Davies-Meyer compression to the state.
    /// Performs permutation and XORs the result with the original state.
    /// This is used in the hash function's compression phase.
    fn compress(self: *Self) void {
        const original_blocks = self.blocks;
        self.permute();
        inline for (0..2) |i| {
            const original_bytes = original_blocks[i].toBytes();
            const permuted_bytes = self.blocks[i].toBytes();
            var result_bytes: [16]u8 = undefined;
            inline for (permuted_bytes, original_bytes, result_bytes[0..]) |perm, orig, *result| {
                result.* = perm ^ orig;
            }
            self.blocks[i] = AesBlock.fromBytes(&result_bytes);
        }
    }

    /// Extracts the final hash output from the state.
    /// Takes the capacity block (second block) as the 16-byte output.
    /// @param output Pointer to 16-byte array to store the extracted output
    fn extractOutput(self: Self, output: *[16]u8) void {
        @memcpy(output[0..16], &self.blocks[1].toBytes());
    }

    /// Converts the entire state to a 32-byte array.
    /// Both AES blocks are concatenated into a single byte array.
    /// @return 32-byte array representing the complete state
    pub fn toBytes(self: Self) [32]u8 {
        var bytes: [32]u8 = undefined;
        inline for (self.blocks, 0..) |b, i| {
            @memcpy(bytes[i * 16 ..][0..16], &b.toBytes());
        }
        return bytes;
    }

    /// Applies the Areion256 permutation to the state.
    /// Performs 10 rounds of AES-based transformations using precomputed round constants.
    /// Each round alternates between two different transformation patterns.
    pub fn permute(self: *Self) void {
        const rcs = comptime rcs: {
            const ints = [10]u128{
                0x243f6a8885a308d313198a2e03707344, 0xa4093822299f31d0082efa98ec4e6c89, 0x452821e638d01377be5466cf34e90c6c, 0xc0ac29b7c97c50dd3f84d5b5b5470917, 0x9216d5d98979fb1bd1310ba698dfb5ac, 0x2ffd72dbd01adfb7b8e1afed6a267e96, 0xba7c9045f12c7f9924a19947b3916cf7, 0x801f2e2858efc16636920d871574e690, 0xa458fea3f4933d7e0d95748f728eb658, 0x718bcd5882154aee7b54a41dc25a59b5,
            };
            var rcs: [ints.len]AesBlock = undefined;
            for (&rcs, ints) |*rc, v| {
                var b: [16]u8 = undefined;
                std.mem.writeInt(u128, &b, v, .little);
                rc.* = AesBlock.fromBytes(&b);
            }
            break :rcs rcs;
        };
        const rc1 = comptime rc1: {
            const b = [_]u8{0} ** 16;
            break :rc1 AesBlock.fromBytes(&b);
        };

        inline for (rcs, 0..) |rc, round| {
            if (round % 2 == 0) {
                const new_x1 = self.blocks[0].encrypt(rc).encrypt(self.blocks[1]);
                const new_x0 = self.blocks[0].encryptLast(rc1);
                self.blocks = [2]AesBlock{ new_x0, new_x1 };
            } else {
                const new_x0 = self.blocks[1].encrypt(rc).encrypt(self.blocks[0]);
                const new_x1 = self.blocks[1].encryptLast(rc1);
                self.blocks = [2]AesBlock{ new_x0, new_x1 };
            }
        }
    }

    /// Computes the Areion256 hash of the input data.
    /// Uses Merkle-Damgård construction with Davies-Meyer compression.
    /// Processes input in 16-byte blocks with proper padding.
    /// @param b Input data to hash
    /// @param out Pointer to 16-byte array to store the hash digest
    /// @param options Hash options (currently unused)
    pub fn hash(b: []const u8, out: *[digest_length]u8, options: Options) void {
        _ = options;

        var hash_state: [16]u8 = undefined;
        const sha256_iv = [_]u8{ 0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb, 0x72, 0xf3, 0x6e, 0x3c, 0x3a, 0xf5, 0x4f, 0xa5 };
        @memcpy(&hash_state, &sha256_iv);

        const end = b.len - b.len % 16;
        var i: usize = 0;
        while (i < end) : (i += 16) {
            var state = Self{};
            state.setRate(b[i..][0..16].*);
            state.setCapacity(hash_state);
            state.compress();
            hash_state = state.getCapacity();
        }

        var padded = [_]u8{0} ** 16;
        const left = b.len - end;
        @memcpy(padded[0..left], b[end..]);
        padded[left] = 0x80;
        const bits: u32 = @intCast(b.len * 8);

        var final_state = Self{};
        if (left < 16 - 4) {
            std.mem.writeInt(u32, padded[16 - 4 ..][0..4], bits, .big);
            final_state.setRate(padded);
            final_state.setCapacity(hash_state);
            final_state.compress();
        } else {
            final_state.setRate(padded);
            final_state.setCapacity(hash_state);
            final_state.compress();
            hash_state = final_state.getCapacity();

            @memset(&padded, 0);
            std.mem.writeInt(u32, padded[16 - 4 ..][0..4], bits, .big);
            final_state = Self{};
            final_state.setRate(padded);
            final_state.setCapacity(hash_state);
            final_state.compress();
        }

        final_state.extractOutput(out);
    }
};

const testing = std.testing;

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
    try testing.expect(!std.mem.eql(u8, &out1, &out3));

    var empty_out: [32]u8 = undefined;
    Areion512.hash("", &empty_out, .{});
    try testing.expect(!std.mem.allEqual(u8, &empty_out, 0));
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
    try testing.expect(!std.mem.eql(u8, &out1, &out3));

    var empty_out: [16]u8 = undefined;
    Areion256.hash("", &empty_out, .{});
    try testing.expect(!std.mem.allEqual(u8, &empty_out, 0));
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

    try testing.expect(!std.mem.eql(u8, out1_512[0..16], &out1_256));
}
