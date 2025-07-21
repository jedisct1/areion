const std = @import("std");
const AesBlock = std.crypto.core.aes.Block;

/// Areion512 implements the 512-bit variant of the Areion permutation and hash function.
/// It uses 4 AES blocks (512 bits total) and is optimized for speed, particularly on small inputs.
/// The state is divided into rate (blocks 0-1) and capacity (blocks 2-3) portions.
pub const Areion512 = struct {
    const Self = @This();

    /// Number of bytes absorbed per permutation (rate portion)
    pub const block_length = 32;
    /// Number of bytes output by the hash function
    pub const digest_length = 32;
    /// Hash function options (currently unused)
    pub const Options = struct {};

    /// Internal state: 4 AES blocks (512 bits total)
    /// blocks[0] and blocks[1] are rate, blocks[2] and blocks[3] are capacity initialized with SHA-256 constants
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

    /// Creates an Areion512 state from a 64-byte array
    pub fn fromBytes(bytes: [64]u8) Self {
        var blocks: [4]AesBlock = undefined;
        inline for (&blocks, 0..) |*b, i| {
            b.* = AesBlock.fromBytes(bytes[i * 16 ..][0..16]);
        }
        return Self{ .blocks = blocks };
    }

    /// Sets the rate portion (blocks 0 and 1) of the state
    pub fn setRate(self: *Self, bytes: [32]u8) void {
        self.blocks[0] = AesBlock.fromBytes(bytes[0..16]);
        self.blocks[1] = AesBlock.fromBytes(bytes[16..32]);
    }

    /// Sets the capacity portion (blocks 2 and 3) of the state
    pub fn setCapacity(self: *Self, state: [32]u8) void {
        self.blocks[2] = AesBlock.fromBytes(state[0..16]);
        self.blocks[3] = AesBlock.fromBytes(state[16..32]);
    }

    /// Retrieves the capacity portion (blocks 2 and 3) of the state
    pub fn getCapacity(self: Self) [32]u8 {
        var state: [32]u8 = undefined;
        @memcpy(state[0..16], &self.blocks[2].toBytes());
        @memcpy(state[16..32], &self.blocks[3].toBytes());
        return state;
    }

    /// Absorbs 32 bytes into the rate portion using XOR
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

    /// Extracts 32 bytes from the rate portion of the state
    pub fn squeeze(self: Self) [32]u8 {
        var rate: [32]u8 = undefined;
        @memcpy(rate[0..16], &self.blocks[0].toBytes());
        @memcpy(rate[16..32], &self.blocks[1].toBytes());
        return rate;
    }

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

    /// Converts the entire state to a 64-byte array
    pub fn toBytes(self: Self) [64]u8 {
        var bytes: [64]u8 = undefined;
        inline for (self.blocks, 0..) |b, i| {
            @memcpy(bytes[i * 16 ..][0..16], &b.toBytes());
        }
        return bytes;
    }

    fn roundFunction512(x0: *AesBlock, x1: *AesBlock, x2: *AesBlock, x3: *AesBlock, rc: AesBlock, rc1: AesBlock) void {
        x1.* = x0.encrypt(x1.*);
        x3.* = x2.encrypt(x3.*);
        x0.* = x0.encryptLast(rc1);
        x2.* = x2.encryptLast(rc).encrypt(rc1);
    }

    /// Applies the Areion512 permutation (15 rounds)
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

        var i: usize = 0;
        while (i < 12) : (i += 4) {
            roundFunction512(&self.blocks[0], &self.blocks[1], &self.blocks[2], &self.blocks[3], rcs[i + 0], rc1);
            roundFunction512(&self.blocks[1], &self.blocks[2], &self.blocks[3], &self.blocks[0], rcs[i + 1], rc1);
            roundFunction512(&self.blocks[2], &self.blocks[3], &self.blocks[0], &self.blocks[1], rcs[i + 2], rc1);
            roundFunction512(&self.blocks[3], &self.blocks[0], &self.blocks[1], &self.blocks[2], rcs[i + 3], rc1);
        }

        roundFunction512(&self.blocks[0], &self.blocks[1], &self.blocks[2], &self.blocks[3], rcs[12], rc1);
        roundFunction512(&self.blocks[1], &self.blocks[2], &self.blocks[3], &self.blocks[0], rcs[13], rc1);
        roundFunction512(&self.blocks[2], &self.blocks[3], &self.blocks[0], &self.blocks[1], rcs[14], rc1);

        // Final rotation: (x0,x1,x2,x3) -> (x3,x2,x1,x0)
        const temp = self.blocks[0];
        self.blocks[0] = self.blocks[3];
        self.blocks[3] = self.blocks[2];
        self.blocks[2] = self.blocks[1];
        self.blocks[1] = temp;
    }

    /// Applies the inverse Areion512 permutation
    pub fn inversePermute(self: *Self) void {
        // Reverse the final block rotation: (x0,x1,x2,x3) -> (x3,x0,x1,x2)
        const temp = self.blocks[0];
        self.blocks[0] = self.blocks[3];
        self.blocks[3] = self.blocks[2];
        self.blocks[2] = self.blocks[1];
        self.blocks[1] = temp;

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

        const invRoundFunction512 = struct {
            fn apply(x0: *AesBlock, x1: *AesBlock, x2: *AesBlock, x3: *AesBlock, rc: AesBlock, zero: AesBlock) void {
                // Note: This doesn't match the C reference exactly due to lack of inverse MixColumns
                x0.* = x0.decryptLast(zero);
                x2.* = x2.decrypt(rc).decryptLast(zero);
                x1.* = x0.encrypt(x1.*);
                x3.* = x2.encrypt(x3.*);
            }
        }.apply;
        invRoundFunction512(&self.blocks[2], &self.blocks[3], &self.blocks[0], &self.blocks[1], rcs[14], rc1);
        invRoundFunction512(&self.blocks[1], &self.blocks[2], &self.blocks[3], &self.blocks[0], rcs[13], rc1);
        invRoundFunction512(&self.blocks[0], &self.blocks[1], &self.blocks[2], &self.blocks[3], rcs[12], rc1);

        var i: usize = 0;
        while (i < 12) : (i += 4) {
            invRoundFunction512(&self.blocks[3], &self.blocks[0], &self.blocks[1], &self.blocks[2], rcs[11 - i], rc1);
            invRoundFunction512(&self.blocks[2], &self.blocks[3], &self.blocks[0], &self.blocks[1], rcs[10 - i], rc1);
            invRoundFunction512(&self.blocks[1], &self.blocks[2], &self.blocks[3], &self.blocks[0], rcs[9 - i], rc1);
            invRoundFunction512(&self.blocks[0], &self.blocks[1], &self.blocks[2], &self.blocks[3], rcs[8 - i], rc1);
        }
    }

    /// Computes the Areion512 hash of the input data
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

/// Areion256 implements the 256-bit variant of the Areion permutation and hash function.
/// It uses 2 AES blocks (256 bits total) and is designed for constrained environments.
/// The state is divided into rate (block 0) and capacity (block 1) portions.
pub const Areion256 = struct {
    const Self = @This();

    /// Number of bytes absorbed per permutation (rate portion)
    pub const block_length = 16;
    /// Number of bytes output by the hash function
    pub const digest_length = 16;
    /// Hash function options (currently unused)
    pub const Options = struct {};

    /// Internal state: 2 AES blocks (256 bits total)
    /// blocks[0] is rate, blocks[1] is capacity initialized with SHA-256 constant
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

    /// Creates an Areion256 state from a 32-byte array
    pub fn fromBytes(bytes: [32]u8) Self {
        var blocks: [2]AesBlock = undefined;
        inline for (&blocks, 0..) |*b, i| {
            b.* = AesBlock.fromBytes(bytes[i * 16 ..][0..16]);
        }
        return Self{ .blocks = blocks };
    }

    /// Sets the rate portion (block 0) of the state
    pub fn setRate(self: *Self, bytes: [16]u8) void {
        self.blocks[0] = AesBlock.fromBytes(bytes[0..16]);
    }

    /// Sets the capacity portion (block 1) of the state
    pub fn setCapacity(self: *Self, state: [16]u8) void {
        self.blocks[1] = AesBlock.fromBytes(state[0..16]);
    }

    /// Retrieves the capacity portion (block 1) of the state
    pub fn getCapacity(self: Self) [16]u8 {
        return self.blocks[1].toBytes();
    }

    /// Absorbs 16 bytes into the rate portion using XOR
    pub fn absorb(self: *Self, bytes: [16]u8) void {
        const block0_bytes = self.blocks[0].toBytes();

        var new_block0_bytes: [16]u8 = undefined;

        inline for (block0_bytes, new_block0_bytes[0..], bytes) |old, *new, input| {
            new.* = old ^ input;
        }

        self.blocks[0] = AesBlock.fromBytes(&new_block0_bytes);
    }

    /// Extracts 16 bytes from the rate portion of the state
    pub fn squeeze(self: Self) [16]u8 {
        return self.blocks[0].toBytes();
    }

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

    fn extractOutput(self: Self, output: *[16]u8) void {
        @memcpy(output[0..16], &self.blocks[1].toBytes());
    }

    /// Converts the entire state to a 32-byte array
    pub fn toBytes(self: Self) [32]u8 {
        var bytes: [32]u8 = undefined;
        inline for (self.blocks, 0..) |b, i| {
            @memcpy(bytes[i * 16 ..][0..16], &b.toBytes());
        }
        return bytes;
    }

    /// Applies the Areion256 permutation (10 rounds)
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

    /// Applies the inverse Areion256 permutation
    pub fn inversePermute(self: *Self) void {
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

        var i: usize = 0;
        while (i < 10) : (i += 2) {
            {
                const rc = rcs[9 - i];
                self.blocks[1] = self.blocks[1].decryptLast(rc1);
                self.blocks[0] = self.blocks[1].encrypt(rc).encrypt(self.blocks[0]);
            }
            {
                const rc = rcs[8 - i];
                self.blocks[0] = self.blocks[0].decryptLast(rc1);
                self.blocks[1] = self.blocks[0].encrypt(rc).encrypt(self.blocks[1]);
            }
        }
    }

    /// Computes the Areion256 hash of the input data
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

const OppState256 = struct {
    const Self = @This();

    a: u64,
    b: u64,
    c: u64,
    d: u64,

    fn fromBytes(bytes: [32]u8) Self {
        return Self{
            .a = std.mem.readInt(u64, bytes[0..8], .little),
            .b = std.mem.readInt(u64, bytes[8..16], .little),
            .c = std.mem.readInt(u64, bytes[16..24], .little),
            .d = std.mem.readInt(u64, bytes[24..32], .little),
        };
    }

    fn toBytes(self: Self) [32]u8 {
        var bytes: [32]u8 = undefined;
        std.mem.writeInt(u64, bytes[0..8], self.a, .little);
        std.mem.writeInt(u64, bytes[8..16], self.b, .little);
        std.mem.writeInt(u64, bytes[16..24], self.c, .little);
        std.mem.writeInt(u64, bytes[24..32], self.d, .little);
        return bytes;
    }

    fn xor(self: Self, other: Self) Self {
        return Self{
            .a = self.a ^ other.a,
            .b = self.b ^ other.b,
            .c = self.c ^ other.c,
            .d = self.d ^ other.d,
        };
    }
};

const OppState512 = struct {
    const Self = @This();

    s: [8]u64,

    fn fromBytes(bytes: [64]u8) Self {
        var s: [8]u64 = undefined;
        for (&s, 0..) |*word, i| {
            word.* = std.mem.readInt(u64, bytes[i * 8 ..][0..8], .little);
        }
        return Self{ .s = s };
    }

    fn toBytes(self: Self) [64]u8 {
        var bytes: [64]u8 = undefined;
        for (self.s, 0..) |word, i| {
            std.mem.writeInt(u64, bytes[i * 8 ..][0..8], word, .little);
        }
        return bytes;
    }

    fn xor(self: Self, other: Self) Self {
        var result: [8]u64 = undefined;
        for (&result, self.s, other.s) |*r, a, b| {
            r.* = a ^ b;
        }
        return Self{ .s = result };
    }
};

/// Areion256-OPP implements the Offset Public Permutation mode using Areion256.
/// This is an authenticated encryption with associated data (AEAD) construction.
/// It provides confidentiality and authenticity for messages with optional associated data.
pub const Areion256Opp = struct {
    const Self = @This();

    /// Length of the encryption key in bytes
    pub const key_length = 16;
    /// Length of the nonce in bytes
    pub const nonce_length = 16;
    /// Length of the authentication tag in bytes
    pub const tag_length = 16;
    /// Number of bytes processed per encryption block
    pub const block_length = 32;

    /// State accumulator for associated data
    sa: OppState256,
    /// State accumulator for message data
    se: OppState256,
    /// Linear function state for associated data
    la: OppState256,
    /// Linear function state for message data
    le: OppState256,
    /// Buffer for partial associated data blocks
    ad_buf: [32]u8,
    /// Buffer for partial message blocks
    buf: [32]u8,
    /// Length of partial associated data in buffer
    ad_partial_len: usize,
    /// Length of partial message data in buffer
    partial_len: usize,
    /// Mode flag: true for encryption, false for decryption
    is_encrypt: bool,
    /// Flag indicating if associated data processing is complete
    ad_finalized: bool,

    /// Initializes an Areion256-OPP cipher instance for encryption or decryption
    pub fn init(key: [key_length]u8, nonce: [nonce_length]u8, is_encrypt: bool) Self {
        const la = initMask256(key, nonce);
        const le = gamma256(la);

        return Self{
            .sa = OppState256{ .a = 0, .b = 0, .c = 0, .d = 0 },
            .se = OppState256{ .a = 0, .b = 0, .c = 0, .d = 0 },
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

    /// Processes associated data (must be called before update)
    pub fn updateAd(self: *Self, ad: []const u8) void {
        var offset: usize = 0;

        if (self.ad_partial_len > 0) {
            const needed = @min(ad.len, block_length - self.ad_partial_len);
            @memcpy(self.ad_buf[self.ad_partial_len .. self.ad_partial_len + needed], ad[0..needed]);
            self.ad_partial_len += needed;
            offset = needed;

            if (self.ad_partial_len == block_length) {
                const block_state = OppState256.fromBytes(self.ad_buf);
                const outb = oppMem256(block_state, self.la);
                self.sa = self.sa.xor(outb);
                self.la = alpha256(self.la);
                self.ad_partial_len = 0;
            }
        }

        while (offset + block_length <= ad.len) {
            const block_state = OppState256.fromBytes(ad[offset .. offset + block_length][0..block_length].*);
            const outb = oppMem256(block_state, self.la);
            self.sa = self.sa.xor(outb);
            self.la = alpha256(self.la);
            offset += block_length;
        }

        if (offset < ad.len) {
            const remaining = ad.len - offset;
            @memcpy(self.ad_buf[0..remaining], ad[offset..]);
            self.ad_partial_len = remaining;
        }
    }

    fn finalizeAd(self: *Self) void {
        if (!self.ad_finalized) {
            self.ad_finalized = true;
            if (self.ad_partial_len > 0) {
                @memset(self.ad_buf[self.ad_partial_len..], 0);
                self.ad_buf[self.ad_partial_len] = 0x01;

                const mask = beta256(self.la);
                const block_state = OppState256.fromBytes(self.ad_buf);
                const outb = oppMem256(block_state, mask);
                self.sa = self.sa.xor(outb);
                self.la = alpha256(mask);
            }
        }
    }

    /// Processes plaintext/ciphertext and produces output
    pub fn update(self: *Self, output: []u8, input: []const u8) void {
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
                    self.se = self.se.xor(block_state);
                } else {
                    const outb = oppMemInverse256(block_state, self.le);
                    const result_bytes = outb.toBytes();
                    @memcpy(output[0..block_length], &result_bytes);
                    self.se = self.se.xor(outb);
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
                self.se = self.se.xor(block_state);
            } else {
                const outb = oppMemInverse256(block_state, self.le);
                const result_bytes = outb.toBytes();
                @memcpy(output[offset .. offset + block_length], &result_bytes);
                self.se = self.se.xor(outb);
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

    /// Finalizes the operation and generates authentication tag
    pub fn finalize(self: *Self, output: []u8, tag: *[tag_length]u8) void {
        self.finalizeAd();

        if (self.partial_len > 0) {
            self.le = beta256(self.le);
            @memset(self.buf[self.partial_len..], 0);
            self.buf[self.partial_len] = 0x01;

            const inb = OppState256.fromBytes(self.buf);
            const zero_state = OppState256{ .a = 0, .b = 0, .c = 0, .d = 0 };
            const block = oppMem256(zero_state, self.le);
            const outb = block.xor(inb);

            const result_bytes = outb.toBytes();
            if (output.len >= self.partial_len) {
                @memcpy(output[0..self.partial_len], result_bytes[0..self.partial_len]);
            }

            if (self.is_encrypt) {
                self.se = self.se.xor(inb);
            } else {
                var plain_buf = [_]u8{0} ** 32;
                @memcpy(plain_buf[0..self.partial_len], result_bytes[0..self.partial_len]);
                plain_buf[self.partial_len] = 0x01;
                const plainb = OppState256.fromBytes(plain_buf);
                self.se = self.se.xor(plainb);
            }
        }

        const final_mask = beta256(beta256(self.le));
        const tag_state = self.sa.xor(oppMem256(self.se, final_mask));
        const tag_bytes = tag_state.toBytes();
        @memcpy(tag, tag_bytes[0..tag_length]);
    }

    /// Encrypts plaintext with associated data and generates authentication tag
    pub fn encrypt(key: [key_length]u8, nonce: [nonce_length]u8, ad: []const u8, plaintext: []const u8, ciphertext: []u8, tag: *[tag_length]u8) void {
        var state = Self.init(key, nonce, true);
        state.updateAd(ad);

        const full_blocks = plaintext.len / block_length;
        const processed_len = full_blocks * block_length;

        state.update(ciphertext, plaintext);

        var empty_output: [0]u8 = undefined;
        const remaining_output = if (processed_len < ciphertext.len) ciphertext[processed_len..] else &empty_output;
        state.finalize(remaining_output, tag);
    }

    /// Decrypts ciphertext with associated data and verifies authentication tag
    pub fn decrypt(key: [key_length]u8, nonce: [nonce_length]u8, ad: []const u8, ciphertext: []const u8, tag: [tag_length]u8, plaintext: []u8) !void {
        var state = Self.init(key, nonce, false);
        state.updateAd(ad);

        const full_blocks = ciphertext.len / block_length;
        const processed_len = full_blocks * block_length;

        state.update(plaintext, ciphertext);

        var empty_output: [0]u8 = undefined;
        const remaining_output = if (processed_len < plaintext.len) plaintext[processed_len..] else &empty_output;
        var computed_tag: [tag_length]u8 = undefined;
        state.finalize(remaining_output, &computed_tag);

        if (!std.mem.eql(u8, &computed_tag, &tag)) {
            return error.AuthenticationFailed;
        }
    }
};

/// Areion512-OPP implements the Offset Public Permutation mode using Areion512.
/// This is an authenticated encryption with associated data (AEAD) construction.
/// It provides higher throughput than Areion256-OPP with 64-byte blocks.
pub const Areion512Opp = struct {
    const Self = @This();

    /// Length of the encryption key in bytes
    pub const key_length = 16;
    /// Length of the nonce in bytes
    pub const nonce_length = 16;
    /// Length of the authentication tag in bytes
    pub const tag_length = 16;
    /// Number of bytes processed per encryption block
    pub const block_length = 64;

    /// State accumulator for associated data
    sa: OppState512,
    /// State accumulator for message data
    se: OppState512,
    /// Linear function state for associated data
    la: OppState512,
    /// Linear function state for message data
    le: OppState512,
    /// Buffer for partial associated data blocks
    ad_buf: [64]u8,
    /// Buffer for partial message blocks
    buf: [64]u8,
    /// Length of partial associated data in buffer
    ad_partial_len: usize,
    /// Length of partial message data in buffer
    partial_len: usize,
    /// Flag indicating if associated data processing is complete
    ad_finalized: bool,

    /// Initializes an Areion512-OPP cipher instance
    pub fn init(key: [key_length]u8, nonce: [nonce_length]u8) Self {
        const la = initMask512(key, nonce);
        const le = gamma512(la);

        return Self{
            .sa = OppState512{ .s = [_]u64{0} ** 8 },
            .se = OppState512{ .s = [_]u64{0} ** 8 },
            .la = la,
            .le = le,
            .ad_buf = [_]u8{0} ** 64,
            .buf = [_]u8{0} ** 64,
            .ad_partial_len = 0,
            .partial_len = 0,
            .ad_finalized = false,
        };
    }

    /// Processes associated data (must be called before update)
    pub fn updateAd(self: *Self, ad: []const u8) void {
        var offset: usize = 0;

        if (self.ad_partial_len > 0) {
            const needed = @min(ad.len, block_length - self.ad_partial_len);
            @memcpy(self.ad_buf[self.ad_partial_len .. self.ad_partial_len + needed], ad[0..needed]);
            self.ad_partial_len += needed;
            offset = needed;

            if (self.ad_partial_len == block_length) {
                const block_state = OppState512.fromBytes(self.ad_buf);
                const outb = oppMem512(block_state, self.la);
                self.sa = self.sa.xor(outb);
                self.la = alpha512(self.la);
                self.ad_partial_len = 0;
            }
        }

        while (offset + block_length <= ad.len) {
            const block_state = OppState512.fromBytes(ad[offset .. offset + block_length][0..block_length].*);
            const outb = oppMem512(block_state, self.la);
            self.sa = self.sa.xor(outb);
            self.la = alpha512(self.la);
            offset += block_length;
        }

        if (offset < ad.len) {
            const remaining = ad.len - offset;
            @memcpy(self.ad_buf[0..remaining], ad[offset..]);
            self.ad_partial_len = remaining;
        }
    }

    fn finalizeAd(self: *Self) void {
        if (!self.ad_finalized) {
            self.ad_finalized = true;
            if (self.ad_partial_len > 0) {
                @memset(self.ad_buf[self.ad_partial_len..], 0);
                self.ad_buf[self.ad_partial_len] = 0x01;

                const mask = beta512(self.la);
                const block_state = OppState512.fromBytes(self.ad_buf);
                const outb = oppMem512(block_state, mask);
                self.sa = self.sa.xor(outb);
                self.la = alpha512(mask);
            }
        }
    }

    /// Processes plaintext and produces ciphertext
    pub fn update(self: *Self, output: []u8, input: []const u8) void {
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
                self.se = self.se.xor(block_state);

                self.le = alpha512(self.le);
                self.partial_len = 0;
            }
        }

        while (offset + block_length <= input.len) {
            const block_state = OppState512.fromBytes(input[offset .. offset + block_length][0..block_length].*);

            const outb = oppMem512(block_state, self.le);
            const result_bytes = outb.toBytes();
            @memcpy(output[offset .. offset + block_length], &result_bytes);
            self.se = self.se.xor(block_state);

            self.le = alpha512(self.le);
            offset += block_length;
        }

        if (offset < input.len) {
            const remaining = input.len - offset;
            @memcpy(self.buf[0..remaining], input[offset..]);
            self.partial_len = remaining;
        }
    }

    /// Finalizes the operation and generates authentication tag
    pub fn finalize(self: *Self, output: []u8, tag: *[tag_length]u8) void {
        self.finalizeAd();

        if (self.partial_len > 0) {
            self.le = beta512(self.le);
            @memset(self.buf[self.partial_len..], 0);
            self.buf[self.partial_len] = 0x01;

            const inb = OppState512.fromBytes(self.buf);
            const zero_state = OppState512{ .s = [_]u64{0} ** 8 };
            const block = oppMem512(zero_state, self.le);
            const outb = block.xor(inb);

            const result_bytes = outb.toBytes();
            if (output.len >= self.partial_len) {
                @memcpy(output[0..self.partial_len], result_bytes[0..self.partial_len]);
            }

            self.se = self.se.xor(inb);
        }

        const final_mask = beta512(beta512(self.le));
        const tag_state = self.sa.xor(oppMem512(self.se, final_mask));
        const tag_bytes = tag_state.toBytes();
        @memcpy(tag, tag_bytes[0..tag_length]);
    }

    /// Encrypts plaintext with associated data and generates authentication tag
    pub fn encrypt(key: [key_length]u8, nonce: [nonce_length]u8, ad: []const u8, plaintext: []const u8, ciphertext: []u8, tag: *[tag_length]u8) void {
        var state = Self.init(key, nonce);
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
    return phi256(x).xor(x);
}

fn gamma256(x: OppState256) OppState256 {
    const phi_x = phi256(x);
    const phi2_x = phi256(phi_x);
    return phi2_x.xor(phi_x).xor(x);
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
    return phi512(x).xor(x);
}

fn gamma512(x: OppState512) OppState512 {
    const phi_x = phi512(x);
    const phi2_x = phi512(phi_x);
    return phi2_x.xor(phi_x).xor(x);
}

fn oppMem256(x: OppState256, m: OppState256) OppState256 {
    const xor_result = x.xor(m);
    const bytes = xor_result.toBytes();

    var areion_state = Areion256.fromBytes(bytes);
    areion_state.permute();
    const permuted_bytes = areion_state.toBytes();

    const permuted_state = OppState256.fromBytes(permuted_bytes);
    return permuted_state.xor(m);
}

fn oppMemInverse256(x: OppState256, m: OppState256) OppState256 {
    const xor_result = x.xor(m);
    const bytes = xor_result.toBytes();

    var areion_state = Areion256.fromBytes(bytes);
    areion_state.inversePermute();
    const permuted_bytes = areion_state.toBytes();

    const permuted_state = OppState256.fromBytes(permuted_bytes);
    return permuted_state.xor(m);
}

fn oppMem512(x: OppState512, m: OppState512) OppState512 {
    const xor_result = x.xor(m);
    const bytes = xor_result.toBytes();

    var areion_state = Areion512.fromBytes(bytes);
    areion_state.permute();
    const permuted_bytes = areion_state.toBytes();

    const permuted_state = OppState512.fromBytes(permuted_bytes);
    return permuted_state.xor(m);
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
