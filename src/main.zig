const std = @import("std");
const AesBlock = std.crypto.core.aes.Block;

pub const Areion512 = struct {
    const Self = @This();

    pub const block_length = 32;
    pub const digest_length = 32;
    pub const Options = struct {};

    blocks: [4]AesBlock = blocks: {
        const ints = [_]u128{ 0x0, 0x0, 0x6a09e667bb67ae853c6ef372a54ff53a, 0x510e527f9b05688c1f83d9ab5be0cd19 };
        var blocks: [ints.len]AesBlock = undefined;
        for (&blocks, ints) |*rc, v| {
            var b: [16]u8 = undefined;
            std.mem.writeIntLittle(u128, &b, v);
            rc.* = AesBlock.fromBytes(&b);
        }
        break :blocks blocks;
    },

    pub fn fromBytes(bytes: [64]u8) Self {
        var blocks: [4]AesBlock = undefined;
        inline for (&blocks, 0..) |*b, i| {
            b.* = AesBlock.fromBytes(bytes[i * 16 ..][0..16]);
        }
        return Self{ .blocks = blocks };
    }

    pub fn absorb(self: *Self, bytes: [32]u8) void {
        self.blocks[0] = AesBlock.fromBytes(bytes[0 * 16 ..][0..16]);
        self.blocks[1] = AesBlock.fromBytes(bytes[1 * 16 ..][0..16]);
    }

    pub fn squeeze(self: Self, bytes: *[32]u8) void {
        @memcpy(bytes[0 * 16 ..][0..16], &self.blocks[2].toBytes());
        @memcpy(bytes[1 * 16 ..][0..16], &self.blocks[3].toBytes());
    }

    pub fn toBytes(self: Self) [64]u8 {
        var bytes: [64]u8 = undefined;
        for (self.blocks, 0..) |b, i| {
            @memcpy(bytes[i * 16 ..][0..16], &b.toBytes());
        }
        return bytes;
    }

    pub fn permute(self: *Self) void {
        const rcs = comptime rcs: {
            const ints = [15]u128{
                0x243f6a8885a308d313198a2e03707344, 0xa4093822299f31d0082efa98ec4e6c89, 0x452821e638d01377be5466cf34e90c6c, 0xc0ac29b7c97c50dd3f84d5b5b5470917, 0x9216d5d98979fb1bd1310ba698dfb5ac, 0x2ffd72dbd01adfb7b8e1afed6a267e96, 0xba7c9045f12c7f9924a19947b3916cf7, 0x801f2e2858efc16636920d871574e690, 0xa458fea3f4933d7e0d95748f728eb658, 0x718bcd5882154aee7b54a41dc25a59b5, 0x9c30d5392af26013c5d1b023286085f0, 0xca417918b8db38ef8e79dcb0603a180e, 0x6c9e0e8bb01e8a3ed71577c1bd314b27, 0x78af2fda55605c60e65525f3aa55ab94, 0x5748986263e8144055ca396a2aab10b6,
            };
            var rcs: [ints.len]AesBlock = undefined;
            for (&rcs, ints) |*rc, v| {
                var b: [16]u8 = undefined;
                std.mem.writeIntLittle(u128, &b, v);
                rc.* = AesBlock.fromBytes(&b);
            }
            break :rcs rcs;
        };
        const rc0 = comptime rc0: {
            const b = [_]u8{0} ** 16;
            break :rc0 AesBlock.fromBytes(&b);
        };
        inline for (rcs) |rc| {
            const x0 = self.blocks[0].encrypt(self.blocks[1]);
            const x1 = self.blocks[2].encryptLast(rc).encrypt(rc0);
            const x2 = self.blocks[2].encrypt(self.blocks[3]);
            const x3 = self.blocks[0].encryptLast(rc0);
            self.blocks = [4]AesBlock{ x0, x1, x2, x3 };
        }
    }

    pub fn hash(b: []const u8, out: *[digest_length]u8, options: Options) void {
        _ = options;

        var state = Self{};
        const end = b.len - b.len % 32;
        var i: usize = 0;
        while (i < end) : (i += 32) {
            state.absorb(b[i..][0..32].*);
            state.permute();
        }
        var padded = [_]u8{0} ** 32;
        const left = b.len - end;
        @memcpy(padded[0..left], b[end..]);
        padded[b.len - end] = 0x80;
        const bits = b.len * 8;
        if (left < 32 - 8) {
            std.mem.writeIntBig(u64, padded[32 - 8 ..], bits);
        } else {
            state.absorb(padded);
            state.permute();
            @memset(&padded, 0);
            std.mem.writeIntBig(u64, padded[32 - 8 ..], bits);
        }
        state.absorb(padded);
        state.permute();
        state.squeeze(out);
    }
};
