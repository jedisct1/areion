//! OCH - Offset Codebook with Hashing authenticated encryption scheme.
//!
//! OCH is a generic AEAD construction providing:
//! - 128-bit NAE (nonce-based authenticated encryption) security
//! - 128-bit CMT (context commitment) security
//! - 256-bit nonces with optional nonce privacy
//!
//! Unlike standard AEAD schemes, OCH embeds a secret nonce in the ciphertext,
//! so `c.len == m.len + secret_nonce_length`.
//!
//! Based on the OCH paper (CCS 2025).

const std = @import("std");
const debug = std.debug;
const mem = std.mem;
const crypto = std.crypto;
const AuthenticationError = crypto.errors.AuthenticationError;

const root = @import("main.zig");

/// AreionOCH is an instantiation of OCH using Areion512 for the sponge,
/// Areion256 for the tweakable block cipher, and Polyval for universal hashing.
pub const AreionOCH = Och(root.Areion512, root.Areion256, crypto.onetimeauth.Polyval);

/// OCH authenticated encryption with associated data.
///
/// OCH provides nonce misuse resistance and key commitment security.
/// The secret nonce is embedded in the ciphertext for nonce privacy.
pub fn Och(comptime SpongePermutation: type, comptime TbcPermutation: type, comptime UniversalHash: type) type {
    return struct {
        pub const key_length = 32;
        pub const npub_length = 24;
        pub const nsec_length = 8;
        pub const nonce_length = npub_length + nsec_length;
        pub const tag_length = UniversalHash.mac_length * 2;
        pub const block_length = 32;

        const kappa: usize = 128;
        const tbc_key_length = 32;
        const axu_key_length = UniversalHash.key_length * 2;
        const derived_key_length = tbc_key_length + axu_key_length;

        const SpongePrf = Sponge(SpongePermutation);
        const OctTbc = Oct(TbcPermutation, @This());
        const DoubleHash = DoubleUniversalHash(UniversalHash);

        /// c: Ciphertext destination buffer (m.len + nsec_length bytes).
        /// tag: Authentication tag destination buffer.
        /// m: Plaintext message.
        /// ad: Associated data.
        /// npub: Public nonce.
        /// nsec: Secret nonce (embedded in ciphertext).
        /// key: Secret key.
        pub fn encrypt(
            c: []u8,
            tag: *[tag_length]u8,
            m: []const u8,
            ad: []const u8,
            npub: [npub_length]u8,
            nsec: [nsec_length]u8,
            key: [key_length]u8,
        ) void {
            debug.assert(c.len == m.len + nsec_length);

            const derived = SpongePrf.prf(derived_key_length, key, &.{"\x03"});
            const tbc_key: [tbc_key_length]u8 = derived[0..tbc_key_length].*;
            const axu_key: [axu_key_length]u8 = derived[tbc_key_length..derived_key_length].*;

            if (m.len + nsec_length < block_length) {
                encryptTiny(c, tag, m, ad, npub, nsec, key, tbc_key, axu_key);
            } else {
                encryptCore(c, tag, m, ad, npub, nsec, key, tbc_key, axu_key);
            }
        }

        /// m: Plaintext destination buffer (c.len - nsec_length bytes).
        /// nsec: Recovered secret nonce destination.
        /// c: Ciphertext.
        /// tag: Authentication tag.
        /// ad: Associated data.
        /// npub: Public nonce.
        /// key: Secret key.
        ///
        /// Asserts `c.len >= nsec_length` and `m.len == c.len - nsec_length`.
        /// Contents of `m` and `nsec` are undefined if an error is returned.
        pub fn decrypt(
            m: []u8,
            nsec: *[nsec_length]u8,
            c: []const u8,
            tag: [tag_length]u8,
            ad: []const u8,
            npub: [npub_length]u8,
            key: [key_length]u8,
        ) AuthenticationError!void {
            debug.assert(c.len >= nsec_length);
            debug.assert(m.len == c.len - nsec_length);

            const derived = SpongePrf.prf(derived_key_length, key, &.{"\x03"});
            const tbc_key: [tbc_key_length]u8 = derived[0..tbc_key_length].*;
            const axu_key: [axu_key_length]u8 = derived[tbc_key_length..derived_key_length].*;

            if (c.len < block_length) {
                return decryptTiny(m, nsec, c, tag, ad, npub, key, tbc_key, axu_key);
            } else {
                return decryptCore(m, nsec, c, tag, ad, npub, key, tbc_key, axu_key);
            }
        }

        fn encryptTiny(
            c: []u8,
            tag: *[tag_length]u8,
            m: []const u8,
            ad: []const u8,
            npub: [npub_length]u8,
            nsec: [nsec_length]u8,
            key: [key_length]u8,
            tbc_key: [tbc_key_length]u8,
            axu_key: [axu_key_length]u8,
        ) void {
            var p: [block_length]u8 = undefined;
            @memcpy(p[0..nsec_length], &nsec);
            @memcpy(p[nsec_length..][0..m.len], m);
            const p_len = nsec_length + m.len;

            const inner_tag = DoubleHash.hash(axu_key, "\x04", p[0..p_len]);
            const xor_tag = ixor(ad, &inner_tag);
            tag.* = SpongePrf.prf(tag_length, key, &.{ "\x05", &npub, &xor_tag });

            var pad: [block_length]u8 = undefined;
            @memcpy(pad[0..tag_length], tag);
            @memset(pad[tag_length..], 0);
            const enc_pad = OctTbc.encrypt(tbc_key, .{ .np = npub, .tag_tweak = .dollar }, pad);

            for (0..p_len) |i| {
                c[i] = p[i] ^ enc_pad[i];
            }
        }

        fn decryptTiny(
            m: []u8,
            nsec: *[nsec_length]u8,
            c: []const u8,
            tag: [tag_length]u8,
            ad: []const u8,
            npub: [npub_length]u8,
            key: [key_length]u8,
            tbc_key: [tbc_key_length]u8,
            axu_key: [axu_key_length]u8,
        ) AuthenticationError!void {
            var pad: [block_length]u8 = undefined;
            @memcpy(pad[0..tag_length], &tag);
            @memset(pad[tag_length..], 0);
            const enc_pad = OctTbc.encrypt(tbc_key, .{ .np = npub, .tag_tweak = .dollar }, pad);

            var p: [block_length]u8 = undefined;
            const p_len = c.len;
            for (0..p_len) |i| {
                p[i] = c[i] ^ enc_pad[i];
            }

            @memcpy(nsec, p[0..nsec_length]);
            @memcpy(m, p[nsec_length..][0..m.len]);

            const inner_tag = DoubleHash.hash(axu_key, "\x04", p[0..p_len]);
            const xor_tag = ixor(ad, &inner_tag);
            const expected_tag = SpongePrf.prf(tag_length, key, &.{ "\x05", &npub, &xor_tag });

            if (!crypto.timing_safe.eql([tag_length]u8, tag, expected_tag)) {
                @memset(nsec, undefined);
                @memset(m, undefined);
                return error.AuthenticationFailed;
            }
        }

        fn encryptCore(
            c: []u8,
            tag: *[tag_length]u8,
            m: []const u8,
            ad: []const u8,
            npub: [npub_length]u8,
            nsec: [nsec_length]u8,
            key: [key_length]u8,
            tbc_key: [tbc_key_length]u8,
            axu_key: [axu_key_length]u8,
        ) void {
            const ThetaCxImpl = ThetaCx(@This(), OctTbc, DoubleHash);
            const inner_tag = ThetaCxImpl.encrypt(c, m, npub, nsec, tbc_key, axu_key);
            const xor_tag = ixor(ad, &inner_tag);
            tag.* = SpongePrf.prf(tag_length, key, &.{ "\x02", &npub, &xor_tag });
        }

        fn decryptCore(
            m: []u8,
            nsec: *[nsec_length]u8,
            c: []const u8,
            tag: [tag_length]u8,
            ad: []const u8,
            npub: [npub_length]u8,
            key: [key_length]u8,
            tbc_key: [tbc_key_length]u8,
            axu_key: [axu_key_length]u8,
        ) AuthenticationError!void {
            const ThetaCxImpl = ThetaCx(@This(), OctTbc, DoubleHash);
            const inner_tag = ThetaCxImpl.decrypt(m, nsec, c, npub, tbc_key, axu_key);
            const xor_tag = ixor(ad, &inner_tag);
            const expected_tag = SpongePrf.prf(tag_length, key, &.{ "\x02", &npub, &xor_tag });

            if (!crypto.timing_safe.eql([tag_length]u8, tag, expected_tag)) {
                @memset(nsec, undefined);
                @memset(m, undefined);
                return error.AuthenticationFailed;
            }
        }
    };
}

fn ixor(a: []const u8, t: *const [32]u8) [32]u8 {
    const ell = @max(a.len + 1, t.len);
    var result: [32]u8 = undefined;

    var a_padded: [32]u8 = undefined;
    @memset(&a_padded, 0);
    if (a.len < 32) {
        @memcpy(a_padded[0..a.len], a);
        a_padded[a.len] = 0x80;
    } else {
        @memcpy(&a_padded, a[0..32]);
    }

    var t_padded: [32]u8 = undefined;
    @memcpy(&t_padded, t);

    for (0..ell) |i| {
        if (i < 32) {
            result[i] = a_padded[i] ^ t_padded[i];
        }
    }

    return result;
}

fn ThetaCx(comptime OchType: type, comptime OctType: type, comptime HashType: type) type {
    return struct {
        const inner_tag_length = HashType.mac_length;

        fn encrypt(
            c: []u8,
            m: []const u8,
            npub: [OchType.npub_length]u8,
            nsec: [OchType.nsec_length]u8,
            tbc_key: [OchType.block_length]u8,
            axu_key: [OchType.block_length]u8,
        ) [inner_tag_length]u8 {
            const kappa = OchType.kappa / 8;
            var checksum: [OchType.block_length]u8 = undefined;
            @memset(&checksum, 0);

            var p1: [OchType.block_length]u8 = undefined;
            @memcpy(p1[0..OchType.nsec_length], &nsec);
            const first_msg_bytes = @min(m.len, OchType.block_length - OchType.nsec_length);
            @memcpy(p1[OchType.nsec_length..][0..first_msg_bytes], m[0..first_msg_bytes]);
            if (first_msg_bytes < OchType.block_length - OchType.nsec_length) {
                @memset(p1[OchType.nsec_length + first_msg_bytes ..], 0);
            }

            const c1 = OctType.encrypt(tbc_key, .{ .np = npub, .tag_tweak = .epsilon }, p1);
            @memcpy(c[0..OchType.block_length], &c1);

            for (0..kappa) |i| {
                checksum[i] ^= p1[i];
            }

            const m_offset: usize = first_msg_bytes;
            const c_offset: usize = OchType.block_length;
            var block_idx: usize = 2;
            const full_msg = m[m_offset..];

            const full_blocks = full_msg.len / OchType.block_length;
            for (0..full_blocks) |bi| {
                const block_start = bi * OchType.block_length;
                var pi: [OchType.block_length]u8 = undefined;
                @memcpy(&pi, full_msg[block_start..][0..OchType.block_length]);

                const ci = OctType.encrypt(tbc_key, .{
                    .np = npub,
                    .ns = nsec,
                    .block_idx = block_idx,
                    .tag_tweak = .epsilon,
                }, pi);
                @memcpy(c[c_offset + block_start ..][0..OchType.block_length], &ci);

                for (0..kappa) |i| {
                    checksum[i] ^= pi[i];
                }
                block_idx += 1;
            }

            const remaining = full_msg.len % OchType.block_length;
            if (remaining > 0) {
                const partial_start = full_blocks * OchType.block_length;
                const pad = OctType.encrypt(tbc_key, .{
                    .np = npub,
                    .ns = nsec,
                    .block_idx = block_idx,
                    .tag_tweak = .star,
                }, @as([OchType.block_length]u8, @splat(0)));

                for (0..remaining) |i| {
                    c[c_offset + partial_start + i] = full_msg[partial_start + i] ^ pad[i];
                }

                const chk_len = @max(kappa, remaining);
                for (0..chk_len) |i| {
                    if (i < remaining) {
                        checksum[i] ^= full_msg[partial_start + i];
                    }
                }
            }

            const mlen: u64 = @intCast(m.len);
            var mlen_bytes: [8]u8 = undefined;
            mem.writeInt(u64, &mlen_bytes, mlen, .big);

            return HashType.hash(axu_key, "\x06", &(nsec ++ checksum[0..16].* ++ mlen_bytes));
        }

        fn decrypt(
            m: []u8,
            nsec: *[OchType.nsec_length]u8,
            c: []const u8,
            npub: [OchType.npub_length]u8,
            tbc_key: [OchType.block_length]u8,
            axu_key: [OchType.block_length]u8,
        ) [inner_tag_length]u8 {
            const kappa = OchType.kappa / 8;
            var checksum: [OchType.block_length]u8 = undefined;
            @memset(&checksum, 0);

            var c1: [OchType.block_length]u8 = undefined;
            @memcpy(&c1, c[0..OchType.block_length]);

            const p1 = OctType.decrypt(tbc_key, .{ .np = npub, .tag_tweak = .epsilon }, c1);
            @memcpy(nsec, p1[0..OchType.nsec_length]);

            const first_msg_bytes = @min(m.len, OchType.block_length - OchType.nsec_length);
            @memcpy(m[0..first_msg_bytes], p1[OchType.nsec_length..][0..first_msg_bytes]);

            for (0..kappa) |i| {
                checksum[i] ^= p1[i];
            }

            const m_offset: usize = first_msg_bytes;
            var block_idx: usize = 2;
            const full_c = c[OchType.block_length..];

            const full_blocks = full_c.len / OchType.block_length;
            for (0..full_blocks) |bi| {
                const block_start = bi * OchType.block_length;
                var ci: [OchType.block_length]u8 = undefined;
                @memcpy(&ci, full_c[block_start..][0..OchType.block_length]);

                const pi = OctType.decrypt(tbc_key, .{
                    .np = npub,
                    .ns = nsec.*,
                    .block_idx = block_idx,
                    .tag_tweak = .epsilon,
                }, ci);
                @memcpy(m[m_offset + block_start ..][0..OchType.block_length], &pi);

                for (0..kappa) |i| {
                    checksum[i] ^= pi[i];
                }
                block_idx += 1;
            }

            const remaining = full_c.len % OchType.block_length;
            if (remaining > 0) {
                const partial_start = full_blocks * OchType.block_length;
                const pad = OctType.encrypt(tbc_key, .{
                    .np = npub,
                    .ns = nsec.*,
                    .block_idx = block_idx,
                    .tag_tweak = .star,
                }, @as([OchType.block_length]u8, @splat(0)));

                for (0..remaining) |i| {
                    m[m_offset + partial_start + i] = full_c[partial_start + i] ^ pad[i];
                    checksum[i] ^= m[m_offset + partial_start + i];
                }
            }

            const mlen: u64 = @intCast(m.len);
            var mlen_bytes: [8]u8 = undefined;
            mem.writeInt(u64, &mlen_bytes, mlen, .big);

            return HashType.hash(axu_key, "\x06", &(nsec.* ++ checksum[0..16].* ++ mlen_bytes));
        }
    };
}

fn Oct(comptime Permutation: type, comptime OchType: type) type {
    return struct {
        const TagTweak = enum { epsilon, star, dollar };

        const Tweak = union(enum) {
            np_only: struct {
                np: [OchType.npub_length]u8,
                tag_tweak: TagTweak,
            },
            full: struct {
                np: [OchType.npub_length]u8,
                ns: [OchType.nsec_length]u8,
                block_idx: usize,
                tag_tweak: TagTweak,
            },

            fn init(args: anytype) Tweak {
                if (@hasField(@TypeOf(args), "block_idx")) {
                    return .{ .full = .{
                        .np = args.np,
                        .ns = args.ns,
                        .block_idx = args.block_idx,
                        .tag_tweak = args.tag_tweak,
                    } };
                } else {
                    return .{ .np_only = .{
                        .np = args.np,
                        .tag_tweak = args.tag_tweak,
                    } };
                }
            }
        };

        fn computeOffset(key: [OchType.block_length]u8, tweak: Tweak) [OchType.block_length]u8 {
            switch (tweak) {
                .np_only => |t| {
                    var x: [OchType.block_length]u8 = undefined;
                    @memcpy(x[0..OchType.npub_length], &t.np);
                    @memset(x[OchType.npub_length..], 0);

                    const tag_byte: u8 = switch (t.tag_tweak) {
                        .epsilon => 0b00,
                        .star => 0b01,
                        .dollar => 0b10,
                    };
                    x[30] = tag_byte;

                    const stretched = stretchAndShift(key, 0);
                    return xorBytes(stretched, x);
                },
                .full => |t| {
                    var x: [OchType.block_length]u8 = undefined;
                    @memcpy(x[0..OchType.npub_length], &t.np);
                    @memcpy(x[OchType.npub_length..][0 .. OchType.nsec_length - 2], t.ns[0 .. OchType.nsec_length - 2]);
                    x[30] = (t.ns[OchType.nsec_length - 2] & 0xFC) | 0b01;
                    x[31] = 0;

                    const gray = grayCode(@intCast(t.block_idx));
                    var k_top = stretchAndShift(key, @intCast(gray & 0x3F));

                    var l: [16]u8 = key[0..16].*;
                    for (0..64) |i| {
                        if ((gray >> @intCast(i)) & 1 == 1) {
                            const contribution = gfMul(l, @as(u8, 1) << @intCast(i % 8));
                            for (0..16) |j| {
                                k_top[j] ^= contribution[j];
                            }
                        }
                        l = gfDouble(l);
                    }

                    var result: [OchType.block_length]u8 = undefined;
                    for (0..OchType.block_length) |j| {
                        result[j] = k_top[j % 16] ^ x[j];
                    }
                    return result;
                },
            }
        }

        fn xorBytes(a: [OchType.block_length]u8, b: [OchType.block_length]u8) [OchType.block_length]u8 {
            var result: [OchType.block_length]u8 = undefined;
            for (0..OchType.block_length) |i| {
                result[i] = a[i] ^ b[i];
            }
            return result;
        }

        pub fn encrypt(key: [OchType.block_length]u8, tweak_args: anytype, input: [OchType.block_length]u8) [OchType.block_length]u8 {
            const tweak = Tweak.init(tweak_args);
            const delta = computeOffset(key, tweak);

            var xored: [OchType.block_length]u8 = undefined;
            for (0..OchType.block_length) |i| {
                xored[i] = input[i] ^ delta[i];
            }

            var state = Permutation.fromBytes(xored);
            state.permute();
            const permuted = state.toBytes();

            var result: [OchType.block_length]u8 = undefined;
            for (0..OchType.block_length) |i| {
                result[i] = permuted[i] ^ delta[i];
            }
            return result;
        }

        pub fn decrypt(key: [OchType.block_length]u8, tweak_args: anytype, input: [OchType.block_length]u8) [OchType.block_length]u8 {
            const tweak = Tweak.init(tweak_args);
            const delta = computeOffset(key, tweak);

            var xored: [OchType.block_length]u8 = undefined;
            for (0..OchType.block_length) |i| {
                xored[i] = input[i] ^ delta[i];
            }

            var state = Permutation.fromBytes(xored);
            state.inversePermute();
            const permuted = state.toBytes();

            var result: [OchType.block_length]u8 = undefined;
            for (0..OchType.block_length) |i| {
                result[i] = permuted[i] ^ delta[i];
            }
            return result;
        }

        fn gfMul(a: [16]u8, b: u8) [16]u8 {
            var result: [16]u8 = @splat(0);
            var acc: [16]u8 = a;

            var scalar = b;
            while (scalar != 0) : (scalar >>= 1) {
                if (scalar & 1 != 0) {
                    for (0..16) |i| {
                        result[i] ^= acc[i];
                    }
                }
                acc = gfDouble(acc);
            }
            return result;
        }

        fn gfDouble(a: [16]u8) [16]u8 {
            const poly: u128 = 0x87;
            var val = mem.readInt(u128, &a, .little);
            const msb = val >> 127;
            val = (val << 1) ^ (msb * poly);
            var result: [16]u8 = undefined;
            mem.writeInt(u128, &result, val, .little);
            return result;
        }

        fn grayCode(i: u64) u64 {
            return i ^ (i >> 1);
        }

        fn stretchAndShift(k_top: [32]u8, bottom: u6) [32]u8 {
            const tk: [16]u8 = k_top[0..16].*;
            var kt_str: [32]u8 = undefined;
            @memcpy(kt_str[0..16], &tk);

            var shifted: [16]u8 = undefined;
            for (0..16) |i| {
                const shift_amt: u4 = @intCast(i);
                shifted[i] = tk[i] ^ (if (shift_amt < 16) tk[(i + 3) % 16] else 0);
            }
            @memcpy(kt_str[16..], &shifted);

            var result: [32]u8 = undefined;
            const shift: u5 = @intCast(bottom % 32);
            for (0..32) |i| {
                result[i] = kt_str[(i + shift) % 32];
            }
            return result;
        }
    };
}

fn Sponge(comptime Permutation: type) type {
    return struct {
        const rate = 32;

        pub fn prf(comptime out_len: usize, key: [32]u8, inputs: anytype) [out_len]u8 {
            var state = Permutation{};

            var first_block: [rate]u8 = undefined;
            @memcpy(first_block[0..32], &key);

            state.absorb(first_block);
            state.permute();

            var buffer: [rate]u8 = undefined;
            var buf_len: usize = 0;

            inline for (inputs) |input| {
                const data: []const u8 = input;
                var offset: usize = 0;

                while (offset < data.len) {
                    const space = rate - buf_len;
                    const to_copy = @min(space, data.len - offset);
                    @memcpy(buffer[buf_len..][0..to_copy], data[offset..][0..to_copy]);
                    buf_len += to_copy;
                    offset += to_copy;

                    if (buf_len == rate) {
                        state.absorb(buffer);
                        state.permute();
                        buf_len = 0;
                    }
                }
            }

            if (buf_len > 0) {
                @memset(buffer[buf_len..], 0);
                buffer[buf_len] = 0x80;
                state.absorb(buffer);
                state.permute();
            } else {
                @memset(&buffer, 0);
                buffer[0] = 0x80;
                state.absorb(buffer);
                state.permute();
            }

            var output: [out_len]u8 = undefined;
            var output_offset: usize = 0;

            while (output_offset < out_len) {
                const squeezed = state.squeeze();
                const to_copy = @min(rate, out_len - output_offset);
                @memcpy(output[output_offset..][0..to_copy], squeezed[0..to_copy]);
                output_offset += to_copy;

                if (output_offset < out_len) {
                    state.permute();
                }
            }

            return output;
        }
    };
}

fn DoubleUniversalHash(comptime UniversalHash: type) type {
    return struct {
        pub const key_length = UniversalHash.key_length * 2;
        pub const mac_length = UniversalHash.mac_length * 2;

        pub fn hash(key: [key_length]u8, domain: []const u8, data: []const u8) [mac_length]u8 {
            var h1 = UniversalHash.init(key[0..UniversalHash.key_length]);
            h1.update(domain);
            h1.update(data);
            var result1: [UniversalHash.mac_length]u8 = undefined;
            h1.final(&result1);

            var h2 = UniversalHash.init(key[UniversalHash.key_length..key_length]);
            h2.update(domain);
            h2.update(data);
            var result2: [UniversalHash.mac_length]u8 = undefined;
            h2.final(&result2);

            return result1 ++ result2;
        }
    };
}

const testing = std.testing;

test "AreionOCH - basic encrypt/decrypt" {
    const key: [AreionOCH.key_length]u8 = @splat(0x00);
    const npub: [AreionOCH.npub_length]u8 = @splat(0x01);
    const nsec: [AreionOCH.nsec_length]u8 = @splat(0x02);
    const m = "Hello, World!";
    const ad = "associated data";

    var c: [m.len + AreionOCH.nsec_length]u8 = undefined;
    var tag: [AreionOCH.tag_length]u8 = undefined;

    AreionOCH.encrypt(&c, &tag, m, ad, npub, nsec, key);

    var m2: [m.len]u8 = undefined;
    var recovered_nsec: [AreionOCH.nsec_length]u8 = undefined;
    try AreionOCH.decrypt(&m2, &recovered_nsec, &c, tag, ad, npub, key);

    try testing.expectEqualSlices(u8, m, &m2);
    try testing.expectEqualSlices(u8, &nsec, &recovered_nsec);
}

test "AreionOCH - authentication failure" {
    const key: [AreionOCH.key_length]u8 = @splat(0x00);
    const npub: [AreionOCH.npub_length]u8 = @splat(0x01);
    const nsec: [AreionOCH.nsec_length]u8 = @splat(0x02);
    const m = "Hello, World!";
    const ad = "associated data";

    var c: [m.len + AreionOCH.nsec_length]u8 = undefined;
    var tag: [AreionOCH.tag_length]u8 = undefined;

    AreionOCH.encrypt(&c, &tag, m, ad, npub, nsec, key);

    tag[0] ^= 1;

    var m2: [m.len]u8 = undefined;
    var recovered_nsec: [AreionOCH.nsec_length]u8 = undefined;
    try testing.expectError(error.AuthenticationFailed, AreionOCH.decrypt(&m2, &recovered_nsec, &c, tag, ad, npub, key));
}

test "AreionOCH - empty message" {
    const key: [AreionOCH.key_length]u8 = @splat(0x00);
    const npub: [AreionOCH.npub_length]u8 = @splat(0x01);
    const nsec: [AreionOCH.nsec_length]u8 = @splat(0x02);
    const m = "";
    const ad = "";

    var c: [AreionOCH.nsec_length]u8 = undefined;
    var tag: [AreionOCH.tag_length]u8 = undefined;

    AreionOCH.encrypt(&c, &tag, m, ad, npub, nsec, key);

    var m2: [0]u8 = undefined;
    var recovered_nsec: [AreionOCH.nsec_length]u8 = undefined;
    try AreionOCH.decrypt(&m2, &recovered_nsec, &c, tag, ad, npub, key);

    try testing.expectEqualSlices(u8, &nsec, &recovered_nsec);
}

test "AreionOCH - long message" {
    const key: [AreionOCH.key_length]u8 = @splat(0xAB);
    const npub: [AreionOCH.npub_length]u8 = @splat(0xCD);
    const nsec: [AreionOCH.nsec_length]u8 = @splat(0xEF);
    const m: [256]u8 = @splat(0x42);
    const ad: [64]u8 = @splat(0x13);

    var c: [256 + AreionOCH.nsec_length]u8 = undefined;
    var tag: [AreionOCH.tag_length]u8 = undefined;

    AreionOCH.encrypt(&c, &tag, &m, &ad, npub, nsec, key);

    var m2: [256]u8 = undefined;
    var recovered_nsec: [AreionOCH.nsec_length]u8 = undefined;
    try AreionOCH.decrypt(&m2, &recovered_nsec, &c, tag, &ad, npub, key);

    try testing.expectEqualSlices(u8, &m, &m2);
    try testing.expectEqualSlices(u8, &nsec, &recovered_nsec);
}

test "Oct - encrypt/decrypt roundtrip" {
    const OctImpl = Oct(root.Areion256, AreionOCH);
    const key: [AreionOCH.block_length]u8 = @splat(0x00);
    const npub: [AreionOCH.npub_length]u8 = @splat(0x01);
    const input: [AreionOCH.block_length]u8 = @splat(0x42);

    const encrypted = OctImpl.encrypt(key, .{ .np = npub, .tag_tweak = .epsilon }, input);
    const decrypted = OctImpl.decrypt(key, .{ .np = npub, .tag_tweak = .epsilon }, encrypted);

    try testing.expectEqualSlices(u8, &input, &decrypted);
}

test "Sponge - prf deterministic" {
    const SpongePrf = Sponge(root.Areion512);
    const key: [32]u8 = @splat(0xAB);
    const result1 = SpongePrf.prf(32, key, &.{ "\x01", "test" });
    const result2 = SpongePrf.prf(32, key, &.{ "\x01", "test" });

    try testing.expectEqualSlices(u8, &result1, &result2);
}

test "DoubleUniversalHash - deterministic" {
    const DoubleHash = DoubleUniversalHash(crypto.onetimeauth.Polyval);
    const key: [DoubleHash.key_length]u8 = @splat(0x00);
    const data = "test data";

    const result1 = DoubleHash.hash(key, "\x01", data);
    const result2 = DoubleHash.hash(key, "\x01", data);

    try testing.expectEqualSlices(u8, &result1, &result2);
}
