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

pub const AreionOCH = OchS(root.Areion512, root.Areion256, crypto.onetimeauth.Polyval);
pub const AreionOCH_P = OchP(root.Areion512, root.Areion256, crypto.onetimeauth.Polyval);

pub fn OchS(comptime SpongePermutation: type, comptime TbcPermutation: type, comptime UniversalHash: type) type {
    return OchGeneric(SpongePermutation, TbcPermutation, UniversalHash, 0, 32);
}

pub fn OchP(comptime SpongePermutation: type, comptime TbcPermutation: type, comptime UniversalHash: type) type {
    return OchGeneric(SpongePermutation, TbcPermutation, UniversalHash, 32, 0);
}

pub fn OchGeneric(
    comptime SpongePermutation: type,
    comptime TbcPermutation: type,
    comptime UniversalHash: type,
    comptime npub_len: u8,
    comptime nsec_len: u8,
) type {
    return struct {
        pub const key_length = 32;
        pub const npub_length = npub_len;
        pub const nsec_length = nsec_len;
        pub const nonce_length: u8 = npub_length + nsec_length;
        pub const tag_length = 32;
        pub const block_length = 32;

        const kappa: usize = 16;

        const SpongePrf = Sponge(SpongePermutation);
        const OctTbc = Oct(TbcPermutation);
        const DoubleHash = DoubleUniversalHash(UniversalHash);

        const label_kg_tbc: u8 = 0xf0;
        const label_kg_axu: u8 = 0xf1;
        const label_tiny: u8 = 0xf2;
        const label_core_no_partial: u8 = 0xf3;
        const label_core_with_partial: u8 = 0xf4;

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

            const tbc_key = SpongePrf.prf(32, key, &.{&[_]u8{label_kg_tbc}});
            const axu_key = SpongePrf.prf(DoubleHash.key_length, key, &.{&[_]u8{label_kg_axu}});

            var oct_state = OctTbc.setup(tbc_key);

            if (m.len + nsec_length < block_length) {
                encryptTiny(c, tag, m, ad, npub, nsec, key, &oct_state, axu_key);
            } else {
                encryptCore(c, tag, m, ad, npub, nsec, key, &oct_state, axu_key);
            }
        }

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

            const tbc_key = SpongePrf.prf(32, key, &.{&[_]u8{label_kg_tbc}});
            const axu_key = SpongePrf.prf(DoubleHash.key_length, key, &.{&[_]u8{label_kg_axu}});

            var oct_state = OctTbc.setup(tbc_key);

            if (c.len < block_length) {
                return decryptTiny(m, nsec, c, tag, ad, npub, key, &oct_state, axu_key);
            } else {
                return decryptCore(m, nsec, c, tag, ad, npub, key, &oct_state, axu_key);
            }
        }

        fn makeN0(npub: [npub_length]u8) [32]u8 {
            var n0: [32]u8 = @splat(0);
            if (npub_length > 0) {
                @memcpy(n0[0..npub_length], &npub);
            }
            return n0;
        }

        fn makeN(npub: [npub_length]u8, nsec: [nsec_length]u8) [32]u8 {
            var n: [32]u8 = @splat(0);
            if (npub_length > 0) {
                @memcpy(n[0..npub_length], &npub);
            }
            if (nsec_length > 0) {
                @memcpy(n[npub_length..][0..nsec_length], &nsec);
            }
            return n;
        }

        fn encryptTiny(
            c: []u8,
            tag: *[tag_length]u8,
            m: []const u8,
            ad: []const u8,
            npub: [npub_length]u8,
            _: [nsec_length]u8,
            key: [key_length]u8,
            oct_state: *OctTbc.State,
            axu_key: [DoubleHash.key_length]u8,
        ) void {
            debug.assert(nsec_length == 0); // tiny only supported for OCH-P
            const p_len = m.len;
            debug.assert(p_len < block_length);

            var axu_in: [32]u8 = @splat(0);
            @memcpy(axu_in[0..p_len], m[0..p_len]);
            axu_in[p_len] = label_tiny;

            const inner_tag = DoubleHash.hash(axu_key, &axu_in);

            tag.* = xthTag(key, &inner_tag, ad, &npub);

            const n0 = makeN0(npub);
            var n0_offset = oct_state.initOffset(n0);
            xor256(&n0_offset, &oct_state.l[ntz(1)]);
            xor256(&n0_offset, &oct_state.l_star);

            var pad = tag.*;
            OctTbc.emEncrypt(&n0_offset, &pad);

            for (0..p_len) |i| {
                c[i] = m[i] ^ pad[i];
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
            oct_state: *OctTbc.State,
            axu_key: [DoubleHash.key_length]u8,
        ) AuthenticationError!void {
            _ = nsec;
            debug.assert(nsec_length == 0);
            const p_len = c.len;
            debug.assert(p_len < block_length);

            const n0 = makeN0(npub);
            var n0_offset = oct_state.initOffset(n0);
            xor256(&n0_offset, &oct_state.l[ntz(1)]);
            xor256(&n0_offset, &oct_state.l_star);

            var pad = tag;
            OctTbc.emEncrypt(&n0_offset, &pad);

            var p: [block_length]u8 = @splat(0);
            for (0..p_len) |i| {
                p[i] = c[i] ^ pad[i];
            }
            @memcpy(m[0..p_len], p[0..p_len]);

            var axu_in: [32]u8 = @splat(0);
            @memcpy(axu_in[0..p_len], p[0..p_len]);
            axu_in[p_len] = label_tiny;

            const inner_tag = DoubleHash.hash(axu_key, &axu_in);
            const expected_tag = xthTag(key, &inner_tag, ad, &npub);

            if (!crypto.timing_safe.eql([tag_length]u8, tag, expected_tag)) {
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
            oct_state: *OctTbc.State,
            axu_key: [DoubleHash.key_length]u8,
        ) void {
            const n0 = makeN0(npub);
            var n0_offset = oct_state.initOffset(n0);

            var checksum: [kappa]u8 = @splat(0);

            // First block: contains secret nonce (if any) + message start
            var p1: [block_length]u8 = @splat(0);
            var msg_idx: usize = 0;
            var ct_idx: usize = 0;
            var i: usize = 1;

            if (nsec_length > 0) {
                @memcpy(p1[0..nsec_length], &nsec);
                const fill = @min(m.len, block_length - nsec_length);
                @memcpy(p1[nsec_length..][0..fill], m[0..fill]);
                msg_idx = fill;
            } else {
                debug.assert(m.len >= block_length);
                @memcpy(&p1, m[0..block_length]);
                msg_idx = block_length;
            }

            for (0..kappa) |j| {
                checksum[j] ^= p1[j];
            }

            xor256(&n0_offset, &oct_state.l[ntz(i)]);
            var c1 = p1;
            OctTbc.emEncrypt(&n0_offset, &c1);
            i += 1;

            const n = makeN(npub, nsec);
            var n_offset = oct_state.initOffset(n);
            xor256(&n_offset, &oct_state.l[ntz(1)]);

            while (msg_idx + block_length <= m.len) {
                var pi: [block_length]u8 = undefined;
                @memcpy(&pi, m[msg_idx..][0..block_length]);

                @memcpy(c[ct_idx..][0..block_length], &c1);
                ct_idx += block_length;

                for (0..kappa) |j| {
                    checksum[j] ^= pi[j];
                }

                xor256(&n_offset, &oct_state.l[ntz(i)]);
                c1 = pi;
                OctTbc.emEncrypt(&n_offset, &c1);

                msg_idx += block_length;
                i += 1;
            }

            const remaining = m.len - msg_idx;

            if (remaining == 0) {
                @memcpy(c[ct_idx..][0..block_length], &c1);

                const inner_tag = computeTagNoPartial(axu_key, &nsec, &checksum, m.len);
                tag.* = xthTag(key, &inner_tag, ad, &npub);
            } else {
                @memcpy(c[ct_idx..][0..block_length], &c1);
                ct_idx += block_length;

                var extended_checksum: [block_length]u8 = @splat(0);
                @memcpy(extended_checksum[0..kappa], &checksum);
                const extended_checksum_len = if (remaining > kappa) remaining else kappa;

                xor256(&n_offset, &oct_state.l_star);
                var pad: [block_length]u8 = @splat(0);
                OctTbc.emEncrypt(&n_offset, &pad);

                for (0..remaining) |j| {
                    extended_checksum[j] ^= m[msg_idx + j];
                    c[ct_idx + j] = pad[j] ^ m[msg_idx + j];
                }

                const inner_tag = computeTagWithPartial(axu_key, &nsec, &extended_checksum, extended_checksum_len, m.len);
                tag.* = xthTag(key, &inner_tag, ad, &npub);
            }
        }

        fn decryptCore(
            m: []u8,
            nsec: *[nsec_length]u8,
            c: []const u8,
            tag: [tag_length]u8,
            ad: []const u8,
            npub: [npub_length]u8,
            key: [key_length]u8,
            oct_state: *OctTbc.State,
            axu_key: [DoubleHash.key_length]u8,
        ) AuthenticationError!void {
            const n0 = makeN0(npub);
            var n0_offset = oct_state.initOffset(n0);

            var checksum: [kappa]u8 = @splat(0);

            var ct_idx: usize = 0;
            var msg_idx: usize = 0;
            var i: usize = 1;

            var c1: [block_length]u8 = undefined;
            @memcpy(&c1, c[0..block_length]);
            ct_idx += block_length;

            xor256(&n0_offset, &oct_state.l[ntz(i)]);
            var p1 = c1;
            OctTbc.emDecrypt(&n0_offset, &p1);
            i += 1;

            for (0..kappa) |j| {
                checksum[j] ^= p1[j];
            }

            if (nsec_length > 0) {
                @memcpy(nsec, p1[0..nsec_length]);
                const fill = @min(m.len, block_length - nsec_length);
                @memcpy(m[0..fill], p1[nsec_length..][0..fill]);
                msg_idx = fill;
            } else {
                @memcpy(m[0..block_length], &p1);
                msg_idx = block_length;
            }

            const n = makeN(npub, nsec.*);
            var n_offset = oct_state.initOffset(n);
            xor256(&n_offset, &oct_state.l[ntz(1)]);

            while (ct_idx + block_length <= c.len) {
                var ci: [block_length]u8 = undefined;
                @memcpy(&ci, c[ct_idx..][0..block_length]);

                xor256(&n_offset, &oct_state.l[ntz(i)]);
                var pi = ci;
                OctTbc.emDecrypt(&n_offset, &pi);

                for (0..kappa) |j| {
                    checksum[j] ^= pi[j];
                }

                @memcpy(m[msg_idx..][0..block_length], &pi);
                ct_idx += block_length;
                msg_idx += block_length;
                i += 1;
            }

            const remaining = c.len - ct_idx;

            var inner_tag: [DoubleHash.mac_length]u8 = undefined;
            if (remaining == 0) {
                inner_tag = computeTagNoPartial(axu_key, nsec, &checksum, m.len);
            } else {
                var extended_checksum: [block_length]u8 = @splat(0);
                @memcpy(extended_checksum[0..kappa], &checksum);
                const extended_checksum_len = if (remaining > kappa) remaining else kappa;

                xor256(&n_offset, &oct_state.l_star);
                var pad: [block_length]u8 = @splat(0);
                OctTbc.emEncrypt(&n_offset, &pad);

                for (0..remaining) |j| {
                    m[msg_idx + j] = pad[j] ^ c[ct_idx + j];
                    extended_checksum[j] ^= m[msg_idx + j];
                }

                inner_tag = computeTagWithPartial(axu_key, nsec, &extended_checksum, extended_checksum_len, m.len);
            }

            const expected_tag = xthTag(key, &inner_tag, ad, &npub);

            if (!crypto.timing_safe.eql([tag_length]u8, tag, expected_tag)) {
                if (nsec_length > 0) @memset(nsec, undefined);
                @memset(m, undefined);
                return error.AuthenticationFailed;
            }
        }

        fn computeTagNoPartial(
            axu_key: [DoubleHash.key_length]u8,
            nsec: *const [nsec_length]u8,
            checksum: *const [kappa]u8,
            msg_len: usize,
        ) [DoubleHash.mac_length]u8 {
            const num_blocks: u64 = @intCast(msg_len / block_length);
            const mlen: u64 = num_blocks << 1;
            const mlen_bytes = mem.toBytes(mlen); // native-endian (little on x86)

            if (nsec_length > 0) {
                // axu_in = nsec || checksum || mlen || label || 0^pad (64 bytes)
                var axu_in: [64]u8 = @splat(0);
                @memcpy(axu_in[0..nsec_length], nsec);
                @memcpy(axu_in[nsec_length..][0..kappa], checksum);
                @memcpy(axu_in[nsec_length + kappa ..][0..8], &mlen_bytes);
                axu_in[nsec_length + kappa + 8] = label_core_no_partial;
                return DoubleHash.hash(axu_key, &axu_in);
            } else {
                // axu_in = checksum || mlen || label || 0^pad (32 bytes)
                var axu_in: [32]u8 = @splat(0);
                @memcpy(axu_in[0..kappa], checksum);
                @memcpy(axu_in[kappa..][0..8], &mlen_bytes);
                axu_in[kappa + 8] = label_core_no_partial;
                return DoubleHash.hash(axu_key, &axu_in);
            }
        }

        fn computeTagWithPartial(
            axu_key: [DoubleHash.key_length]u8,
            nsec: *const [nsec_length]u8,
            extended_checksum: *const [block_length]u8,
            extended_checksum_len: usize,
            msg_len: usize,
        ) [DoubleHash.mac_length]u8 {
            const num_blocks: u64 = @intCast(msg_len / block_length);
            const mlen: u64 = (num_blocks << 1) | 1;
            const mlen_bytes = mem.toBytes(mlen);

            if (nsec_length > 0) {
                // axu_in = nsec || extended_checksum || mlen || label || 0^pad (80 bytes)
                var axu_in: [80]u8 = @splat(0);
                @memcpy(axu_in[0..nsec_length], nsec);
                @memcpy(axu_in[nsec_length..][0..extended_checksum_len], extended_checksum[0..extended_checksum_len]);
                @memcpy(axu_in[nsec_length + extended_checksum_len ..][0..8], &mlen_bytes);
                axu_in[nsec_length + extended_checksum_len + 8] = label_core_with_partial;
                return DoubleHash.hash(axu_key, &axu_in);
            } else {
                // axu_in = extended_checksum || mlen || label || 0^pad (48 bytes)
                var axu_in: [48]u8 = @splat(0);
                @memcpy(axu_in[0..extended_checksum_len], extended_checksum[0..extended_checksum_len]);
                @memcpy(axu_in[extended_checksum_len..][0..8], &mlen_bytes);
                axu_in[extended_checksum_len + 8] = label_core_with_partial;
                return DoubleHash.hash(axu_key, &axu_in);
            }
        }

        fn xthTag(
            key: [key_length]u8,
            inner_tag: *const [DoubleHash.mac_length]u8,
            ad: []const u8,
            npub: *const [npub_length]u8,
        ) [tag_length]u8 {
            // XtH: prf(key, ixor(inner_tag, ad) || nonce)
            if (ad.len < DoubleHash.mac_length) {
                var sponge_in: [DoubleHash.mac_length]u8 = @splat(0);
                for (0..ad.len) |j| {
                    sponge_in[j] = inner_tag[j] ^ ad[j];
                }
                sponge_in[ad.len] ^= 0xff;
                if (npub_length > 0) {
                    return SpongePrf.prf(tag_length, key, &.{ &sponge_in, npub });
                } else {
                    return SpongePrf.prf(tag_length, key, &.{&sponge_in});
                }
            } else {
                var sponge_in: [DoubleHash.mac_length]u8 = undefined;
                for (0..DoubleHash.mac_length) |j| {
                    sponge_in[j] = inner_tag[j] ^ ad[j];
                }
                if (ad.len > DoubleHash.mac_length) {
                    if (npub_length > 0) {
                        return SpongePrf.prf(tag_length, key, &.{ &sponge_in, ad[DoubleHash.mac_length..], npub });
                    } else {
                        return SpongePrf.prf(tag_length, key, &.{ &sponge_in, ad[DoubleHash.mac_length..] });
                    }
                } else {
                    if (npub_length > 0) {
                        return SpongePrf.prf(tag_length, key, &.{ &sponge_in, npub });
                    } else {
                        return SpongePrf.prf(tag_length, key, &.{&sponge_in});
                    }
                }
            }
        }
    };
}

fn Oct(comptime Permutation: type) type {
    return struct {
        const L_TABLE_SIZE = 16;

        const State = struct {
            tbc_key: [32]u8,
            l_star: [32]u8,
            l_dollar: [32]u8,
            l: [L_TABLE_SIZE][32]u8,

            fn initOffset(self: *const State, nonce: [32]u8) [32]u8 {
                const bottom: u6 = @truncate(nonce[31] & 0x3F);
                var top = nonce;
                top[31] &= 0xC0;

                var k_top = top;
                emEncrypt(&self.tbc_key, &k_top);

                return shiftLeft256(k_top, bottom);
            }
        };

        fn setup(tbc_key: [32]u8) State {
            var l_star: [32]u8 = @splat(0);
            emEncrypt(&tbc_key, &l_star);

            const l_dollar = gf256Double(l_star);

            var l: [L_TABLE_SIZE][32]u8 = undefined;
            l[0] = gf256Double(l_dollar);
            for (1..L_TABLE_SIZE) |i| {
                l[i] = gf256Double(l[i - 1]);
            }

            return .{
                .tbc_key = tbc_key,
                .l_star = l_star,
                .l_dollar = l_dollar,
                .l = l,
            };
        }

        fn emEncrypt(offset: *const [32]u8, inout: *[32]u8) void {
            xor256(inout, offset);
            var state = Permutation.fromBytes(inout.*);
            state.permute();
            inout.* = state.toBytes();
            xor256(inout, offset);
        }

        fn emDecrypt(offset: *const [32]u8, inout: *[32]u8) void {
            xor256(inout, offset);
            var state = Permutation.fromBytes(inout.*);
            state.inversePermute();
            inout.* = state.toBytes();
            xor256(inout, offset);
        }
    };
}

fn xor256(a: *[32]u8, b: *const [32]u8) void {
    for (a, b) |*av, bv| {
        av.* ^= bv;
    }
}

fn ntz(x: usize) usize {
    debug.assert(x > 0);
    return @ctz(x);
}

fn gf256Double(in: [32]u8) [32]u8 {
    // GF(2^256) doubling with polynomial x^256 + x^10 + x^5 + x^2 + 1
    var be: [4]u64 = undefined;
    be[0] = mem.readInt(u64, in[0..8], .big);
    be[1] = mem.readInt(u64, in[8..16], .big);
    be[2] = mem.readInt(u64, in[16..24], .big);
    be[3] = mem.readInt(u64, in[24..32], .big);

    const mask: u64 = 1061;
    const tmp = be[0] >> 63;

    var out: [4]u64 = undefined;
    out[0] = (be[0] << 1) ^ (be[1] >> 63);
    out[1] = (be[1] << 1) ^ (be[2] >> 63);
    out[2] = (be[2] << 1) ^ (be[3] >> 63);
    out[3] = (be[3] << 1) ^ (mask & (0 -% tmp));

    var result: [32]u8 = undefined;
    mem.writeInt(u64, result[0..8], out[0], .big);
    mem.writeInt(u64, result[8..16], out[1], .big);
    mem.writeInt(u64, result[16..24], out[2], .big);
    mem.writeInt(u64, result[24..32], out[3], .big);
    return result;
}

fn shiftLeft256(a: [32]u8, value: u6) [32]u8 {
    if (value == 0) return a;

    // Little-endian u64 layout: carries propagate from u64[i+1] to u64[i]
    var le: [4]u64 = undefined;
    le[0] = mem.readInt(u64, a[0..8], .little);
    le[1] = mem.readInt(u64, a[8..16], .little);
    le[2] = mem.readInt(u64, a[16..24], .little);
    le[3] = mem.readInt(u64, a[24..32], .little);

    const shift: u6 = value;
    const inv_shift: u7 = @as(u7, 64) - @as(u7, shift);

    var out: [4]u64 = undefined;
    out[0] = (le[0] << shift) | (le[1] >> @intCast(inv_shift));
    out[1] = (le[1] << shift) | (le[2] >> @intCast(inv_shift));
    out[2] = (le[2] << shift) | (le[3] >> @intCast(inv_shift));
    out[3] = le[3] << shift;

    var result: [32]u8 = undefined;
    mem.writeInt(u64, result[0..8], out[0], .little);
    mem.writeInt(u64, result[8..16], out[1], .little);
    mem.writeInt(u64, result[16..24], out[2], .little);
    mem.writeInt(u64, result[24..32], out[3], .little);
    return result;
}

fn Sponge(comptime Permutation: type) type {
    return struct {
        const rate = 32;

        fn spongePermute(state_bytes: *[64]u8) void {
            var state = Permutation.fromBytes(state_bytes.*);
            state.permute();
            state_bytes.* = state.toBytes();
            // Undo Areion512's post-round block rotation (rotate left by 16 bytes)
            const tmp = state_bytes.*;
            @memcpy(state_bytes[0..48], tmp[16..64]);
            @memcpy(state_bytes[48..64], tmp[0..16]);
        }

        fn absorbBytes(state_bytes: *[64]u8, input: [rate]u8) void {
            for (0..rate) |i| {
                state_bytes[i] ^= input[i];
            }
        }

        pub fn prf(comptime out_len: usize, key: [32]u8, inputs: anytype) [out_len]u8 {
            var state_bytes: [64]u8 = @splat(0);
            @memcpy(state_bytes[0..32], &key);
            state_bytes[32] = 0xd0;
            spongePermute(&state_bytes);

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
                        absorbBytes(&state_bytes, buffer);
                        spongePermute(&state_bytes);
                        buf_len = 0;
                    }
                }
            }

            // Pad partial block with 0xff separator
            if (buf_len > 0) {
                @memset(buffer[buf_len..], 0);
                buffer[buf_len] = 0xff;
                absorbBytes(&state_bytes, buffer);
                spongePermute(&state_bytes);
            }

            // Squeeze: extra permute before first output
            spongePermute(&state_bytes);
            var output: [out_len]u8 = undefined;
            var output_offset: usize = 0;

            while (output_offset < out_len) {
                const to_copy = @min(rate, out_len - output_offset);
                @memcpy(output[output_offset..][0..to_copy], state_bytes[0..to_copy]);
                output_offset += to_copy;

                if (output_offset < out_len) {
                    spongePermute(&state_bytes);
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

        pub fn hash(key: [key_length]u8, data: []const u8) [mac_length]u8 {
            var h1 = UniversalHash.init(key[0..UniversalHash.key_length]);
            h1.update(data);
            var result1: [UniversalHash.mac_length]u8 = undefined;
            h1.final(&result1);

            var h2 = UniversalHash.init(key[UniversalHash.key_length..key_length]);
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
    const npub: [AreionOCH.npub_length]u8 = .{};
    const nsec: [AreionOCH.nsec_length]u8 = @splat(0x02);
    const m = "Hello, World! This is a test!!!!"; // >= 32 bytes for core path
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
    const npub: [AreionOCH.npub_length]u8 = .{};
    const nsec: [AreionOCH.nsec_length]u8 = @splat(0x02);
    const m = "Hello, World! This is a test!!!!"; // >= 32 bytes for core path
    const ad = "associated data";

    var c: [m.len + AreionOCH.nsec_length]u8 = undefined;
    var tag: [AreionOCH.tag_length]u8 = undefined;

    AreionOCH.encrypt(&c, &tag, m, ad, npub, nsec, key);

    tag[0] ^= 1;

    var m2: [m.len]u8 = undefined;
    var recovered_nsec: [AreionOCH.nsec_length]u8 = undefined;
    try testing.expectError(error.AuthenticationFailed, AreionOCH.decrypt(&m2, &recovered_nsec, &c, tag, ad, npub, key));
}

test "AreionOCH_P - basic encrypt/decrypt" {
    const key: [AreionOCH_P.key_length]u8 = @splat(0x00);
    var npub: [AreionOCH_P.npub_length]u8 = @splat(0x01);
    const nsec: [AreionOCH_P.nsec_length]u8 = .{};
    const m: [64]u8 = @splat(0x42);
    const ad = "associated data";

    var c: [m.len + AreionOCH_P.nsec_length]u8 = undefined;
    var tag: [AreionOCH_P.tag_length]u8 = undefined;

    AreionOCH_P.encrypt(&c, &tag, &m, ad, npub, nsec, key);

    var m2: [m.len]u8 = undefined;
    var recovered_nsec: [AreionOCH_P.nsec_length]u8 = undefined;
    try AreionOCH_P.decrypt(&m2, &recovered_nsec, &c, tag, ad, npub, key);

    try testing.expectEqualSlices(u8, &m, &m2);
    _ = &npub;
}

test "AreionOCH_P - tiny message" {
    const key: [AreionOCH_P.key_length]u8 = @splat(0xAB);
    const npub: [AreionOCH_P.npub_length]u8 = @splat(0xCD);
    const nsec: [AreionOCH_P.nsec_length]u8 = .{};
    const m = "short";
    const ad = "";

    var c: [m.len + AreionOCH_P.nsec_length]u8 = undefined;
    var tag: [AreionOCH_P.tag_length]u8 = undefined;

    AreionOCH_P.encrypt(&c, &tag, m, ad, npub, nsec, key);

    var m2: [m.len]u8 = undefined;
    var recovered_nsec: [AreionOCH_P.nsec_length]u8 = undefined;
    try AreionOCH_P.decrypt(&m2, &recovered_nsec, &c, tag, ad, npub, key);

    try testing.expectEqualSlices(u8, m, &m2);
}

test "AreionOCH_P - long message with partial block" {
    const key: [AreionOCH_P.key_length]u8 = @splat(0xAB);
    const npub: [AreionOCH_P.npub_length]u8 = @splat(0xCD);
    const nsec: [AreionOCH_P.nsec_length]u8 = .{};
    const m: [100]u8 = @splat(0x42); // 3 full blocks + 4 byte partial
    const ad: [64]u8 = @splat(0x13);

    var c: [100 + AreionOCH_P.nsec_length]u8 = undefined;
    var tag: [AreionOCH_P.tag_length]u8 = undefined;

    AreionOCH_P.encrypt(&c, &tag, &m, &ad, npub, nsec, key);

    var m2: [100]u8 = undefined;
    var recovered_nsec: [AreionOCH_P.nsec_length]u8 = undefined;
    try AreionOCH_P.decrypt(&m2, &recovered_nsec, &c, tag, &ad, npub, key);

    try testing.expectEqualSlices(u8, &m, &m2);
}

test "AreionOCH - long message" {
    const key: [AreionOCH.key_length]u8 = @splat(0xAB);
    const npub: [AreionOCH.npub_length]u8 = .{};
    const nsec: [AreionOCH.nsec_length]u8 = @splat(0xEF);
    const m: [256]u8 = @splat(0x42);
    const ad: [64]u8 = @splat(0x13);

    var c: [256 + @as(usize, AreionOCH.nsec_length)]u8 = undefined;
    var tag: [AreionOCH.tag_length]u8 = undefined;

    AreionOCH.encrypt(&c, &tag, &m, &ad, npub, nsec, key);

    var m2: [256]u8 = undefined;
    var recovered_nsec: [AreionOCH.nsec_length]u8 = undefined;
    try AreionOCH.decrypt(&m2, &recovered_nsec, &c, tag, &ad, npub, key);

    try testing.expectEqualSlices(u8, &m, &m2);
    try testing.expectEqualSlices(u8, &nsec, &recovered_nsec);
}

test "EM encrypt" {
    const OctImpl = Oct(root.Areion256);

    const key: [32]u8 = @splat(0x42);
    var block: [32]u8 = @splat(0);
    OctImpl.emEncrypt(&key, &block);
    try testing.expectEqualSlices(u8, &hexToBytes32("c9e12740b5ab3907dfe72c7cb5188c276b25a51f4273781b7e9ec23f857584a1"), &block);
}

test "Oct - encrypt/decrypt roundtrip" {
    const OctImpl = Oct(root.Areion256);
    const tbc_key: [32]u8 = @splat(0x42);
    var state = OctImpl.setup(tbc_key);

    const nonce: [32]u8 = @splat(0x01);
    var offset = state.initOffset(nonce);
    xor256(&offset, &state.l[ntz(1)]);

    var block: [32]u8 = @splat(0xAB);
    const original = block;
    OctImpl.emEncrypt(&offset, &block);
    OctImpl.emDecrypt(&offset, &block);

    try testing.expectEqualSlices(u8, &original, &block);
}

fn hexToBytes32(comptime hex_str: *const [64]u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex_str) catch unreachable;
    return out;
}

test "GF256 double" {
    const zero: [32]u8 = @splat(0);
    try testing.expectEqualSlices(u8, &zero, &gf256Double(zero));

    var one: [32]u8 = @splat(0);
    one[31] = 1;
    var exp_two: [32]u8 = @splat(0);
    exp_two[31] = 2;
    try testing.expectEqualSlices(u8, &exp_two, &gf256Double(one));

    var val: [32]u8 = undefined;
    for (0..32) |i| val[i] = @intCast(i + 1);
    const expected = hexToBytes32("020406080a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e40");
    try testing.expectEqualSlices(u8, &expected, &gf256Double(val));

    var msb: [32]u8 = @splat(0);
    msb[0] = 0x80;
    const exp_msb = hexToBytes32("0000000000000000000000000000000000000000000000000000000000000425");
    try testing.expectEqualSlices(u8, &exp_msb, &gf256Double(msb));
}

test "shiftLeft256" {
    var input: [32]u8 = @splat(0);
    input[31] = 1;
    const shifted = shiftLeft256(input, 1);
    var expected: [32]u8 = @splat(0);
    expected[31] = 2;
    try testing.expectEqualSlices(u8, &expected, &shifted);

    // Zero shift = identity
    const identity = shiftLeft256(input, 0);
    try testing.expectEqualSlices(u8, &input, &identity);
}

test "Sponge PRF" {
    const SpongePrf = Sponge(root.Areion512);
    const key: [32]u8 = @splat(0x42);

    const tbc_key = SpongePrf.prf(32, key, &.{"\xf0"});
    try testing.expectEqualSlices(u8, &hexToBytes32("ae7c64e0133eb4db8e2ce083b7b8f0fc2b034b97d9033e6456403b0a817331f8"), &tbc_key);

    const axu_key = SpongePrf.prf(32, key, &.{"\xf1"});
    try testing.expectEqualSlices(u8, &hexToBytes32("a315e8d68019005247f99af96d2807e36492650bbdb605b2f7b30da3ec3b45b2"), &axu_key);
}

test "DoubleUniversalHash - deterministic" {
    const DoubleHash = DoubleUniversalHash(crypto.onetimeauth.Polyval);
    const key: [DoubleHash.key_length]u8 = @splat(0x00);
    const data = "test data for hashing!!!!!!!!!!!"; // 32 bytes

    const result1 = DoubleHash.hash(key, data);
    const result2 = DoubleHash.hash(key, data);

    try testing.expectEqualSlices(u8, &result1, &result2);
}

fn hexToBytesBuf(comptime hex_str: []const u8) [hex_str.len / 2]u8 {
    var out: [hex_str.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex_str) catch unreachable;
    return out;
}

test "OCT setup" {
    const OctImpl = Oct(root.Areion256);
    const SpongePrf = Sponge(root.Areion512);
    const key: [32]u8 = @splat(0x42);

    const tbc_key = SpongePrf.prf(32, key, &.{"\xf0"});
    var state = OctImpl.setup(tbc_key);

    try testing.expectEqualSlices(u8, &hexToBytes32("e9aa12654bea8ff35c28f0c6603cd7a67a5618a8637d7586aa66c7fd7aa91809"), &state.l_star);
    try testing.expectEqualSlices(u8, &hexToBytes32("d35424ca97d51fe6b851e18cc079af4cf4ac3150c6faeb0d54cd8ffaf5523437"), &state.l_dollar);
    try testing.expectEqualSlices(u8, &hexToBytes32("a6a849952faa3fcd70a3c31980f35e99e95862a18df5d61aa99b1ff5eaa46c4b"), &state.l[0]);

    const n0: [32]u8 = @splat(0x42);
    const n0_offset = state.initOffset(n0);
    try testing.expectEqualSlices(u8, &hexToBytes32("742215b0185457ace6a63bae4848cfc9d6af780b92dd45008c40a45d8f4ef819"), &n0_offset);
}

test "OCH-P KAT 64B" {
    const key: [AreionOCH_P.key_length]u8 = @splat(0x42);
    const npub: [AreionOCH_P.npub_length]u8 = @splat(0x42);
    const nsec: [AreionOCH_P.nsec_length]u8 = .{};
    const m: [64]u8 = @splat(0x42);
    const ad: [16]u8 = @splat(0x42);

    var c: [64]u8 = undefined;
    var tag: [AreionOCH_P.tag_length]u8 = undefined;

    AreionOCH_P.encrypt(&c, &tag, &m, &ad, npub, nsec, key);

    const expected_ct = hexToBytesBuf("efc691d694b2eb8291d6968808ba65db82447ff06d3c222eadc8dded9b0d95962c3ba26da40f596c7aee3ac37ffd523b99cf33ae17d47dd05ce32556cf82e167");
    const expected_tag = hexToBytes32("f9d3fce1ec655bb4ef49b7407b3d046d65c97cf0ec8afd85d2989e809b8e9bc0");
    try testing.expectEqualSlices(u8, &expected_ct, &c);
    try testing.expectEqualSlices(u8, &expected_tag, &tag);
}

test "OCH-P KAT 5B tiny" {
    const key: [AreionOCH_P.key_length]u8 = @splat(0x42);
    const npub: [AreionOCH_P.npub_length]u8 = @splat(0x42);
    const nsec: [AreionOCH_P.nsec_length]u8 = .{};
    const m: [5]u8 = @splat(0x42);
    const ad: [0]u8 = .{};

    var c: [5]u8 = undefined;
    var tag: [AreionOCH_P.tag_length]u8 = undefined;

    AreionOCH_P.encrypt(&c, &tag, &m, &ad, npub, nsec, key);

    const expected_ct = hexToBytesBuf("1a6f0d7954");
    const expected_tag = hexToBytes32("cf3ef39e89d6b05dad34587055f6cb45001451e4f3dfc3d2f213ae59947d0fe8");
    try testing.expectEqualSlices(u8, &expected_ct, &c);
    try testing.expectEqualSlices(u8, &expected_tag, &tag);
}

test "OCH-P KAT 100B partial" {
    const key: [AreionOCH_P.key_length]u8 = @splat(0x42);
    const npub: [AreionOCH_P.npub_length]u8 = @splat(0x42);
    const nsec: [AreionOCH_P.nsec_length]u8 = .{};
    const m: [100]u8 = @splat(0x42);
    const ad: [64]u8 = @splat(0x13);

    var c: [100]u8 = undefined;
    var tag: [AreionOCH_P.tag_length]u8 = undefined;

    AreionOCH_P.encrypt(&c, &tag, &m, &ad, npub, nsec, key);

    const expected_ct = hexToBytesBuf("efc691d694b2eb8291d6968808ba65db82447ff06d3c222eadc8dded9b0d95962c3ba26da40f596c7aee3ac37ffd523b99cf33ae17d47dd05ce32556cf82e167d1d3882f04c6a60258d66ae4042788cf6f1d0ef618207515ab8b574d019a6e824cde5701");
    const expected_tag = hexToBytes32("d475545d297fafabb6de1158cea85c873927685978bc419e4e714be78fe74666");
    try testing.expectEqualSlices(u8, &expected_ct, &c);
    try testing.expectEqualSlices(u8, &expected_tag, &tag);
}
