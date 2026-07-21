# Areion

Fast Zig implementation of the [Areion](https://eprint.iacr.org/2023/794.pdf) permutation family presented at CHES 2023. This library provides both Areion512 and Areion256 variants, optimized for speed particularly on small inputs.

## Features

- **Areion512**: 512-bit permutation with 32-byte input blocks and 32-byte hash output
- **Areion256**: 256-bit permutation with 16-byte input blocks and 16-byte hash output
- **AreionOCH / AreionOCH_P**: Authenticated encryption (AEAD) using the OCH construction, with or without nonce privacy
- **Areion256Opp / Areion512Opp**: Authenticated encryption using the Offset Public Permutation (OPP) construction
- **Areion512Vec / Areion256Vec**: Vectorized permutations for parallel processing of multiple independent states
- AES-based permutation using hardware acceleration when available
- Merkle-Damgård construction with Davies-Meyer compression
- Comprehensive test vectors included

## Building

```bash
# Build the library (creates zig-out/lib/libareion.a)
zig build

# Build with optimizations
zig build --release=fast    # Optimized for performance
zig build --release=safe    # Optimized with safety checks
zig build --release=small   # Optimized for size

# Run tests
zig build test
```

## Usage

This library provides a standard hash function interface compatible with other Zig crypto libraries:

```zig
const std = @import("std");
const areion = @import("areion");

// Areion512 hash function
var output512: [32]u8 = undefined;
areion.Areion512.hash("your message here", &output512, .{});

// Areion256 hash function  
var output256: [16]u8 = undefined;
areion.Areion256.hash("your message here", &output256, .{});

// Direct permutation usage (advanced)
var state512 = areion.Areion512.init();
state512.absorb(@splat(0x01));        // Absorb 32-byte input
state512.permute();                   // Apply permutation
const squeezed = state512.squeeze();  // Extract 32-byte output

// Authenticated encryption with AreionOCH
const key: [32]u8 = ...; // 256-bit key
const npub: [0]u8 = .{}; // AreionOCH has no public nonce
const nsec: [32]u8 = ...; // 256-bit secret nonce, embedded in the ciphertext
const plaintext = "secret message";
const associated_data = "metadata";

var ciphertext: [plaintext.len + 32]u8 = undefined;
var tag: [32]u8 = undefined;
areion.AreionOCH.encrypt(&ciphertext, &tag, plaintext, associated_data, npub, nsec, key);

// Decryption
var decrypted: [plaintext.len]u8 = undefined;
var recovered_nsec: [32]u8 = undefined;
try areion.AreionOCH.decrypt(&decrypted, &recovered_nsec, &ciphertext, tag, associated_data, npub, key);
```

## API Reference

### Areion512

- `block_length`: 32 bytes (input block size)
- `digest_length`: 32 bytes (output hash size)
- `hash(input, output, options)`: Main hash function
- `init()`: Initial hash state (zero rate, SHA-256 IV constants in the capacity)
- `fromBytes(bytes)`: Create instance from 64-byte state
- `toBytes()`: Serialize state to 64 bytes
- `absorb(bytes)`: Absorb 32-byte input block
- `squeeze()`: Extract 32-byte output
- `permute()`: Apply 15-round permutation
- `inversePermute()`: Apply the inverse permutation
- `setRate(bytes)` / `setCapacity(bytes)` / `getCapacity()`: Direct state manipulation
- `dm(message)`: Single-call Davies-Meyer compression of a 64-byte block
- `prf(input, key)`: Truncated Even-Mansour PRF (64-byte key + 64-byte input → 32-byte output)
- `encrypt(plaintext, key)`: Even-Mansour block cipher encryption (64-byte key, 64-byte block)
- `decrypt(ciphertext, key)`: Even-Mansour block cipher decryption

### Areion256

- `block_length`: 16 bytes (input block size)
- `digest_length`: 16 bytes (output hash size)
- `hash(input, output, options)`: Main hash function
- `init()`: Initial hash state (zero rate, SHA-256 IV constant in the capacity)
- `fromBytes(bytes)`: Create instance from 32-byte state
- `toBytes()`: Serialize state to 32 bytes
- `absorb(bytes)`: Absorb 16-byte input block
- `squeeze()`: Extract 16-byte output
- `permute()`: Apply 10-round permutation
- `inversePermute()`: Apply the inverse permutation
- `setRate(bytes)` / `setCapacity(bytes)` / `getCapacity()`: Direct state manipulation
- `dm(message)`: Single-call Davies-Meyer compression of a 32-byte block
- `prf(input, key)`: Truncated Even-Mansour PRF (32-byte key + 32-byte input → 16-byte output)
- `encrypt(plaintext, key)`: Even-Mansour block cipher encryption (32-byte key, 32-byte block)
- `decrypt(ciphertext, key)`: Even-Mansour block cipher decryption

### AreionOCH / AreionOCH_P

Authenticated encryption with associated data (AEAD) based on the OCH (Offset Codebook with Hashing) construction (CCS 2025). Two instantiations are provided, differing only in how the 256-bit nonce is split:

- **AreionOCH**: the whole nonce is secret and embedded in the ciphertext (`npub_length`: 0, `nsec_length`: 32), providing nonce privacy. Ciphertexts are 32 bytes longer than the plaintext.
- **AreionOCH_P**: the whole nonce is public (`npub_length`: 32, `nsec_length`: 0). Ciphertexts have the same length as the plaintext.

Common parameters:

- `key_length`: 32 bytes
- `nonce_length`: 32 bytes total (`npub_length + nsec_length`)
- `tag_length`: 32 bytes (authentication tag)
- `encrypt(c, tag, m, ad, npub, nsec, key)`: Encrypt and authenticate (`c.len == m.len + nsec_length`)
- `decrypt(m, nsec, c, tag, ad, npub, key)`: Decrypt and verify (returns `AuthenticationError` on failure)

Custom instantiations over other permutations can be built with the generic `och.OchS`, `och.OchP`, and `och.OchGeneric` functions.

Security properties:
- 128-bit NAE (nonce-based authenticated encryption) security
- 128-bit CMT (context commitment) security
- 256-bit nonces, with nonce privacy in the AreionOCH variant

### Areion256Opp / Areion512Opp

Authenticated encryption using the Offset Public Permutation (OPP) construction.

- `key_length`: 16 bytes
- `nonce_length`: 16 bytes
- `tag_length`: 16 bytes
- `block_length`: 32 bytes (Areion256Opp) or 64 bytes (Areion512Opp)
- `encrypt(key, nonce, ad, plaintext, ciphertext, tag)`: Encrypt and authenticate
- `decrypt(key, nonce, ad, ciphertext, tag, plaintext)`: Decrypt and verify (Areion256Opp only)

Both provide a streaming interface via `init`, `updateAd`, `update`, and `finalize`.

### Areion512Vec / Areion256Vec

Vectorized permutations for processing `count` independent states in parallel using SIMD. Created via `Areion512Vec(count)` or `Areion256Vec(count)`.

- `fromBytes(bytes)` / `toBytes()`: Serialize/deserialize concatenated states
- `xorBlocks(other)`: Element-wise XOR of two vectorized states
- `permute()` / `inversePermute()`: Apply the permutation to all parallel states

## Algorithm Details

### State Structure
- **Areion512**: 4 AES blocks (512 bits total)
  - blocks[0-1]: Rate (32 bytes) for input absorption
  - blocks[2-3]: Capacity (32 bytes) for internal state
- **Areion256**: 2 AES blocks (256 bits total)
  - blocks[0]: Rate (16 bytes) for input absorption
  - blocks[1]: Capacity (16 bytes) for internal state

### Padding Scheme
Standard Merkle-Damgård padding:
1. Append 0x80 byte
2. Pad with zeros
3. Append 32-bit big-endian bit length
4. Handle multi-block padding when necessary

## Performance

This implementation is optimized for:
- Small input sizes (common in cryptographic applications)
- Hardware AES acceleration when available
- Low memory overhead
- Cache-friendly memory access patterns

## Papers and References

This implementation is based on:
- **Areion**: [Areion: Highly-Efficient Permutations and Its Applications](https://eprint.iacr.org/2023/794.pdf) (TCHES 2023)
  - Authors: Takanori Isobe, Ryoma Ito, Fukang Liu, Kazuhiko Minematsu, Motoki Nakahashi, Kosei Sakamoto, Rentaro Shiba
- **OCH**: Offset Codebook with Hashing authenticated encryption mode (CCS 2025)
- **OPP**: [Improved Masking for Tweakable Blockciphers with Applications to Authenticated Encryption](https://eprint.iacr.org/2015/999.pdf) (EUROCRYPT 2016) -- defines the OPP AEAD construction

Implementation uses corrected test vectors from the updated Areion paper.
