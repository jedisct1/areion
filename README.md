# Areion

Fast Zig implementation of the [Areion](https://eprint.iacr.org/2023/794.pdf) permutation family presented at CHES 2023. This library provides both Areion512 and Areion256 variants, optimized for speed particularly on small inputs.

## Features

- **Areion512**: 512-bit permutation with 32-byte input blocks and 32-byte hash output
- **Areion256**: 256-bit permutation with 16-byte input blocks and 16-byte hash output
- **AreionOCH**: Authenticated encryption with associated data (AEAD) using OCH mode
- AES-based permutation using hardware acceleration when available
- Merkle-Damgård construction with Davies-Meyer compression
- Comprehensive test vectors included
- Optimized for performance on small inputs

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
var state512 = areion.Areion512{};
state512.absorb([_]u8{0x01} ** 32);  // Absorb 32-byte input
state512.permute();                   // Apply permutation
const squeezed = state512.squeeze();  // Extract 32-byte output

// Authenticated encryption with AreionOCH
const key: [32]u8 = ...; // 256-bit key
const npub: [24]u8 = ...; // 192-bit public nonce
const nsec: [8]u8 = ...; // 64-bit secret nonce
const plaintext = "secret message";
const associated_data = "metadata";

var ciphertext: [plaintext.len + 8]u8 = undefined;
var tag: [32]u8 = undefined;
areion.AreionOCH.encrypt(&ciphertext, &tag, plaintext, associated_data, npub, nsec, key);

// Decryption
var decrypted: [plaintext.len]u8 = undefined;
var recovered_nsec: [8]u8 = undefined;
try areion.AreionOCH.decrypt(&decrypted, &recovered_nsec, &ciphertext, tag, associated_data, npub, key);
```

## API Reference

### Areion512

- `block_length`: 32 bytes (input block size)
- `digest_length`: 32 bytes (output hash size)
- `hash(input, output, options)`: Main hash function
- `fromBytes(bytes)`: Create instance from 64-byte state
- `absorb(bytes)`: Absorb 32-byte input block
- `squeeze()`: Extract 32-byte output
- `permute()`: Apply 15-round permutation

### Areion256

- `block_length`: 16 bytes (input block size)
- `digest_length`: 16 bytes (output hash size)
- `hash(input, output, options)`: Main hash function
- `fromBytes(bytes)`: Create instance from 32-byte state
- `absorb(bytes)`: Absorb 16-byte input block
- `squeeze()`: Extract 16-byte output
- `permute()`: Apply 10-round permutation

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

## Paper and Reference

This implementation is based on the corrected version of the Areion paper:
- **Paper**: [Areion: Highly-Efficient Permutations and Its Applications](https://eprint.iacr.org/2023/794.pdf)
- **Authors**: Clémence Bouvier, Pierre Briaud, Pyrros Chaidos, Léo Perrin, Robin Salen, Vesselin Velichkov, Danny Willems
- **Implementation**: Uses corrected test vectors from the updated paper
