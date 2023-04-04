# AEGIS-128X

- [AEGIS-128X](#aegis-128x)
- [Benchmarks](#benchmarks)
    - [Intel i9-13900k (thanks to @watzon)](#intel-i9-13900k-thanks-to-watzon)
  - [Zig CI server - Ryzen 9](#zig-ci-server---ryzen-9)
  - [Scaleway EPYC 7543 instance](#scaleway-epyc-7543-instance)
- [The AEGIS-128X construction](#the-aegis-128x-construction)
  - [Definitions](#definitions)
  - [Context separation](#context-separation)
  - [Parallel processing](#parallel-processing)
  - [Implementation notes](#implementation-notes)
  - [Security](#security)

AEGIS-128X is an experimental, parallel variant of the high performance authenticated cipher AEGIS-128L, designed to take advantage of the vectorized AES instructions present on recent x86_64 CPUs.

It is equivalent to evaluating multiple AEGIS-128L instances in parallel with different initial states.

# Benchmarks

AEGIS-128X has exceptional performance, even without AVX512.

Results for a 2-way variant, requiring AVX2 only:

### Intel i9-13900k (thanks to @watzon)

Zig benchmark:

```
       aegis-128x:      39781 MiB/s
       aegis-128l:      23863 MiB/s
        aegis-256:      12077 MiB/s
```

OpenSSL 3 AES benchmarks on the same machine:

```
       aes128-ocb:       16013 MiB/s
       aes256-ocb:       11520 MiB/s
       aes128-gcm:       10243 MiB/s
```

## Zig CI server - Ryzen 9

Zig benchmark:

```
       aegis-128x:      35642 MiB/s
       aegis-128l:      19209 MiB/s
        aegis-256:      11529 MiB/s
```

OpenSSL 3 AES benchmarks on the same machine:

```
       aes128-ocb:       8161 MiB/s
       aes256-ocb:       6255 MiB/s
       aes128-gcm:       4182 MiB/s
```

## Scaleway EPYC 7543 instance

Zig benchmark:

```
       aegis-128x:      29070 MiB/s
       aegis-128l:      15178 MiB/s
        aegis-256:       9066 MiB/s
```

OpenSSL 3 AES benchmarks on the same machine:

```
       aes128-ocb:       8933 MiB/s
       aes256-ocb:       6255 MiB/s
       aes128-gcm:       4387 MiB/s
```

Given that the `AESENC` instruction has the same latency/throughput regardless of the register size, one can expect AEGIS-128X to be about 4x the speed of AEGIS-128L on server-class CPUs with VAES and AVX512.

However, we may already be hitting memory bandwidth limits.

# The AEGIS-128X construction

## Definitions

- `ctx`: context separator
- `k`: encryption key
- `n`: nonce
- `p`: parallelism degree
- `ad`: associated data
- `m`: message
- `c`: ciphertext
- `t`: authentication tag
- `c0`, `c1`: AEGIS constants

## Context separation

AEGIS-128X evaluates `p` context-separated instances of AEGIS-128L.

In order to do so, we augment AEGIS-128L to include a context parameter in its initialization function.

AEGIS-128L defines the initial state as eight AES blocks set to:

| block | initial value |
| ----- | ------------- |
| 0     | k             |
| 1     | c1            |
| 2     | c0            |
| 3     | c1            |
| 4     | k ^ n         |
| 5     | k ^ c0        |
| 6     | k ^ c1        |
| 7     | k ^ c0        |

The AEGIS-128L initialization function performs 10 state updates. Before each update, we add the context to the state:

```
block[3] ← block[3] ^ ZeroPad(ctx)
block[7] ← block[7] ^ ZeroPad(ctx)
```

The `ZeroPad(ctx)` function, defined in the AEGIS-128L specification, adds trailing zeros to `ctx` in order to match the AES block size.

Note that when `ctx = 0`, the resulting state is exactly the same as AEGIS-128L, as originally specified, without a context.

## Parallel processing

AEGIS-128L absorbs the associated data and message with a 256-bit rate `r`.

In AEGIS-128X, the associated data and message are distributed in interleaved blocks with a stride of `r * p` bits as they arrive.

Input message message `m` is split into `r`-bit blocks:

```
{ m[0], m[1], m[2], … }
```

The last block is zero-padded to `r * p` bits.

These blocks are interleaved to produce `p` independent `|m|/p` bit messages `{ M[0], M[1], M[2], … M[p-1] }`:

```
M[0]   ← m[0]   ‖ m[p]       ‖ m[2p]       ‖ m[3p] …
M[1]   ← m[1]   ‖ m[p+1]     ‖ m[2p+1]     ‖ m[3p+2] …
M[2]   ← m[2]   ‖ m[p+2]     ‖ m[2p+2]     ‖ m[3p+2] …
…
M[p-1] ← m[p-1] ‖ m[p+(p-1)] ‖ m[2p+(p-1)] ‖ m[3p+(p-1)] …
```

Associated data is split into `p` parts the same way to produce `{ A[0], A[1], A[2], … A[p-1] }`.

AEGIS-128X then encrypts these inputs independently, producing `p` ciphertexts `C` and authentication tags `T`:

```
C[0], T[0]     ← AEGIS-128L(ctx←0,   k, n, A[0],   M[0])
C[1], T[1]     ← AEGIS-128L(ctx←1,   k, n, A[1],   M[1])
C[2], T[2]     ← AEGIS-128L(ctx←2,   k, n, A[2],   M[2])
…
C[p-1], T[p-1] ← AEGIS-128L(ctx←p-1, k, n, A[p-1], M[p-1])
```

`{ C[0], C[1], C[2], … C[p-1] }` are deinterleaved to produce the AEGIS-128X ciphertext:

```
c ← C[0][0] ‖ C[1][0] ‖ C[2][0] ‖ … ‖ C[p-1][0] ‖
    C[0][1] ‖ C[1][1] ‖ C[2][1] ‖ … ‖ C[p-1][1] ‖
    C[0][2] ‖ C[1][2] ‖ C[2][2] ‖ … ‖ C[p-1][2] ‖ …
```

Finally, the AEGIS-128X authentication tag is the addition the AEGIS-128L authentication tags:

```
t ← T[0] ^ T[1] ^ T[2] … ^ T[p-1]
```

Note that AEGIS-128L is just a specific instance of AEGIS-128X with `p=1`.

## Implementation notes

An AEGIS-128L state is represented as eight AES blocks, individually represented as the type `AesBlock`:

```
State128L: [8]AesBlock
```

In AEGIS-128X, we can consider vectors of `p` AES blocks:

```
AesBlockXp: [p]AesBlock
```

With proper hardware support, `AesBlockXP` can be efficiently stored in a 256-bit or 512-bit register.

The AEGIS-128X state only differs from the AEGIS-128L by the fact that is uses 8 vectors of AES blocks instead of 8 AES blocks:

```
State128X: [8]AesBlockXp
```

AEGIS-128X applies the exact same operation sequences as AEGIS-128L, to every member of the vector instead of single blocks.

This is equivalent to evaluating mutiple independent AEGIS-128L instances.

On CPUs that don't implement vectorized versions of the AES core permutation, AEGIS-128X can be implemented in two different ways:

1) by emulating AES block vectors. This is the easiest option, keeping the code close to hardware-accelerated versions.
2) by evaluating `A[0], A[1], A[2], … A[p-1]` and `C[0], C[1], C[2], … C[p-1]` sequentially, with periodic synchronization, for example after every memory page. This reduces cache-locality but also register pressure.

## Security

The AEGIS-128L security claims have the following requirements:
1. Each key should be generated uniformly at random.
2. Each key and nonce pair should not be used to protect more than one message; and each key and nonce pair should not be used with two different tag sizes.
3. If verification fails, the decrypted plaintext and the wrong authentication tag should not be given as output.

AEGIS-128X has the same requirements.

`AEGIS-128X(p, k, n, ad, m)` can be seen as `p` evaluations of AEGIS-128L, on `p` independent messages of length `|m|/p` bits.

In order to satisfy the AEGIS-128L contract, we should either derive distinct keys for each of these messages, or use distinct nonces.

`p` is limited by the hardware, and guaranteed to be small. On general purpose CPUs, the context cannot exceed `3`.

We could limit the AEGIS-128X nonce size to `128-log(p)` bits (instead of 128 for AEGIS-128L), encoding the context in the remaining bits to create the nonce used by the underlying AEGIS-128L functions.

That would be effectively AEGIS-128L, evaluated with independent messages, and distinct key and nonce pairs.

However, from an application perspective, `128-log(p)` bit nonces would be unusual, and at odds with AEGIS-128L.

Ideally, we'd like AEGIS-128L to internally support `128+log(p)`-bit nonces: AEGIS-128X applications would use 128 bit nonces, but the context could still be encoded to separate the parallel AEGIS-128L instances. To put it differently, we need to introduce a context with the same differential properties as the nonce.

In the proposed tweak to the initialization function, the context is added to the constants in blocks 3 and 7 of the initial state.

The purpose of the constants (simply derived from the Fibonacci sequence) is to resist attacks exploiting the symmetry of the AES round function and of the overall AEGIS state.

Given its limited range, adding `p` cannot turn them into weak constants, and doesn't alter any of the AEGIS-128L properties.
Note that `p` is expected to be a hyperparameter, that an adversary cannot have control of.

The main concern with the same key and nonce pair used in different contexts are differential attacks.

In AEGIS-128L, there are 80 AES round functions (10 steps) in the initialization function. A difference in contexts passes through more than 10 AES round functions, thus exceeding the AES-128 security margin.

Furthermore, in order to prevent the difference in the state being eliminated completely in the middle of the initialization, the context difference is repeatedly injected into the state. This is consistent with how 128-bit nonces are absorbed in AEGIS-128L.

The addition of a short context is thus unlikely to invalidate any of the current AEGIS-128L security claims.

These security claims require a key and nonce pair not to be used with different tag sizes. The AEGIS-128X construction guarantees that internal AEGIS-128L evaluations will always share the same tag size.

Note that the addition of a context to the AEGIS-128L initialization function could also be used to create a different initial state for different tag sizes, effectively increasing misuse resistance.