# AEGIS-128X

AEGIS-128X is an experimental, parallel variant of the high performance authenticated cipher AEGIS-128L, designed to take advantage of the vectorized AES instructions present on recent x86_64 CPUs.

It is equivalent to evaluating multiple AEGIS-128L instances in parallel with different initial states.

AEGIS-128X has exceptional performance, even without AVX512.

Results for a 2-way variant, requiring AVX2 only:

## Intel i9-13900k (thanks to @watzon)

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

## The AEGIS-128X construction

### Definitions

- `ctx`: context separator
- `k`: encryption key
- `n`: nonce
- `p`: parallelism degree
- `ad`: associated data
- `m`: message
- `c`: ciphertext
- `t`: authentication tag
- `c0`, `c1`: AEGIS constants

### Context seperation

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

We add the context to that state:

```
block[3] = block[3] ^ ZeroPad(ctx)
block[7] = block[7] ^ ZeroPad(ctx)
```

The `ZeroPad(ctx)` function, defined in the AEGIS-128L specification, adds trailing zeros to `ctx` in order to match the AES block size.

Note that when `ctx = 0`, the initial state is exactly the same as AEGIS-128L, as originally defined, without a context.

### Parallel encryption

AEGIS-128L absorbs the associated data and message with a 256-bit rate `r`.

In AEGIS-128X, the associated data and message are distributed in interleaved blocks of size `B = r * p` bits as they arrive.

Given input message `m`, considered as a sequence of `r`-bit blocks:

```
m = { m[0], m[1], m[2], … }
```

These blocks are interleaved to produce `p` independent messages `{ M[0], M[1], M[2], … M[p-1] }`:

```
M[0]   = m[0]      ‖ m[B]        ‖ m[2B]        ‖ m[3B] …
M[1]   = m[r]      ‖ m[B+r]      ‖ m[2B+r]      ‖ m[3B+r] …
M[2]   = m[2r]     ‖ m[B+2r]     ‖ m[2B+2r]     ‖ m[3B+2r] …
M[p-1] = m[(p-1)r] ‖ m[B+(p-1)r] ‖ m[2B+(p-1)r] ‖ m[3B+(p-1)r] …
```

The exact same distribution method is applied to the associated data in order to produce `{ A[0], A[1], A[2], … A[p-1] }`.

AEGIS-128X then encrypts these inputs independently, producing `p` ciphertexts `C` and authentication tags `T`:

```
C[0], T[0]     = AEGIS-128L(ctx=0,   k, n, A[0],   M[0])
C[1], T[1]     = AEGIS-128L(ctx=1,   k, n, A[1],   M[1])
C[2], T[2]     = AEGIS-128L(ctx=2,   k, n, A[2],   M[2])
C[p-1], T[p-1] = AEGIS-128L(ctx=p-1, k, n, A[p-1], M[p-1])
```

`{ C[0], C[1], C[2], … C[p-1] }` are de-interleaved to produce the AEGIS-128X ciphertext:

```
c = C[0][0] ‖ C[1][0] ‖ C[2][0] ‖ C[p-1][0] ‖
    C[0][1] ‖ C[1][1] ‖ C[2][1] ‖ C[p-1][1] ‖
    C[0][2] ‖ C[1][2] ‖ C[2][2] ‖ C[p-1][2] ‖
    …
```

Finally, the AEGIS-128X authentication tag is the addition of the independent authentication tags:

```
t = T[0] ^ T[1] ^ T[2] … T[p-1]
```

Note that AEGIS-128L is just a specific instance of AEGIS-128X with `p=1`.