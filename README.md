# AEGIS-128X and AEGIS-256X

- [AEGIS-128X and AEGIS-256X](#aegis-128x-and-aegis-256x)
- [Specification and rationale](#specification-and-rationale)
- [Benchmarks](#benchmarks)
    - [Intel i9-13900k (thanks to @watzon)](#intel-i9-13900k-thanks-to-watzon)
  - [Zig CI server - Ryzen 9](#zig-ci-server---ryzen-9)
    - [Encryption](#encryption)
    - [Authentication (MAC)](#authentication-mac)
  - [Scaleway EPYC 7543 instance](#scaleway-epyc-7543-instance)
    - [Encryption](#encryption-1)
    - [Authentication (MAC)](#authentication-mac-1)

AEGIS-128X and AEGIS-256X are proposed variants of the high performance authenticated ciphers AEGIS-128L and AEGIS-256, designed to take advantage of the vectorized AES instructions present on recent x86_64 CPUs.

# Specification and rationale

[Adding more parallelism to the AEGIS authenticated encryption algorithms](https://eprint.iacr.org/2023/523)

# Benchmarks

AEGIS-128X has exceptional performance, even without AVX512.

Results for a 2-way variant, requiring AVX2 only:

### Intel i9-13900k (thanks to @watzon)

Zig benchmark:

```text
       aegis-128x:      39781 MiB/s
       aegis-128l:      23863 MiB/s
        aegis-256:      12077 MiB/s
```

OpenSSL 3 AES benchmarks on the same machine:

```text
       aes128-ocb:       16013 MiB/s
       aes256-ocb:       11520 MiB/s
       aes128-gcm:       10243 MiB/s
```

## Zig CI server - Ryzen 9

### Encryption

Zig benchmark:

```text
       aegis-128x:      35642 MiB/s
       aegis-128l:      19209 MiB/s
        aegis-256:      11529 MiB/s
```

OpenSSL 3 AES benchmarks on the same machine:

```text
       aes128-ocb:       8161 MiB/s
       aes256-ocb:       6255 MiB/s
       aes128-gcm:       4182 MiB/s
```

### Authentication (MAC)

Zig benchmark:

```text
   blake3 (rust/asm):    4570 MiB/s
   aegis-128l mac:      24381 MiB/s
   aegis-128x mac:      37537 MiB/s
```

## Scaleway EPYC 7543 instance

### Encryption

Zig benchmark:

```text
       aegis-128x:      29070 MiB/s
       aegis-128l:      15178 MiB/s
        aegis-256:       9066 MiB/s
```

OpenSSL 3 AES benchmarks on the same machine:

```text
       aes128-ocb:       8933 MiB/s
       aes256-ocb:       6255 MiB/s
       aes128-gcm:       4387 MiB/s
```

### Authentication (MAC)

Zig benchmark:

```text
   blake3 (rust/asm):    4900 MiB/s
   aegis-128l mac:      20768 MiB/s
   aegis-128x mac:      31992 MiB/s
```

Given that the `AESENC` instruction has the same latency/throughput regardless of the register size, one can expect AEGIS-128X to be about 4x the speed of AEGIS-128L on server-class CPUs with VAES and AVX512.

However, we may already be hitting memory bandwidth limits.
