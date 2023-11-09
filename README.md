# AEGIS-128X and AEGIS-256X

- [AEGIS-128X and AEGIS-256X](#aegis-128x-and-aegis-256x)
- [Specification and rationale](#specification-and-rationale)
- [Benchmarks](#benchmarks)
  - [Ryzen 7 7700](#ryzen-7-7700)
    - [Encryption](#encryption)
    - [Authentication (MAC)](#authentication-mac)
    - [Intel i9-13900k (thanks to @watzon)](#intel-i9-13900k-thanks-to-watzon)
  - [Zig CI server - Ryzen 9](#zig-ci-server---ryzen-9)
    - [Encryption](#encryption-1)
    - [Authentication (MAC)](#authentication-mac-1)
  - [Scaleway EPYC 7543 instance](#scaleway-epyc-7543-instance)
    - [Encryption](#encryption-2)
    - [Authentication (MAC)](#authentication-mac-2)
- [Other implementations](#other-implementations)

AEGIS-128X and AEGIS-256X are proposed variants of the high performance authenticated ciphers AEGIS-128L and AEGIS-256, designed to take advantage of the vectorized AES instructions present on recent x86_64 CPUs.

# Specification and rationale

AEGIS-128X and AEGIS-256X are now included in the [AEGIS specification](https://cfrg.github.io/draft-irtf-cfrg-aegis-aead/draft-irtf-cfrg-aegis-aead.html).

Rationale: [Adding more parallelism to the AEGIS authenticated encryption algorithms](https://eprint.iacr.org/2023/523)

# Benchmarks

AEGIS-128X has exceptional performance, even without AVX512.

## Ryzen 7 7700

### Encryption

BoringSSL benchmark (16K blocks):

```text
      aegis-128x4:      44654 MiB/s
      aegis-128x2:      39707 MiB/s
       aegis-128l:      19514 MiB/s
       aes128-ocb:      10195 MiB/s
       aes128-gcm:       4940 MiB/s
```

256-bit variants:

```text
      aegis-256x4:      35521 MiB/s
      aegis-256x2:      23555 MiB/s
        aegis-256:      12055 MiB/s
       aes256-ocb:       7143 MiB/s
       aes256-gcm:       4649 MiB/s
```

### Authentication (MAC)

```text
      aegis-128x4:      53573 MiB/s
      aegis-128x2:      45821 MiB/s
       aegis-128l:      19514 MiB/s
```

### Intel i9-13900k (thanks to @watzon)

Results for a 2-way variant, requiring AVX2 only:

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

Results for a 2-way variant, requiring AVX2 only:

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

Zig benchmark (single core):

```text
   aegis-128x mac:      37537 MiB/s
   aegis-128l mac:      24381 MiB/s
   blake3 (rust/asm):    4570 MiB/s
```

## Scaleway EPYC 7543 instance

Results for a 2-way variant, requiring AVX2 only:

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

Zig benchmark (single core):

```text
   aegis-128x mac:      31992 MiB/s
   aegis-128l mac:      20768 MiB/s
   blake3 (rust/asm):    4900 MiB/s
```

Given that the `AESENC` instruction has the same latency/throughput regardless of the register size, one can expect AEGIS-128X to be about 4x the speed of AEGIS-128L on server-class CPUs with VAES and AVX512.

However, we may already be hitting memory bandwidth limits.

# Other implementations

- [libaegis](https://github.com/jedisct1/libaegis) is a library written in C, with support for all the AEGIS variants, including AEGIS-X.
