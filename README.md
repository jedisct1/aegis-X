# AEGIS-128X and AEGIS-256X

- [AEGIS-128X and AEGIS-256X](#aegis-128x-and-aegis-256x)
- [Specification](#specification)
- [Benchmarks](#benchmarks)
    - [Intel i9-13900k (thanks to @watzon)](#intel-i9-13900k-thanks-to-watzon)
  - [Zig CI server - Ryzen 9](#zig-ci-server---ryzen-9)
  - [Scaleway EPYC 7543 instance](#scaleway-epyc-7543-instance)

AEGIS-128X and AEGIS-256X are proposed variants of the high performance authenticated ciphers AEGIS-128L and AEGIS-256, designed to take advantage of the vectorized AES instructions present on recent x86_64 CPUs.

# Specification

[Adding more parallelism to the AEGIS authenticated encryption algorithms](aegis-x.pdf)

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

## Scaleway EPYC 7543 instance

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

Given that the `AESENC` instruction has the same latency/throughput regardless of the register size, one can expect AEGIS-128X to be about 4x the speed of AEGIS-128L on server-class CPUs with VAES and AVX512.

However, we may already be hitting memory bandwidth limits.
