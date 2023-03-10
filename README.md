# AEGIS-128X

AEGIS-128X is an experimental, parallel variant of the high performance authenticated cipher AEGIS-128L, designed to take advantage of the vectorized AES instructions present on recent x86_64 CPUs.

It is equivalent to evaluating multiple AEGIS-128L instances in parallel with different initial states.

AEGIS-128X has exceptional performance, even without AVX512.

## Intel i13900k (thanks to @watzon) (AVX2 only)

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

## Scaleway Zen2 instance (AVX2 only)

Zig benchmark:

```
       aegis-128x:      29070 MiB/s
       aegis-128l:      15178 MiB/s
        aegis-256:       9066 MiB/s
```

## Zig CI server - Ryzen 9 (AVX2 only)

Zig benchmark:

```
       aegis-128x:      35642 MiB/s
       aegis-128l:      19209 MiB/s
        aegis-256:      11529 MiB/s
```

Given that the `AESENC` instruction has the same latency/throughput regardless of the register size, one can expect AEGIS-128X to be about 4x the speed of AEGIS-128L on server-class CPUs with VAES and AVX512.
