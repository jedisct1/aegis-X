# AEGIS-128X

AEGIS-128X is an experimental, parallel variant of the high performance authenticated cipher AEGIS-128L, designed to take advantage of the vectorized AES instructions present on recent x86_64 CPUs.

It is equivalent to evaluating multiple AEGIS-128L instances in parallel with different initial states.

AEGIS-128X has exceptional performance, even without AVX512.

## Scaleway Zen2 instance (AVX2 only)

Zig benchmark:

```
       aegis-128x:      29070 MiB/s
       aegis-128l:      15178 MiB/s
        aegis-256:       9066 MiB/s
```

OpenSSL 3 AES-OCB benchmarks on the same machine:

```
       aes128-ocb:       8633 MiB/s
       aes256-ocb:       5972 MiB/s
```

## Zig CI server - Ryzen 9 (AVX2 only)

Zig benchmark:

```
       aegis-128x:      35642 MiB/s
       aegis-128l:      19209 MiB/s
        aegis-256:      11529 MiB/s
```

OpenSSL 3 AES-OCB benchmarks on the same machine:

```
       aes128-ocb:      11427 MiB/s
       aes256-ocb:       7993 MiB/s
```

Given that the `AESENC` instruction has the same latency/throughput regardless of the register size, one can expect AEGIS-128X to be about 4x the speed of AEGIS-128L on server-class CPUs with VAES and AVX512.
