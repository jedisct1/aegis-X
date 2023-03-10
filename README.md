# AEGIS-128X

AEGIS-128X is an experimental, parallel variant of the high performance authenticated cipher AEGIS-128L, designed to take advantage of the vectorized AES instructions present on recent x86_64 CPUs.

It is equivalent to evaluating multiple AEGIS-128L instances in parallel with different initial states.

AEGIS-128X has exceptionnal performance, even without AVX512:

Zig benchmark results on a Scaleway Zen2 instance:

```
       aegis-128x:      29070 MiB/s
       aegis-128l:      15178 MiB/s
        aegis-256:       9066 MiB/s
       aes128-ocb:       5373 MiB/s
       aes256-ocb:       4732 MiB/s
       aes128-gcm:       3577 MiB/s
       aes256-gcm:       3115 MiB/s
```

Given that the `AESENC` instruction has the same latency/throughput regardless of the register size, one can expect AEGIS-128X to be about 4x the speed of AEGIS-128L on server-class CPUs with VAES and AVX512.
