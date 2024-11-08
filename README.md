# AEGIS-128X and AEGIS-256X

- [AEGIS-128X and AEGIS-256X](#aegis-128x-and-aegis-256x)
- [Specification and rationale](#specification-and-rationale)
- [Implementations](#implementations)
- [Benchmarks](#benchmarks)
    - [Encryption (16 KB)](#encryption-16-kb)
    - [Authentication (64 KB)](#authentication-64-kb)
    - [Mobile benchmarks](#mobile-benchmarks)

AEGIS-128X and AEGIS-256X are proposed variants of the high performance authenticated ciphers AEGIS-128L and AEGIS-256, designed to take advantage of the long pipelines and vectorized AES instructions present on recent CPUs.

# Specification and rationale

AEGIS-128X and AEGIS-256X are now included in the [AEGIS specification](https://cfrg.github.io/draft-irtf-cfrg-aegis-aead/draft-irtf-cfrg-aegis-aead.html).

Rationale: [Adding more parallelism to the AEGIS authenticated encryption algorithms](https://eprint.iacr.org/2023/523)

# Implementations

List of known [opensource AEGIS implementations](https://github.com/cfrg/draft-irtf-cfrg-aegis-aead?tab=readme-ov-file#known-implementations).

AEGIS-X is at least implemented in libaegis, jasmin-aegis and
crypto-rust in addition to the reference implementations.

# Benchmarks

AEGIS-128X has exceptional performance, even without AVX512.

### Encryption (16 KB)

![AEGIS benchmark results](img/bench-encryption.png)

### Authentication (64 KB)

![AEGIS-MAC benchmark results](img/bench-mac.png)

### Mobile benchmarks

![AEGIS mobile benchmark results](img/bench-mobile.png)
