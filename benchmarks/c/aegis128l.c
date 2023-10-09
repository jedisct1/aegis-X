// aegis-128l.c v1.0.0 03/17/2023
//
// Benchmark of the AEGIS-128L authenticated encryption function
// Maintainer: Frank Denis @fdenis
// Source repos: https://github.com/fastly/cpu-benchmarks/
//
// Supported CPUs: x86_64 (aarch64 support available if needed) with
// the AES and AVX2 instructions sets.
// Supported compilers: zig cc, clang, gcc, icc
//
// This benchmark recursively encrypts a message in-place, updating the
// key and the nonce with the previous ciphertext.
//
// AEGIS-128L is a cipher we are looking to use for clustering,
// for object storage, in order to improve performance over AES-GCM.
//
// This is a stripped-down implementation that only includes encryption,
// and only support for x86_64 CPUs, but with the same code as the one
// from our BoringSSL fork, itself derived from libsodium and from the
// Zig reference implementation of the specification.
//
// Reference:
// https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/
//
// Reference implementation:
// https://github.com/cfrg/draft-irtf-cfrg-aegis-aead/tree/main/reference-implementations

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#ifdef __clang__
#pragma clang attribute push(__attribute__((target("aes,ssse3"))), apply_to = function)
#elif defined(__GNUC__)
#pragma GCC target("aes,ssse3")
#endif

#if defined(__INTEL_COMPILER) || defined(_MSC_VER)
#define CRYPTO_ALIGN(x) __declspec(align(x))
#else
#define CRYPTO_ALIGN(x) __attribute__((aligned(x)))
#endif

#include <wmmintrin.h>

typedef __m128i aes_block_t;
#define AES_BLOCK_XOR(A, B)       _mm_xor_si128((A), (B))
#define AES_BLOCK_AND(A, B)       _mm_and_si128((A), (B))
#define AES_BLOCK_LOAD(A)         _mm_loadu_si128((const aes_block_t *) (const void *) (A))
#define AES_BLOCK_LOAD_64x2(A, B) _mm_set_epi64x((A), (B))
#define AES_BLOCK_STORE(A, B)     _mm_storeu_si128((aes_block_t *) (void *) (A), (B))
#define AES_ENC(A, B)             _mm_aesenc_si128((A), (B))

static inline void
aegis128l_update(aes_block_t *const state, const aes_block_t d1, const aes_block_t d2)
{
    aes_block_t tmp;

    tmp      = state[7];
    state[7] = AES_ENC(state[6], state[7]);
    state[6] = AES_ENC(state[5], state[6]);
    state[5] = AES_ENC(state[4], state[5]);
    state[4] = AES_ENC(state[3], state[4]);
    state[3] = AES_ENC(state[2], state[3]);
    state[2] = AES_ENC(state[1], state[2]);
    state[1] = AES_ENC(state[0], state[1]);
    state[0] = AES_ENC(tmp, state[0]);

    state[0] = AES_BLOCK_XOR(state[0], d1);
    state[4] = AES_BLOCK_XOR(state[4], d2);
}

static void
aegis128l_init(const unsigned char *key, const unsigned char *nonce, aes_block_t *const state)
{
    static CRYPTO_ALIGN(16)
        const uint8_t c0_[] = { 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1,
                                0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd };
    static CRYPTO_ALIGN(16)
        const uint8_t c1_[] = { 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d,
                                0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 };
    const aes_block_t c0    = AES_BLOCK_LOAD(c0_);
    const aes_block_t c1    = AES_BLOCK_LOAD(c1_);
    aes_block_t       k;
    aes_block_t       n;
    int               i;

    k = AES_BLOCK_LOAD(key);
    n = AES_BLOCK_LOAD(nonce);

    state[0] = AES_BLOCK_XOR(k, n);
    state[1] = c0;
    state[2] = c1;
    state[3] = c0;
    state[4] = AES_BLOCK_XOR(k, n);
    state[5] = AES_BLOCK_XOR(k, c1);
    state[6] = AES_BLOCK_XOR(k, c0);
    state[7] = AES_BLOCK_XOR(k, c1);
    for (i = 0; i < 10; i++) {
        aegis128l_update(state, n, k);
    }
}

static void
aegis128l_mac(unsigned char *mac, unsigned long long adlen, unsigned long long mlen,
              aes_block_t *const state)
{
    aes_block_t tmp;
    int         i;

    tmp = AES_BLOCK_LOAD_64x2(mlen << 3, adlen << 3);
    tmp = AES_BLOCK_XOR(tmp, state[2]);

    for (i = 0; i < 7; i++) {
        aegis128l_update(state, tmp, tmp);
    }

    tmp = AES_BLOCK_XOR(state[6], AES_BLOCK_XOR(state[5], state[4]));
    tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[3], state[2]));
    tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[1], state[0]));

    AES_BLOCK_STORE(mac, tmp);
}

static inline void
aegis128l_absorb(const unsigned char *const src, aes_block_t *const state)
{
    aes_block_t msg0, msg1;

    msg0 = AES_BLOCK_LOAD(src);
    msg1 = AES_BLOCK_LOAD(src + 16);
    aegis128l_update(state, msg0, msg1);
}

static void
aegis128l_enc(unsigned char *const dst, const unsigned char *const src, aes_block_t *const state)
{
    aes_block_t msg0, msg1;
    aes_block_t tmp0, tmp1;

    msg0 = AES_BLOCK_LOAD(src);
    msg1 = AES_BLOCK_LOAD(src + 16);
    tmp0 = AES_BLOCK_XOR(msg0, state[6]);
    tmp0 = AES_BLOCK_XOR(tmp0, state[1]);
    tmp1 = AES_BLOCK_XOR(msg1, state[5]);
    tmp1 = AES_BLOCK_XOR(tmp1, state[2]);
    tmp0 = AES_BLOCK_XOR(tmp0, AES_BLOCK_AND(state[2], state[3]));
    tmp1 = AES_BLOCK_XOR(tmp1, AES_BLOCK_AND(state[6], state[7]));
    AES_BLOCK_STORE(dst, tmp0);
    AES_BLOCK_STORE(dst + 16, tmp1);

    aegis128l_update(state, msg0, msg1);
}

static int
aegis128l_encrypt_detached(unsigned char *c, unsigned char *mac, const unsigned char *m,
                           unsigned long long mlen, const unsigned char *ad,
                           unsigned long long adlen, const unsigned char *npub,
                           const unsigned char *k)
{
    aes_block_t state[8];
    CRYPTO_ALIGN(16)
    unsigned char src[32];
    CRYPTO_ALIGN(16)
    unsigned char      dst[32];
    unsigned long long i;

    aegis128l_init(k, npub, state);

    for (i = 0ULL; i + 32ULL <= adlen; i += 32ULL) {
        aegis128l_absorb(ad + i, state);
    }
    if (adlen & 0x1f) {
        memset(src, 0, 32);
        memcpy(src, ad + i, adlen & 0x1f);
        aegis128l_absorb(src, state);
    }
    for (i = 0ULL; i + 32ULL <= mlen; i += 32ULL) {
        aegis128l_enc(c + i, m + i, state);
    }
    if (mlen & 0x1f) {
        memset(src, 0, 32);
        memcpy(src, m + i, mlen & 0x1f);
        aegis128l_enc(dst, src, state);
        memcpy(c + i, dst, mlen & 0x1f);
    }

    aegis128l_mac(mac, adlen, mlen, state);
    memset(state, 0, sizeof state);
    memset(src, 0, sizeof src);
    memset(dst, 0, sizeof dst);

    return 0;
}

#define CPUID_ECX_AESNI   0x02000000
#define CPUID_ECX_XSAVE   0x04000000
#define CPUID_ECX_OSXSAVE 0x08000000
#define CPUID_ECX_AVX     0x10000000

#define XCR0_SSE       0x00000002
#define XCR0_AVX       0x00000004
#define XCR0_OPMASK    0x00000020
#define XCR0_ZMM_HI256 0x00000040
#define XCR0_HI16_ZMM  0x00000080

static void
_cpuid(unsigned int cpu_info[4U], const unsigned int cpu_info_type)
{
    cpu_info[0] = cpu_info[1] = cpu_info[2] = cpu_info[3] = 0;
    __asm__ __volatile__("xchgq %%rbx, %q1; cpuid; xchgq %%rbx, %q1"
                         : "=a"(cpu_info[0]), "=&r"(cpu_info[1]), "=c"(cpu_info[2]),
                           "=d"(cpu_info[3])
                         : "0"(cpu_info_type), "2"(0U));
}

static int
check_cpu_features(void)
{
    unsigned int cpu_info[4];
    uint32_t     xcr0      = 0U;
    int          has_avx   = 0;
    int          has_aesni = 0;

    _cpuid(cpu_info, 0x0);
    if (cpu_info[0] == 0U) {
        return -1;
    }
    _cpuid(cpu_info, 0x00000001);

    if ((cpu_info[2] & (CPUID_ECX_AVX | CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE)) ==
        (CPUID_ECX_AVX | CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE)) {
        __asm__ __volatile__(".byte 0x0f, 0x01, 0xd0" /* XGETBV */
                             : "=a"(xcr0)
                             : "c"((uint32_t) 0U)
                             : "%edx");
        if ((xcr0 & (XCR0_SSE | XCR0_AVX)) == (XCR0_SSE | XCR0_AVX)) {
            has_avx = 1;
        }
    }
    has_aesni = ((cpu_info[2] & CPUID_ECX_AESNI) != 0x0);

    if (!(has_avx && has_aesni)) {
        printf("AVX support: %d (required)\n", has_avx);
        printf("AES support: %d (required)\n", has_aesni);
        return -1;
    }
    return 0;
}

#if defined(_POSIX_TIMERS) && (_POSIX_TIMERS > 0) && defined(_POSIX_MONOTONIC_CLOCK)
#define HAS_CLOCK_GETTIME_MONOTONIC
#endif

int
main(int argc, char *argv[])
{
    int64_t delta;
#ifdef HAS_CLOCK_GETTIME_MONOTONIC
    struct timespec start, stop;
#else
    struct timeval start, stop;
#endif

    unsigned char     *buf;
    unsigned char      mac[16];
    unsigned char      key[16]   = { 0 };
    unsigned char      nonce[16] = { 0 };
    unsigned long long count;
    size_t             size;

    if (check_cpu_features() != 0) {
        return 254;
    }

    if (argc != 3) {
        printf("usage: aegis128l <message-size> <message-count>\n");
        return 1;
    }

    size  = atoi(argv[1]);
    count = atol(argv[2]);

    if ((buf = calloc(size, (size_t) 1U)) == NULL) {
        return 1;
    }

#ifdef HAS_CLOCK_GETTIME_MONOTONIC
    (void) clock_gettime(CLOCK_MONOTONIC, &start);
#else
    (void) gettimeofday(&start, NULL);
#endif

    for (unsigned long long i = 0; i < count; i++) {
        aegis128l_encrypt_detached(buf, mac, buf, size, NULL, 0, nonce, key);
        key[0]   = buf[0] ^ mac[0];
        nonce[0] = buf[1] ^ mac[1];
    }

#ifdef HAS_CLOCK_GETTIME_MONOTONIC
    (void) clock_gettime(CLOCK_MONOTONIC, &stop);
    delta = ((stop.tv_sec - start.tv_sec) * 1000000 + (stop.tv_nsec - start.tv_nsec) / 1000);
#else
    (void) gettimeofday(&stop, NULL);
    delta = (stop.tv_sec - start.tv_sec) * 1000000 + (stop.tv_usec - start.tv_usec);
#endif

    __asm__ __volatile__("" : : "r"(buf) : "memory");
    free(buf);

    printf("average throughput: %llu msg/s\n", (count * 1000000) / delta);
    printf("average throughput: %llu Mb/s\n", (((count * 1000000) / delta) * size * 8) / 1000000);

    return 0;
}

#ifdef __clang__
#pragma clang attribute pop
#endif
