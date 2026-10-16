#define THREEI_CTX_CACHE_MAX 4
#define THREEI_CTX_CACHE_FULL GENMASK(THREEI_CTX_CACHE_MAX - 1, 0)

struct threei_grate_ctx;

struct threei_ctx_cache {
    pid_t                   grateid[THREEI_CTX_CACHE_MAX];
    struct threei_grate_ctx *ctx[THREEI_CTX_CACHE_MAX];
    unsigned long           valid;
    unsigned int            next;
} ____cacheline_aligned; // lands in kmalloc-64
