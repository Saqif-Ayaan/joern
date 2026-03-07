/*
 * Safe join-based clamp sanitizer.
 *
 * Both branches assign a strict upper bound and then return n at the join.
 * Stage-3 validator should accept this as bounded on all paths.
 */

#define MAX 1024

extern void* malloc(unsigned long);
extern void memcpy(void*, const void*, unsigned long);
extern void free(void*);

typedef unsigned long size_t;

size_t clamp_join_safe(size_t n, int flag) {
    if (flag) {
        n = MAX;
    } else {
        n = 900;
    }
    return n;
}

void with_method_sanitizer_join_safe(size_t len, char *src) {
    size_t sanitized_len = clamp_join_safe(len, 1);
    char *dst = (char *)malloc(sanitized_len + 1);
    if (!dst) return;
    memcpy(dst, src, sanitized_len);  /* SINK */
    dst[sanitized_len] = '\0';
    free(dst);
}
