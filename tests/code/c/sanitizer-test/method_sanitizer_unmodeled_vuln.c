/*
 * Unsafe sanitizer lookalike intentionally NOT pre-modeled in DefaultSemantics.
 * Auto-discovery should reject this implementation.
 */

#define MAX 1024

extern void* malloc(unsigned long);
extern void memcpy(void*, const void*, unsigned long);
extern void free(void*);

typedef unsigned long size_t;

size_t clamp_unmodeled_vuln(size_t n) {
    if (n > MAX) {
        n = n + 1;  /* not a clamp; may increase tainted value */
    }
    return n;
}

void with_method_sanitizer_unmodeled_vuln(size_t len, char *src) {
    size_t sanitized_len = clamp_unmodeled_vuln(len);
    char *dst = (char *)malloc(sanitized_len + 1);
    if (!dst) return;
    memcpy(dst, src, sanitized_len);  /* SINK */
    dst[sanitized_len] = '\0';
    free(dst);
}
