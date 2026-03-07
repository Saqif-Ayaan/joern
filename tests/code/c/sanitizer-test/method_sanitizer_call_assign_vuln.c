/*
 * Intentionally unsafe sanitizer lookalike.
 *
 * On the "bad" branch, n is overwritten by a call result. This should not be
 * accepted as a strict bound by the stage-3 validator.
 */

#define MAX 1024

extern void* malloc(unsigned long);
extern void memcpy(void*, const void*, unsigned long);
extern void free(void*);

typedef unsigned long size_t;

size_t plus_one(size_t x) {
    return x + 1;
}

size_t clamp_call_assign_vuln(size_t n) {
    if (n > MAX) {
        n = plus_one(n);
    }
    return n;
}

void with_method_sanitizer_call_assign_vuln(size_t len, char *src) {
    size_t sanitized_len = clamp_call_assign_vuln(len);
    char *dst = (char *)malloc(sanitized_len + 1);
    if (!dst) return;
    memcpy(dst, src, sanitized_len);  /* SINK */
    dst[sanitized_len] = '\0';
    free(dst);
}
