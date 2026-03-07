/*
 * Intentionally unsafe sanitizer lookalike.
 *
 * Returning a helper-call result is not a strict bound and should not be
 * accepted by the stage-3 validator.
 */

#define MAX 1024

extern void* malloc(unsigned long);
extern void memcpy(void*, const void*, unsigned long);
extern void free(void*);

typedef unsigned long size_t;

size_t identity(size_t x) {
    return x;
}

size_t clamp_return_call_vuln(size_t n) {
    return identity(n);
}

void with_method_sanitizer_return_call_vuln(size_t len, char *src) {
    size_t sanitized_len = clamp_return_call_vuln(len);
    char *dst = (char *)malloc(sanitized_len + 1);
    if (!dst) return;
    memcpy(dst, src, sanitized_len);  /* SINK */
    dst[sanitized_len] = '\0';
    free(dst);
}
