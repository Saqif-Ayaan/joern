/*
 * Assignment-based clamp sanitizer.
 *
 * This variant does not immediately return in the true branch; it updates n
 * and returns n at the end. Validator should still accept this as safe.
 */

#define MAX 1024

extern void* malloc(unsigned long);
extern void memcpy(void*, const void*, unsigned long);
extern void free(void*);

typedef unsigned long size_t;

size_t clamp_many(size_t n) {
    if (n > MAX) n = MAX;
    if (n > 900) n = 900;
    if (n > 800) n = 800;
    return n;
}

void with_method_sanitizer_many_assign(size_t len, char *src) {
    size_t sanitized_len = clamp_many(len);
    char *dst = (char *)malloc(sanitized_len + 1);
    if (!dst) return;
    memcpy(dst, src, sanitized_len);    /* SINK */
    dst[sanitized_len] = '\0';
    free(dst);
}
