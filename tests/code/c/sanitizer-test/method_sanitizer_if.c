/*
 * Sanitizer style using explicit if/else branches (non-ternary).
 */

#define MAX 1024

extern void* malloc(unsigned long);
extern void memcpy(void*, const void*, unsigned long);
extern void free(void*);

typedef unsigned long size_t;

size_t clamp_if(size_t n) {
    if (n > MAX) {
        return MAX;
    } else {
        return n;
    }
}

void with_method_sanitizer_if(size_t len, char *src) {
    size_t sanitized_len = clamp_if(len);
    char *dst = (char *)malloc(sanitized_len + 1);
    if (!dst) return;
    memcpy(dst, src, sanitized_len);  /* SINK */
    dst[sanitized_len] = '\0';
    free(dst);
}
