/*
 * Safe clamp sanitizer intentionally NOT pre-modeled in DefaultSemantics.
 * Auto-discovery should identify this as a sanitizer when enabled.
 */

#define MAX 1024

extern void* malloc(unsigned long);
extern void memcpy(void*, const void*, unsigned long);
extern void free(void*);

typedef unsigned long size_t;

size_t clamp_unmodeled_safe(size_t n) {
    if (n > MAX) {
        n = MAX;
    }
    return n;
}

void with_method_sanitizer_unmodeled_safe(size_t len, char *src) {
    size_t sanitized_len = clamp_unmodeled_safe(len);
    char *dst = (char *)malloc(sanitized_len + 1);
    if (!dst) return;
    memcpy(dst, src, sanitized_len);  /* SINK */
    dst[sanitized_len] = '\0';
    free(dst);
}
