/*
 * Assignment-based sanitizer that is intentionally unsafe.
 *
 * The method keeps n unchanged on all branches, so validator must reject it.
 */

#define MAX 1024

extern void* malloc(unsigned long);
extern void memcpy(void*, const void*, unsigned long);
extern void free(void*);

typedef unsigned long size_t;

size_t clamp_many_vuln(size_t n) {
    if (n > MAX) n = n;
    if (n > 900) n = n;
    if (n > 800) n = n;
    return n;
}

void with_method_sanitizer_many_assign_vuln(size_t len, char *src) {
    size_t sanitized_len = clamp_many_vuln(len);
    char *dst = (char *)malloc(sanitized_len + 1);
    if (!dst) return;
    memcpy(dst, src, sanitized_len);    /* SINK */
    dst[sanitized_len] = '\0';
    free(dst);
}
