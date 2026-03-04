/*
 * Contrast: flow through a SANITIZER METHOD.
 *
 * Here we have sanitized_len = clamp(len) or similar. If "clamp" is
 * declared in Semantics as a sanitizer (e.g. doesn't propagate taint
 * from arg to return), then the flow to memcpy(sanitized_len) would
 * be killed at the call. This file is for contrasting with cosmetic_check.c.
 */

#define MAX 1024

extern void* malloc(unsigned long);
extern void memcpy(void*, const void*, unsigned long);
extern void free(void*);

typedef unsigned long size_t;

/* Placeholder: in a real codebase this would be defined and then
   registered in Semantics as a sanitizer (param 0 -> no taint to return). */
size_t clamp(size_t n) {
    return n > MAX ? MAX : n;
}

void with_method_sanitizer(size_t len, char *src) {
    size_t sanitized_len = clamp(len);  /* If clamp is in Semantics as sanitizer, taint stops here */
    char *dst = (char *)malloc(sanitized_len + 1);
    if (!dst) return;
    memcpy(dst, src, sanitized_len);    /* SINK: only sanitized_len flows here */
    dst[sanitized_len] = '\0';
    free(dst);
}
