/*
 * Test case for "syntactic sanitizer" that is NOT a method call.
 *
 * Scenario: A bare conditional (if (len > MAX)) looks like a check, but the
 * "bad" branch only logs and falls through—execution still reaches memcpy
 * with the tainted `len`. So the check is cosmetic; the flow is UNSANITIZED.
 *
 * Source: parameter `len` (or `src`)
 * "Syntactic sanitizer": if (len > MAX) log(...)  -- not a sanitizer method
 * Sink: memcpy(dst, src, len)
 *
 * Expected (current Joern): flow from len/src to memcpy is FOUND, because
 * the engine does NOT treat the bare conditional as a sanitizer.
 */

#define MAX 1024

extern void log_msg(const char*);
extern void* malloc(unsigned long);
extern void memcpy(void*, const void*, unsigned long);
extern void free(void*);

typedef unsigned long size_t;

void vulnerable(size_t len, char *src) {
    char *dst = (char *)malloc(len + 1);
    if (!dst) return;

    /* Cosmetic check: we "check" len but the bad branch only logs and
       execution continues; len is still tainted when we reach memcpy. */
    if (len > MAX) {
        log_msg("len too large");
    }

    memcpy(dst, src, len);  /* SINK: tainted len and src reach here */
    dst[len] = '\0';
    free(dst);
}
