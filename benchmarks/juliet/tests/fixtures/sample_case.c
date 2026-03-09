#include <string.h>
#include <stdlib.h>

void bad() {
  char *dst = (char *)malloc(10);
  char src[20] = {0};
  memcpy(dst, src, 20);
}

void goodB2G() {
  char *dst = (char *)malloc(20);
  char src[20] = {0};
  memcpy(dst, src, 20);
}

void goodG2B() {
  char *dst = (char *)malloc(20);
  char src[20] = {0};
  memcpy(dst, src, 10);
}
