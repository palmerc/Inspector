#ifndef utils_h
#define utils_h

#include <stdio.h>
#include <stdlib.h>


char *format_bytes_as_hex(void *ptr, int size);
char *format_canonical_uuid(const uint8_t uuid[16]);

#endif /* utils_h */
