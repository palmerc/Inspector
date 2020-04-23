#include "utils.h"


char *format_bytes_as_hex(void *ptr, int size) {
    uint8_t *source = (uint8_t *)ptr;
    char *result = malloc(2 * size + 1);
    for (int i = 0; i < size; i++)
        sprintf(&result[i * 2], "%02X", source[i]);
    result[size * 2] = 0;
    
    return result;
}

char *format_canonical_uuid(const uint8_t uuid[16]) {
    char *uuid_str = malloc(sizeof(char) * (16 * 2 + 4 + 1));
    uint32_t position = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t value = uuid[i];
        position += sprintf(&uuid_str[position], "%02X", value);
        if (i == 3 || i == 5 || i == 7 || i == 9)
            uuid_str[position++] = '-';
    }
    uuid_str[position] = 0;
    
    return uuid_str;
}
