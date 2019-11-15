#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

size_t min(size_t a, size_t b) {
    if (a < b) {
        return a;
    } else {
        return b;
    }
}

bool ConsumeBool(const uint8_t **data, size_t *size) {
    if (*size == 0) {
        return false;
    }
    bool result = **data & 1;
    (*data)++;
    (*size)--;
    return result;
}

// Caller must free the result.
char *ConsumeRandomLengthNullTerminatedString(const uint8_t **data, size_t *size, size_t max_length) {
    // Mimics the logic from FuzzedDataProvider.h
    char *result = malloc(min(max_length, *size));
    size_t result_length = 0;
    for (size_t i = 0; i < max_length && *size != 0; i++) {
        char next = **data;
        (*data)++;
        (*size)--;
        if (next == '\\' && *size != 0) {
            next = **data;
            (*data)++;
            (*size)--;
            if (next != '\\') {
                break;
            }
        }
        result[result_length] = next;
        result_length++;
    }

    char *final_result = malloc(result_length + 1);
    memcpy(final_result, result, result_length);
    final_result[result_length] = 0;
    free(result);
    return final_result;
}

// Caller must free the result.
char *ConsumeNullTerminatedString(const uint8_t **data, size_t *size) {
    char *result = malloc(*size + 1);
    memcpy(result, *data, *size);
    result[*size] = 0;

    *data += *size;
    *size = 0;
    return result;
}
