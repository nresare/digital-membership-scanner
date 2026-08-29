// SPDX-License-Identifier: 0BSD
#ifndef XZ_WRAPPER_H
#define XZ_WRAPPER_H

#include <stddef.h>
#include <stdint.h>

// Returns 0 on success. Any nonzero return value is an XZ Embedded error code.
int xz_decompress_to_buffer(
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_length
);

#endif
