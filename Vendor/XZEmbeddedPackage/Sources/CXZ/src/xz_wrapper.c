// SPDX-License-Identifier: 0BSD
#include "xz.h"
#include "xz_wrapper.h"

int xz_decompress_to_buffer(
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_length
) {
    if (input == NULL || output == NULL || output_length == NULL) {
        return XZ_DATA_ERROR;
    }

    xz_crc32_init();
    xz_crc64_init();

    struct xz_dec *decoder = xz_dec_init(XZ_SINGLE, 0);
    if (decoder == NULL) {
        return XZ_MEM_ERROR;
    }

    struct xz_buf buffer = {
        .in = input,
        .in_pos = 0,
        .in_size = input_length,
        .out = output,
        .out_pos = 0,
        .out_size = output_capacity,
    };
    enum xz_ret result = xz_dec_run(decoder, &buffer);
    if (result == XZ_STREAM_END && buffer.in_pos == input_length) {
        *output_length = buffer.out_pos;
        result = XZ_OK;
    }
    xz_dec_end(decoder);
    return result;
}
