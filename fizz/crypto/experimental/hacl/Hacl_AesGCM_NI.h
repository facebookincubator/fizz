/* MIT License
 *
 * Copyright (c) 2018 INRIA 
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __Hacl_AesGCM_NI_H
#define __Hacl_AesGCM_NI_H

#include <stdlib.h>
#include <string.h>
#include "endianness.h"
#include "vec128.h"

typedef Lib_Vec128_vec128 Hacl_AesGCM_NI_aes_gcm_ctx[22];

void Hacl_AesGCM_NI_aes128_gcm_init(Lib_Vec128_vec128 *ctx, uint8_t *key, uint8_t *nonce);

void
Hacl_AesGCM_NI_aes128_gcm_encrypt(
  Lib_Vec128_vec128 *ctx,
  uint32_t len,
  uint8_t *out,
  uint8_t *text,
  uint32_t aad_len,
  uint8_t *aad
);

bool
Hacl_AesGCM_NI_aes128_gcm_decrypt(
  Lib_Vec128_vec128 *ctx,
  uint32_t len,
  uint8_t *out,
  uint8_t *cipher,
  uint32_t aad_len,
  uint8_t *aad
);

#define __Hacl_AesGCM_NI_H_DEFINED
#endif
