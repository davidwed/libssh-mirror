/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2014 by Aris Adamantiadis <aris@badcode.be>
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"

#include <stdio.h>

#include "libssh/priv.h"
#include "libssh/bignum.h"
#include "libssh/string.h"

static ssh_string make_bignum_string(bignum num, int add_padding) {
  ssh_string ptr = NULL;
  size_t pad = 0;
  size_t len = bignum_num_bytes(num);
  size_t bits = bignum_num_bits(num);

  if (len == 0) {
      return NULL;
  }

  /* If the first bit is set we have a negative number */
  if (add_padding && !(bits % 8) && bignum_is_bit_set(num, bits - 1)) {
    pad++;
  }

#ifdef DEBUG_CRYPTO
  SSH_LOG(SSH_LOG_TRACE,
          "%zu bits, %zu bytes, %zu padding",
          bits, len, pad);
#endif /* DEBUG_CRYPTO */

  ptr = ssh_string_new(len + pad);
  if (ptr == NULL) {
    return NULL;
  }

  /* We have a negative number so we need a leading zero */
  if (pad) {
    ptr->data[0] = 0;
  }

  bignum_bn2bin(num, len, ptr->data + pad);

  return ptr;
}

ssh_string ssh_make_bignum_string(bignum num)
{
    return make_bignum_string (num, 1);
}

ssh_string ssh_make_unpadded_bignum_string(bignum num)
{
    return make_bignum_string (num, 0);
}

bignum ssh_make_string_bn(ssh_string string)
{
    bignum bn = NULL;
    size_t len = ssh_string_len(string);

#ifdef DEBUG_CRYPTO
    SSH_LOG(SSH_LOG_TRACE,
            "Importing a %zu bits, %zu bytes object ...",
            len * 8, len);
#endif /* DEBUG_CRYPTO */

    bignum_bin2bn(string->data, len, &bn);

    return bn;
}

/* prints the bignum on stderr */
void ssh_print_bignum(const char *name, const_bignum num)
{
    unsigned char *hex = NULL;
    if (num != NULL) {
        bignum_bn2hex(num, &hex);
    }
    SSH_LOG(SSH_LOG_DEBUG, "%s value: %s", name,
            (hex == NULL) ? "(null)" : (char *)hex);
    ssh_crypto_free(hex);
}
