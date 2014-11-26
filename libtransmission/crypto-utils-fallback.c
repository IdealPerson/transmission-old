/*
 * This file Copyright (C) Mnemosyne LLC
 *
 * It may be used under the GNU GPL versions 2 or 3
 * or any future license endorsed by Mnemosyne LLC.
 *
 * $Id$
 */

#include <assert.h>

#include "transmission.h"
#include "crypto-utils.h"
#include "utils.h"

/***
****
***/

#ifdef TR_CRYPTO_DH_SECRET_FALLBACK

struct tr_dh_secret
{
  size_t  key_length;
  uint8_t key[];
};

static struct tr_dh_secret *
tr_dh_secret_new (size_t key_length)
{
  struct tr_dh_secret * handle = tr_malloc (sizeof (struct tr_dh_secret) + key_length);
  handle->key_length = key_length;
  return handle;
}

static void
tr_dh_secret_align (struct tr_dh_secret * handle,
                    size_t                current_key_length)
{
  tr_dh_align_key (handle->key, current_key_length, handle->key_length);
}

bool
tr_dh_secret_derive (tr_dh_secret_t   raw_handle,
                     const void     * prepend_data,
                     size_t           prepend_data_size,
                     const void     * append_data,
                     size_t           append_data_size,
                     uint8_t        * hash)
{
  struct tr_dh_secret * handle = raw_handle;
  tr_sha1_ctx_t sha = tr_sha1_init ();

  assert (handle != NULL);
  assert (hash != NULL);

  if (sha == NULL)
    return false;

  if (prepend_data != NULL &&
      !tr_sha1_update (sha, prepend_data, prepend_data_size))
    goto fail;

  if (!tr_sha1_update (sha, handle->key, handle->key_length))
    goto fail;

  if (append_data != NULL &&
      !tr_sha1_update (sha, append_data, append_data_size))
    goto fail;

  return tr_sha1_final (sha, hash);

fail:
  tr_sha1_final (sha, NULL);
  return false;
}

void
tr_dh_secret_free (tr_dh_secret_t handle)
{
  if (handle == NULL)
    return;

  tr_free (handle);
}

#endif /* TR_CRYPTO_DH_SECRET_FALLBACK */
