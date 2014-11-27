/*
 * This file Copyright (C) Mnemosyne LLC
 *
 * It may be used under the GNU GPL versions 2 or 3
 * or any future license endorsed by Mnemosyne LLC.
 *
 * $Id$
 */

#include <assert.h>

#ifdef _WIN32
 #define WIN32
#else
 #define POSIX
#endif
#include <matrixssl/crypto/cryptoApi.h>

#include "transmission.h"
#include "crypto-utils.h"
#include "log.h"
#include "utils.h"

#define TR_CRYPTO_DH_SECRET_FALLBACK
#define TR_CRYPTO_BASE64_FALLBACK
#include "crypto-utils-fallback.c"

struct tr_dh_ctx
{
  const uint8_t * p;
  size_t          p_len;
  const uint8_t * g;
  size_t          g_len;
  psDhKey_t       key_pair;
};

/***
****
***/

#define MY_NAME "tr_crypto_utils"

static void
log_matrixssl_error (int          error_code,
                     const char * file,
                     int          line)
{
  if (tr_logLevelIsActive (TR_LOG_ERROR))
    {
      const char * error_message;

      switch (error_code)
        {
          /* core */
          case PS_SUCCESS:               error_message = "Success."; break;
          case PS_FAILURE:               error_message = "Generic error."; break;
          case PS_ARG_FAIL:              error_message = "Invalid function argument."; break;
          case PS_PLATFORM_FAIL:         error_message = "System call error."; break;
          case PS_MEM_FAIL:              error_message = "Not enough memory."; break;
          case PS_LIMIT_FAIL:            error_message = "Sanity check failure."; break;
          case PS_UNSUPPORTED_FAIL:      error_message = "Feature is not supported."; break;
          case PS_DISABLED_FEATURE_FAIL: error_message = "Feature is disabled."; break;
          case PS_PROTOCOL_FAIL:         error_message = "Protocol error."; break;
          case PS_TIMEOUT_FAIL:          error_message = "Timeout occurred."; break;
          case PS_INTERRUPT_FAIL:        error_message = "Interrupt occurred."; break;
          case PS_PENDING:               error_message = "Operation is in progress."; break;
          case PS_EAGAIN:                error_message = "Try again later."; break;
          /* crypto */
          case PS_PARSE_FAIL:            error_message = "Parse error."; break;
          /* unknown */
          default:                       error_message = "Unknown error."; break;
        }

      tr_logAddMessage (file, line, TR_LOG_ERROR, MY_NAME, "MatrixSSL error: %s", error_message);
    }
}

static bool
check_matrixssl_result (int          result,
                        const char * file,
                        int          line)
{
  const bool ret = result >= 0;
  if (!ret)
    log_matrixssl_error (result, file, line);
  return ret;
}

#define check_result(result) check_matrixssl_result ((result), __FILE__, __LINE__)

/***
****
***/

tr_sha1_ctx_t
tr_sha1_init (void)
{
  psDigestContext_t * handle = tr_new (psDigestContext_t, 1);
  psSha1Init (handle);
  return handle;
}

bool
tr_sha1_update (tr_sha1_ctx_t   handle,
                const void    * data,
                size_t          data_length)
{
  assert (handle != NULL);

  if (data_length == 0)
    return true;

  assert (data != NULL);

  psSha1Update (handle, data, data_length);
  return true;
}

bool
tr_sha1_final (tr_sha1_ctx_t   handle,
               uint8_t       * hash)
{
  bool ret = true;

  if (hash != NULL)
    {
      assert (handle != NULL);

      ret = check_result (psSha1Final (handle, hash));
    }

  tr_free (handle);
  return ret;
}

/***
****
***/

tr_rc4_ctx_t
tr_rc4_new (void)
{
  return tr_new0 (psCipherContext_t, 1);
}

void
tr_rc4_free (tr_rc4_ctx_t handle)
{
  tr_free (handle);
}

void
tr_rc4_set_key (tr_rc4_ctx_t    handle,
                const uint8_t * key,
                size_t          key_length)
{
  assert (handle != NULL);
  assert (key != NULL);

  psArc4Init (handle, (uint8_t *) key, key_length);
}

void
tr_rc4_process (tr_rc4_ctx_t   handle,
                const void   * input,
                void         * output,
                size_t         length)
{
  assert (handle != NULL);

  if (length == 0)
    return;

  assert (input != NULL);
  assert (output != NULL);

  check_result (psArc4 (handle, (uint8_t *) input, output, length));
}

/***
****
***/

tr_dh_ctx_t
tr_dh_new (const uint8_t * prime_num,
           size_t          prime_num_length,
           const uint8_t * generator_num,
           size_t          generator_num_length)
{
  struct tr_dh_ctx * handle = tr_new0 (struct tr_dh_ctx, 1);

  assert (prime_num != NULL);
  assert (generator_num != NULL);

  handle->p = prime_num;
  handle->p_len = prime_num_length;
  handle->g = generator_num;
  handle->g_len = generator_num_length;

  return handle;
}

void
tr_dh_free (tr_dh_ctx_t raw_handle)
{
  struct tr_dh_ctx * handle = raw_handle;

  if (handle == NULL)
    return;

  psDhFreeKey (&handle->key_pair);
  tr_free (handle);
}

bool
tr_dh_make_key (tr_dh_ctx_t   raw_handle,
                size_t        private_key_length,
                uint8_t     * public_key,
                size_t      * public_key_length)
{
  struct tr_dh_ctx * handle = raw_handle;

  assert (handle != NULL);
  assert (public_key != NULL);

  if (!check_result (psDhKeyGen (NULL, private_key_length,
                                 (uint8_t *) handle->p, handle->p_len,
                                 (uint8_t *) handle->g, handle->g_len,
                                 &handle->key_pair, NULL)))
    return false;

  if (!check_result (psDhExportPubKey (NULL, &handle->key_pair, &public_key)))
    return false;

  tr_dh_align_key (public_key, pstm_unsigned_bin_size (&handle->key_pair.pub), handle->p_len);

  if (public_key_length != NULL)
    *public_key_length = handle->p_len;

  return true;
}

tr_dh_secret_t
tr_dh_agree (tr_dh_ctx_t     raw_handle,
             const uint8_t * other_public_key,
             size_t          other_public_key_length)
{
  struct tr_dh_ctx * handle = raw_handle;
  struct tr_dh_secret * ret;
  uint32_t my_secret_key_length = handle->p_len;
  psDhKey_t other_key;

  assert (handle != NULL);
  assert (other_public_key != NULL);

  if (!check_result (psDhImportPubKey (NULL, (uint8_t *) other_public_key,
                                       other_public_key_length, &other_key)))
    return NULL;

  ret = tr_dh_secret_new (handle->p_len);

  if (check_result (psDhGenSecret (NULL, &handle->key_pair, &other_key,
                                   (uint8_t *) handle->p, handle->p_len,
                                   ret->key, &my_secret_key_length,
                                   NULL)))
    {
      tr_dh_secret_align (ret, my_secret_key_length);
    }
  else
    {
      tr_dh_secret_free (ret);
      ret = NULL;
    }

  psDhFreeKey (&other_key);

  return ret;
}

/***
****
***/

bool
tr_rand_buffer (void   * buffer,
                size_t   length)
{
  assert (buffer != NULL);

  return check_result (psGetPrng (NULL, buffer, length));
}
