/*
 * This file Copyright (C) Mnemosyne LLC
 *
 * It may be used under the GNU GPL versions 2 or 3
 * or any future license endorsed by Mnemosyne LLC.
 *
 * $Id$
 */

#include <assert.h>

#ifdef HAVE_COMMONCRYPTO_COMMONBIGNUM_H
#include <CommonCrypto/CommonBigNum.h>
#endif
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>
/* #include <CommonCrypto/CommonRandom.h> */

#include "transmission.h"
#include "crypto-utils.h"
#include "log.h"
#include "utils.h"

#define TR_CRYPTO_DH_SECRET_FALLBACK
#define TR_CRYPTO_BASE64_FALLBACK
#include "crypto-utils-fallback.c"

/***
****
***/

#ifndef HAVE_COMMONCRYPTO_COMMONBIGNUM_H

/* 10.8+ */
typedef struct _CCBigNumRef * CCBigNumRef;
typedef CCCryptorStatus CCStatus;

extern CCBigNumRef CCBigNumFromData      (CCStatus          * status,
                                          const void        * s,
                                          size_t              len);
extern CCBigNumRef CCCreateBigNum        (CCStatus          * status);
extern CCBigNumRef CCBigNumCreateRandom  (CCStatus          * status,
                                          int                 bits,
                                          int                 top,
                                          int                 bottom);
extern void        CCBigNumFree          (CCBigNumRef         bn);
extern CCStatus    CCBigNumModExp        (CCBigNumRef         result,
                                          const CCBigNumRef   a,
                                          const CCBigNumRef   power,
                                          const CCBigNumRef   modulus);
extern uint32_t    CCBigNumByteCount     (const CCBigNumRef   bn);
extern size_t      CCBigNumToData        (CCStatus          * status,
                                          const CCBigNumRef   bn,
                                          void              * to);

#endif /* !HAVE_COMMONCRYPTO_COMMONBIGNUM_H */

/* 10.7+ */
typedef struct __CCRandom *CCRandomRef;
extern CCRandomRef kCCRandomDefault __attribute__((weak_import));
extern CCRandomRef kCCRandomDevRandom __attribute__((weak_import));

extern int         CCRandomCopyBytes     (CCRandomRef         rnd,
                                          void              * bytes,
                                          size_t              count) __attribute__((weak_import));

/* 10.10+ */
typedef CCCryptorStatus CCRNGStatus;

extern CCRNGStatus CCRandomGenerateBytes (void              * bytes,
                                          size_t              count) __attribute__((weak_import));

/***
****
***/

#define MY_NAME "tr_crypto_utils"

static void
log_commoncrypto_error (CCCryptorStatus   error_code,
                        const char      * file,
                        int               line)
{
  if (tr_logLevelIsActive (TR_LOG_ERROR))
    {
      const char * error_message;

      switch (error_code)
        {
          case kCCSuccess:        error_message = "Operation completed normally."; break;
          case kCCParamError:     error_message = "Illegal parameter value."; break;
          case kCCBufferTooSmall: error_message = "Insufficent buffer provided for specified operation."; break;
          case kCCMemoryFailure:  error_message = "Memory allocation failure."; break;
          case kCCAlignmentError: error_message = "Input size was not aligned properly."; break;
          case kCCDecodeError:    error_message = "Input data did not decode or decrypt properly."; break;
          case kCCUnimplemented:  error_message = "Function not implemented for the current algorithm."; break;
          case kCCOverflow:       error_message = "Buffer overflow."; break;
          case kCCRNGFailure:     error_message = "Random number generator failure."; break;
          default:                error_message = "Unknown error."; break;
        }

      tr_logAddMessage (file, line, TR_LOG_ERROR, MY_NAME, "CommonCrypto error (%d): %s", error_code, error_message);
    }
}

static bool
check_commoncrypto_result (CCCryptorStatus   result,
                           const char      * file,
                           int               line)
{
  const bool ret = result == kCCSuccess;
  if (!ret)
    log_commoncrypto_error (result, file, line);
  return ret;
}

#define check_result(result) check_commoncrypto_result ((result), __FILE__, __LINE__)

static bool
check_commoncrypto_pointer (const void            * pointer,
                            const CCCryptorStatus * result,
                            const char            * file,
                            int                     line)
{
  const bool ret = pointer != NULL;
  if (!ret)
    log_commoncrypto_error (*result, file, line);
  return ret;
}

#define check_pointer(pointer, result) check_commoncrypto_pointer ((pointer), (result), __FILE__, __LINE__)

/***
****
***/

struct tr_dh_ctx
{
  CCBigNumRef p;
  CCBigNumRef g;
  CCBigNumRef private_key;
};

/***
****
***/

tr_sha1_ctx_t
tr_sha1_init (void)
{
  CC_SHA1_CTX * handle = tr_new0 (CC_SHA1_CTX, 1);
  CC_SHA1_Init (handle);
  return handle;
}

bool
tr_sha1_update (tr_sha1_ctx_t   handle,
                const void    * data,
                size_t          data_length)
{
  assert (handle != NULL);

  if (data_length == 0)
    return;

  assert (data != NULL);

  CC_SHA1_Update (handle, data, data_length);
  return true;
}

bool
tr_sha1_final (tr_sha1_ctx_t   handle,
               uint8_t       * hash)
{
  if (hash != NULL)
    {
      assert (handle != NULL);

      CC_SHA1_Final (hash, handle);
    }

  tr_free (handle);
  return true;
}

/***
****
***/

tr_rc4_ctx_t
tr_rc4_new (void)
{
  return tr_new0 (CCCryptorRef, 1);
}

void
tr_rc4_free (tr_rc4_ctx_t raw_handle)
{
  CCCryptorRef * handle = raw_handle;

  if (handle == NULL)
    return;

  if (*handle != NULL)
    CCCryptorRelease(*handle);
  tr_free (handle);
}

void
tr_rc4_set_key (tr_rc4_ctx_t    raw_handle,
                const uint8_t * key,
                size_t          key_length)
{
  CCCryptorRef * handle = raw_handle;

  assert (handle != NULL);
  assert (key != NULL);

  check_result (CCCryptorCreate (kCCEncrypt, kCCAlgorithmRC4, 0, key, key_length, NULL, handle));
}

void
tr_rc4_process (tr_rc4_ctx_t   raw_handle,
                const void   * input,
                void         * output,
                size_t         length)
{
  CCCryptorRef * handle = raw_handle;

  assert (handle != NULL);

  if (length == 0)
    return;

  assert (input != NULL);
  assert (output != NULL);

  check_result (CCCryptorUpdate (*handle, input, length, output, length, NULL));
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
  CCStatus status;

  assert (prime_num != NULL);
  assert (generator_num != NULL);

  if (!check_pointer ((handle->p = CCBigNumFromData (&status, prime_num, prime_num_length)), &status) ||
      !check_pointer ((handle->g = CCBigNumFromData (&status, generator_num, generator_num_length)), &status))
    {
      tr_dh_free (handle);
      return NULL;
    }

  return handle;
}

void
tr_dh_free (tr_dh_ctx_t raw_handle)
{
  struct tr_dh_ctx * handle = raw_handle;

  if (handle == NULL)
    return;

  if (handle->p != NULL)
    CCBigNumFree (handle->p);
  if (handle->g != NULL)
    CCBigNumFree (handle->g);
  if (handle->private_key != NULL)
    CCBigNumFree (handle->private_key);
  tr_free (handle);
}

bool
tr_dh_make_key (tr_dh_ctx_t   raw_handle,
                size_t        private_key_length,
                uint8_t     * public_key,
                size_t      * public_key_length)
{
  struct tr_dh_ctx * handle = raw_handle;
  bool ret = false;
  CCStatus status;
  CCBigNumRef my_public_key;
  uint32_t my_public_key_length;
  const uint32_t dh_size = CCBigNumByteCount (handle->p);

  assert (handle != NULL);
  assert (public_key != NULL);

  if (handle->private_key != NULL)
    CCBigNumFree (handle->private_key);

  if (!check_pointer ((handle->private_key = CCBigNumCreateRandom (&status, private_key_length * 8, private_key_length * 8, 0)), &status))
    return false;

  if (!check_pointer ((my_public_key = CCCreateBigNum (&status)), &status))
    goto cleanup;

  if (!check_result (CCBigNumModExp (my_public_key, handle->g, handle->private_key, handle->p)))
    goto cleanup;

  my_public_key_length = CCBigNumByteCount (my_public_key);
  CCBigNumToData (&status, my_public_key, public_key);
  if (!check_result (status))
    goto cleanup;

  tr_dh_align_key (public_key, my_public_key_length, dh_size);

  if (public_key_length != NULL)
    *public_key_length = dh_size;

  ret = true;

cleanup:
  if (my_public_key != NULL)
    CCBigNumFree (my_public_key);

  return ret;
}

tr_dh_secret_t
tr_dh_agree (tr_dh_ctx_t     raw_handle,
             const uint8_t * other_public_key,
             size_t          other_public_key_length)
{
  struct tr_dh_ctx * handle = raw_handle;
  struct tr_dh_secret * ret = NULL;
  CCStatus status;
  CCBigNumRef other_key, my_secret_key = NULL;
  uint32_t my_secret_key_length;
  const uint32_t dh_size = CCBigNumByteCount (handle->p);

  assert (handle != NULL);
  assert (other_public_key != NULL);

  if (!check_pointer ((other_key = CCBigNumFromData (&status, other_public_key, other_public_key_length)), &status))
    goto cleanup;

  if (!check_pointer ((my_secret_key = CCCreateBigNum (&status)), &status))
    goto cleanup;

  if (!check_result (CCBigNumModExp (my_secret_key, other_key, handle->private_key, handle->p)))
    goto cleanup;

  ret = tr_dh_secret_new (dh_size);

  my_secret_key_length = CCBigNumByteCount (my_secret_key);
  CCBigNumToData (&status, my_secret_key, ret->key);
  if (!check_result (status))
    goto cleanup;

  tr_dh_secret_align (ret, my_secret_key_length);

cleanup:
  if (my_secret_key != NULL)
    CCBigNumFree (my_secret_key);

  if (other_key != NULL)
    CCBigNumFree (other_key);

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

  /* 10.10+ */
  if (CCRandomGenerateBytes != NULL)
    return check_result (CCRandomGenerateBytes (buffer, length));

  /* 10.7+ */
  if (CCRandomCopyBytes != NULL)
    return CCRandomCopyBytes (kCCRandomDefault, buffer, length) == 0 ||
           CCRandomCopyBytes (kCCRandomDevRandom, buffer, length) == 0;

  return false;
}
