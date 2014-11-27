/*
 * This file Copyright (C) Mnemosyne LLC
 *
 * It may be used under the GNU GPL versions 2 or 3
 * or any future license endorsed by Mnemosyne LLC.
 *
 * $Id$
 */

#include <assert.h>

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h> /* base64 */

#include "transmission.h"
#include "crypto-utils.h"
#include "log.h"
#include "utils.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib") /* base64 */

/***
****
***/

#define MY_NAME "tr_crypto_utils"

static void
log_win32_cng_error (NTSTATUS     error_code,
                     const char * file,
                     int          line)
{
  if (tr_logLevelIsActive (TR_LOG_ERROR))
    {
      char * error_message = tr_win32_format_message_ex (L"ntdll.dll", error_code);
      tr_logAddMessage (file, line, TR_LOG_ERROR, MY_NAME, "Win32 CNG error (0x%08x): %s", error_code,
        error_message == NULL ? "Unknown error." : error_message);
      tr_free (error_message);
    }
}

#define log_error(error_code) log_win32_cng_error(error_code, __FILE__, __LINE__)

static bool
check_win32_cng_result (NTSTATUS     result,
                        const char * file,
                        int          line)
{
  const bool ret = BCRYPT_SUCCESS (result);
  if (!ret)
    log_win32_cng_error (result, file, line);
  return ret;
}

#define check_result(result) check_win32_cng_result ((result), __FILE__, __LINE__)

/***
****
***/

static BCRYPT_ALG_HANDLE
get_named_provider (LPCWSTR name)
{
  BCRYPT_ALG_HANDLE ret;

  if (!check_result (BCryptOpenAlgorithmProvider (&ret, name, MS_PRIMITIVE_PROVIDER, 0)))
    ret = NULL;

  return ret;
}

static BCRYPT_ALG_HANDLE
get_sha1_provider (void)
{
  static BCRYPT_ALG_HANDLE ret = NULL;

  if (ret == NULL)
    ret = get_named_provider (BCRYPT_SHA1_ALGORITHM);

  return ret;
}

static BCRYPT_ALG_HANDLE
get_dh_provider (void)
{
  static BCRYPT_ALG_HANDLE ret = NULL;

  if (ret == NULL)
    ret = get_named_provider (BCRYPT_DH_ALGORITHM);

  return ret;
}

static BCRYPT_ALG_HANDLE
get_rc4_provider (void)
{
  static BCRYPT_ALG_HANDLE ret = NULL;

  if (ret == NULL)
    ret = get_named_provider (BCRYPT_RC4_ALGORITHM);

  return ret;
}

static BCRYPT_ALG_HANDLE
get_rng_provider (void)
{
  static BCRYPT_ALG_HANDLE ret = NULL;

  if (ret == NULL)
    ret = get_named_provider (BCRYPT_RNG_ALGORITHM);

  return ret;
}

/***
****
***/

tr_sha1_ctx_t
tr_sha1_init (void)
{
  BCRYPT_HASH_HANDLE ret;

  if (!check_result (BCryptCreateHash (get_sha1_provider (), &ret, NULL, 0, NULL, 0, 0)))
    ret = NULL;

  return ret;
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

  return check_result (BCryptHashData (handle, (PUCHAR) data, data_length, 0));
}

bool
tr_sha1_final (tr_sha1_ctx_t   handle,
               uint8_t       * hash)
{
  bool ret = true;

  if (hash != NULL)
    {
      assert (handle != NULL);

      ret = check_result (BCryptFinishHash (handle, hash, SHA_DIGEST_LENGTH, 0));
    }

  BCryptDestroyHash (handle);
  return ret;
}

/***
****
***/

tr_rc4_ctx_t
tr_rc4_new (void)
{
  return tr_new0 (BCRYPT_KEY_HANDLE, 1);
}

void
tr_rc4_free (tr_rc4_ctx_t raw_handle)
{
  BCRYPT_KEY_HANDLE * handle = raw_handle;

  if (handle == NULL)
    return;

  BCryptDestroyKey (*handle);
  tr_free (handle);
}

void
tr_rc4_set_key (tr_rc4_ctx_t    raw_handle,
                const uint8_t * key,
                size_t          key_length)
{
  BCRYPT_KEY_HANDLE * handle = raw_handle;

  assert (handle != NULL);
  assert (key != NULL);

  if (*handle != NULL)
    BCryptDestroyKey (*handle);

  if (!check_result (BCryptGenerateSymmetricKey (get_rc4_provider (), handle, NULL, 0,
                                                 (PUCHAR) key, key_length, 0)))
    *handle = NULL;
}

void
tr_rc4_process (tr_rc4_ctx_t   raw_handle,
                const void   * input,
                void         * output,
                size_t         length)
{
  BCRYPT_KEY_HANDLE * handle = raw_handle;
  DWORD len;

  assert (handle != NULL);

  if (length == 0)
    return;

  assert (input != NULL);
  assert (output != NULL);

  check_result (BCryptEncrypt (*handle, (PUCHAR) input, length, NULL, NULL, 0,
                               output, length, &len, 0));
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
  BCRYPT_KEY_HANDLE ret;
  const size_t key_length = prime_num_length;
  DWORD params_size = sizeof (BCRYPT_DH_PARAMETER_HEADER) + key_length * 2;
  BCRYPT_DH_PARAMETER_HEADER * params;
  uint8_t * tmp;

  assert (prime_num != NULL);
  assert (generator_num != NULL);

  if (!check_result (BCryptGenerateKeyPair (get_dh_provider (), &ret, key_length * 8, 0)))
    return NULL;

  params = tr_malloc0 (params_size);

  params->cbLength = params_size;
  params->dwMagic = BCRYPT_DH_PARAMETERS_MAGIC;
  params->cbKeyLength = key_length;

  tmp = (uint8_t *) (params + 1);
  memcpy (tmp + key_length - prime_num_length, prime_num, prime_num_length);

  tmp += key_length;
  memcpy (tmp + key_length - generator_num_length, generator_num, generator_num_length);

  if (!check_result (BCryptSetProperty (ret, BCRYPT_DH_PARAMETERS, (PUCHAR) params, params_size, 0)))
    {
      BCryptDestroyKey (ret);
      ret = NULL;
    }

  tr_free (params);

  return ret;
}

void
tr_dh_free (tr_dh_ctx_t handle)
{
  if (handle == NULL)
    return;

  BCryptDestroyKey (handle);
}

bool
tr_dh_make_key (tr_dh_ctx_t   handle,
                size_t        private_key_length,
                uint8_t     * public_key,
                size_t      * public_key_length)
{
  bool ret = false;

  assert (handle != NULL);
  assert (public_key != NULL);

  if (check_result (BCryptFinalizeKeyPair (handle, 0)))
    {
      DWORD blob_size;
      if (check_result (BCryptExportKey (handle, NULL, BCRYPT_DH_PUBLIC_BLOB, NULL, 0, &blob_size, 0)))
        {
          BCRYPT_DH_KEY_BLOB * blob = tr_malloc (blob_size);
          if (check_result (BCryptExportKey (handle, NULL, BCRYPT_DH_PUBLIC_BLOB,
                                             (PUCHAR) blob, blob_size, &blob_size, 0)))
            {
              memcpy (public_key, (const uint8_t *) (blob + 1) + blob->cbKey * 2, blob->cbKey);
              if (public_key_length != NULL)
                *public_key_length = blob->cbKey;
              ret = true;
            }
        }
    }

  return false;
}

tr_dh_secret_t
tr_dh_agree (tr_dh_ctx_t     handle,
             const uint8_t * other_public_key,
             size_t          other_public_key_length)
{
  BCRYPT_SECRET_HANDLE ret = NULL;
  DWORD blob_size;
  BCRYPT_KEY_HANDLE public_key;

  assert (handle != NULL);
  assert (other_public_key != NULL);

  if (check_result (BCryptExportKey (handle, NULL, BCRYPT_DH_PUBLIC_BLOB, NULL, 0, &blob_size, 0)))
    {
      PBCRYPT_DH_KEY_BLOB blob = tr_malloc0 (blob_size);
      if (check_result (BCryptExportKey (handle, NULL, BCRYPT_DH_PUBLIC_BLOB,
                                         (PUCHAR) blob, blob_size, &blob_size, 0)))
        {
          memcpy ((uint8_t *) (blob + 1) + blob->cbKey * 3 - other_public_key_length,
                  other_public_key, other_public_key_length);

          if (check_result (BCryptImportKeyPair (get_dh_provider (), NULL, BCRYPT_DH_PUBLIC_BLOB,
                                                 &public_key, (PUCHAR) blob, blob_size, 0)))
            {
              if (!check_result (BCryptSecretAgreement (handle, public_key, &ret, 0)))
                ret = NULL;

              BCryptDestroyKey (public_key);
            }
        }

      tr_free (blob);
    }

  return ret;
}

bool
tr_dh_secret_derive (tr_dh_secret_t   handle,
                     const void     * prepend_data,
                     size_t           prepend_data_size,
                     const void     * append_data,
                     size_t           append_data_size,
                     uint8_t        * hash)
{
  BCryptBufferDesc params_desc;
  BCryptBuffer params[3];
  DWORD hash_size;

  assert (handle != NULL);
  assert (hash != NULL);

  params_desc.ulVersion = BCRYPTBUFFER_VERSION;
  params_desc.cBuffers = 0;
  params_desc.pBuffers = params;

  params[params_desc.cBuffers].cbBuffer = (wcslen (BCRYPT_SHA1_ALGORITHM) + 1) * sizeof (WCHAR);
  params[params_desc.cBuffers].BufferType = KDF_HASH_ALGORITHM;
  params[params_desc.cBuffers].pvBuffer = BCRYPT_SHA1_ALGORITHM;
  ++params_desc.cBuffers;

  if (prepend_data != NULL)
    {
      params[params_desc.cBuffers].cbBuffer = prepend_data_size;
      params[params_desc.cBuffers].BufferType = KDF_SECRET_PREPEND;
      params[params_desc.cBuffers].pvBuffer = (PVOID) prepend_data;
      ++params_desc.cBuffers;
    }

  if (append_data != NULL)
    {
      params[params_desc.cBuffers].cbBuffer = append_data_size;
      params[params_desc.cBuffers].BufferType = KDF_SECRET_APPEND;
      params[params_desc.cBuffers].pvBuffer = (PVOID) append_data;
      ++params_desc.cBuffers;
    }

  return check_result (BCryptDeriveKey (handle, BCRYPT_KDF_HASH, &params_desc, hash,
                                        SHA_DIGEST_LENGTH, &hash_size, 0));
}

void
tr_dh_secret_free (tr_dh_secret_t handle)
{
  if (handle == NULL)
    return;

  BCryptDestroySecret (handle);
}

/***
****
***/

bool
tr_rand_buffer (void   * buffer,
                size_t   length)
{
  assert (buffer != NULL);

  return check_result (BCryptGenRandom (get_rng_provider (), buffer, length, 0));
}

/***
****
***/

void *
tr_base64_encode_impl (const void * input,
                       size_t       input_length,
                       size_t     * output_length)
{
  char * ret = NULL;
  DWORD ret_length = 0;

  assert (input != NULL);
  assert (input_length > 0);

  if (!CryptBinaryToStringA (input, input_length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                             NULL, &ret_length))
    return NULL;

  ret = tr_new (char, ret_length + 1);

  if (!CryptBinaryToStringA (input, input_length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                             ret, &ret_length))
    {
      tr_free (ret);
      return NULL;
    }

  ret[ret_length] = '\0';

  if (output_length != NULL)
    *output_length = ret_length;

  return ret;
}

void *
tr_base64_decode_impl (const void * input,
                       size_t       input_length,
                       size_t     * output_length)
{
  char * ret = NULL;
  DWORD ret_length = 0;

  assert (input != NULL);
  assert (input_length > 0);

  if (!CryptStringToBinaryA (input, input_length, CRYPT_STRING_BASE64,
                             NULL, &ret_length, NULL, NULL))
    return NULL;

  ret = tr_new (char, ret_length + 1);

  if (!CryptStringToBinaryA (input, input_length, CRYPT_STRING_BASE64,
                             ret, &ret_length, NULL, NULL))
    {
      tr_free (ret);
      return NULL;
    }

  ret[ret_length] = '\0';

  if (output_length != NULL)
    *output_length = ret_length;

  return ret;
}
