
/*
 * The olsr.org Optimized Link-State Routing daemon version 2 (olsrd2)
 * Copyright (c) 2004-2015, the olsr.org team - see HISTORY file
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of olsr.org, olsrd nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Visit http://www.olsr.org for more information.
 *
 * If you find this software useful feel free to make a donation
 * to the project. For more information see the website or contact
 * the copyright holders.
 *
 */

/**
 * @file
 */

#include <polarssl/config.h>
#ifdef POLARSSL_SHA1_C
#include <polarssl/sha1.h>
#endif
#ifdef POLARSSL_SHA256_C
#include <polarssl/sha256.h>
#endif
#ifdef POLARSSL_SHA512_C
#include <polarssl/sha512.h>
#endif
#include <oonf/oonf.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/crypto/rfc7182_provider/rfc7182_provider.h>
#include <oonf/librfc5444/rfc5444_iana.h>

#include <oonf/crypto/hash_polarssl/hash_polarssl.h>

#define LOG_HASH_POLARSSL _hash_polarssl_subsystem.logging

/* function prototypes */
static int _init(void);
static void _cleanup(void);

#ifdef POLARSSL_SHA1_C
static int _cb_sha1_hash(struct rfc7182_hash *hash, void *dst, size_t *dst_len, const void *src, size_t src_len);
#endif
#ifdef POLARSSL_SHA1_C
static int _cb_sha256_hash(struct rfc7182_hash *hash, void *dst, size_t *dst_len, const void *src, size_t src_len);
#endif
#ifdef POLARSSL_SHA1_C
static int _cb_sha512_hash(struct rfc7182_hash *hash, void *dst, size_t *dst_len, const void *src, size_t src_len);
#endif
static size_t _cb_get_signsize(struct rfc7182_crypt *crpyt, struct rfc7182_hash *hash);
static int _cb_hmac_sign(struct rfc7182_crypt *crypt, struct rfc7182_hash *hash, void *dst, size_t *dst_len,
  const void *src, size_t src_len, const void *key, size_t key_len);

/* hash tomcrypt subsystem definition */
static const char *_dependencies[] = {
  OONF_RFC7182_PROVIDER_SUBSYSTEM,
};
static struct oonf_subsystem _hash_polarssl_subsystem = {
  .name = OONF_HASH_POLARSSL_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "RFC5444 hash/hmac functions libpolarssl plugin",
  .author = "Henning Rogge",

  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_hash_polarssl_subsystem);

/* definition for all sha1/2 hashes */
static struct rfc7182_hash _hashes[] = {
#ifdef POLARSSL_SHA1_C
  {
    .type = RFC7182_ICV_HASH_SHA_1,
    .hash = _cb_sha1_hash,
    .hash_length = 160 / 8,
  },
#endif
#ifdef POLARSSL_SHA1_C
  {
    .type = RFC7182_ICV_HASH_SHA_224,
    .hash = _cb_sha256_hash,
    .hash_length = 224 / 8,
  },
  {
    .type = RFC7182_ICV_HASH_SHA_256,
    .hash = _cb_sha256_hash,
    .hash_length = 256 / 8,
  },
#endif
#ifdef POLARSSL_SHA1_C
  {
    .type = RFC7182_ICV_HASH_SHA_384,
    .hash = _cb_sha512_hash,
    .hash_length = 384 / 8,
  },
  {
    .type = RFC7182_ICV_HASH_SHA_512,
    .hash = _cb_sha512_hash,
    .hash_length = 512 / 8,
  },
#endif
};

/* definition of hmac crypto function */
static struct rfc7182_crypt _hmac = {
  .type = RFC7182_ICV_CRYPT_HMAC,
  .sign = _cb_hmac_sign,
  .getSignSize = _cb_get_signsize,
};

/**
 * Constructor for subsystem
 * @return always 0
 */
static int
_init(void) {
  size_t i;

  /* register hashes with rfc5444 signature API */
  for (i = 0; i < ARRAYSIZE(_hashes); i++) {
    OONF_INFO(LOG_HASH_POLARSSL, "Add %s hash to rfc7182 API", rfc7182_get_hash_name(_hashes[i].type));
    rfc7182_add_hash(&_hashes[i]);
  }

  rfc7182_add_crypt(&_hmac);
  OONF_INFO(LOG_HASH_POLARSSL, "Add hmac to rfc7182 API");
  return 0;
}

/**
 * Destructor of subsystem
 */
static void
_cleanup(void) {
  size_t i;

  /* register hashes with rfc5444 signature API */
  for (i = 0; i < ARRAYSIZE(_hashes); i++) {
    rfc7182_remove_hash(&_hashes[i]);
  }

  rfc7182_remove_crypt(&_hmac);
}

#ifdef POLARSSL_SHA1_C
/**
 * SHA1 hash implementation based on libpolarssl
 * @param hash rfc7182 hash
 * @param dst output buffer for hash
 * @param dst_len pointer to length of output buffer,
 *   will be set to hash length afterwards
 * @param src original data to hash
 * @param src_len length of original data
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_sha1_hash(struct rfc7182_hash *hash, void *dst, size_t *dst_len, const void *src, size_t src_len) {
  sha1(src, (unsigned long)src_len, dst);
  *dst_len = hash->hash_length;
  return 0;
}
#endif

#ifdef POLARSSL_SHA256_C
/**
 * SHA224/256 hash implementation based on libpolarssl
 * @param sig rfc5444 signature
 * @param dst output buffer for hash
 * @param dst_len pointer to length of output buffer,
 *   will be set to hash length afterwards
 * @param src original data to hash
 * @param src_len length of original data
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_sha256_hash(struct rfc7182_hash *hash, void *dst, size_t *dst_len, const void *src, size_t src_len) {
  sha256(src, (unsigned long)src_len, dst, hash->type == RFC7182_ICV_HASH_SHA_224 ? 1 : 0);
  *dst_len = hash->hash_length;
  return 0;
}
#endif

#ifdef POLARSSL_SHA512_C
/**
 * SHA384/512 hash implementation based on libpolarssl
 * @param sig rfc5444 signature
 * @param dst output buffer for hash
 * @param dst_len pointer to length of output buffer,
 *   will be set to hash length afterwards
 * @param src original data to hash
 * @param src_len length of original data
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_sha512_hash(struct rfc7182_hash *hash, void *dst, size_t *dst_len, const void *src, size_t src_len) {
  sha512(src, (unsigned long)src_len, dst, hash->type == RFC7182_ICV_HASH_SHA_384 ? 1 : 0);
  *dst_len = hash->hash_length;
  return 0;
}
#endif

/**
 * @param crypt rfc7182 crypt
 * @param hash rfc7182 hash
 * @return length of signature based on chosen hash
 */
static size_t
_cb_get_signsize(struct rfc7182_crypt *crypt __attribute__((unused)), struct rfc7182_hash *hash) {
  return hash->hash_length;
}

/**
 * HMAC function based on libtomcrypt
 * @param crypt rfc7182 crypt
 * @param hash rfc7182 hash
 * @param dst output buffer for signature
 * @param dst_len pointer to length of output buffer,
 *   will be set to signature length afterwards
 * @param src unsigned original data
 * @param src_len length of original data
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_hmac_sign(struct rfc7182_crypt *crypt __attribute__((unused)), struct rfc7182_hash *hash, void *dst,
  size_t *dst_len, const void *src, size_t src_len, const void *key, size_t key_len) {
  OONF_DEBUG_HEX(LOG_HASH_POLARSSL, src, src_len, "Calculate hash:");

  switch (hash->type) {
#ifdef POLARSSL_SHA1_C
    case RFC7182_ICV_HASH_SHA_1:
      sha1_hmac(key, key_len, src, src_len, dst);
      break;
#endif
#ifdef POLARSSL_SHA256_C
    case RFC7182_ICV_HASH_SHA_224:
      sha256_hmac(key, key_len, src, src_len, dst, 1);
      break;
    case RFC7182_ICV_HASH_SHA_256:
      sha256_hmac(key, key_len, src, src_len, dst, 0);
      break;
#endif
#ifdef POLARSSL_SHA512_C
    case RFC7182_ICV_HASH_SHA_384:
      sha512_hmac(key, key_len, src, src_len, dst, 1);
      break;
    case RFC7182_ICV_HASH_SHA_512:
      sha512_hmac(key, key_len, src, src_len, dst, 0);
      break;
#endif
    default:
      return -1;
  }

  *dst_len = hash->hash_length;
  return 0;
}
