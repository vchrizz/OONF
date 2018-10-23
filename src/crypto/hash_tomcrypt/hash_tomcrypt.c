
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

#include <tomcrypt.h>

#include <oonf/oonf.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/crypto/rfc5444_signature/rfc5444_signature.h>
#include <oonf/librfc5444/rfc5444_iana.h>

#include <oonf/crypto/hash_tomcrypt/hash_tomcrypt.h>

#define LOG_HASH_TOMCRYPT _hash_tomcrypt_subsystem.logging

/**
 * Libtomcrypt extension for hash definition
 */
struct tomcrypt_hash {
  /*! rfc7182 hash provider */
  struct rfc7182_hash h;

  /*! tomcrypt string id of hash */
  const char *tomcrypt_name;

  /*! tomcrypt index of hash */
  int idx;
};

/* function prototypes */
static int _init(void);
static void _cleanup(void);

static int _cb_sha_hash(struct rfc7182_hash *hash, void *dst, size_t *dst_len, const void *src, size_t src_len);
static size_t _cb_get_cryptsize(struct rfc7182_crypt *, struct rfc7182_hash *);
static int _cb_hmac_sign(struct rfc7182_crypt *, struct rfc7182_hash *, void *dst, size_t *dst_len, const void *src,
  size_t src_len, const void *key, size_t key_len);

/* hash tomcrypt subsystem definition */
static const char *_dependencies[] = {
  OONF_RFC7182_PROVIDER_SUBSYSTEM,
};
static struct oonf_subsystem _hash_tomcrypt_subsystem = {
  .name = OONF_HASH_TOMCRYPT_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "RFC5444 hash/hmac functions libtomcrypt plugin",
  .author = "Henning Rogge",

  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_hash_tomcrypt_subsystem);

/* definition for all sha1/2 hashes */
static struct tomcrypt_hash _hashes[] = {
  {
    .h =
      {
        .type = RFC7182_ICV_HASH_SHA_1,
        .hash = _cb_sha_hash,
        .hash_length = 160 / 8,
      },
    .tomcrypt_name = "sha1",
  },
  {
    .h =
      {
        .type = RFC7182_ICV_HASH_SHA_224,
        .hash = _cb_sha_hash,
        .hash_length = 224 / 8,
      },
    .tomcrypt_name = "sha224",
  },
  {
    .h =
      {
        .type = RFC7182_ICV_HASH_SHA_256,
        .hash = _cb_sha_hash,
        .hash_length = 256 / 8,
      },
    .tomcrypt_name = "sha256",
  },
  {
    .h =
      {
        .type = RFC7182_ICV_HASH_SHA_384,
        .hash = _cb_sha_hash,
        .hash_length = 384 / 8,
      },
    .tomcrypt_name = "sha384",
  },
  {
    .h =
      {
        .type = RFC7182_ICV_HASH_SHA_512,
        .hash = _cb_sha_hash,
        .hash_length = 512 / 8,
      },
    .tomcrypt_name = "sha512",
  },
};

/* definition of hmac crypto function */
static struct rfc7182_crypt _hmac = {
  .type = RFC7182_ICV_CRYPT_HMAC,
  .sign = _cb_hmac_sign,
  .getSignSize = _cb_get_cryptsize,
};

/**
 * Constructor for subsystem
 * @return always 0
 */
static int
_init(void) {
  size_t i;

  /* register hashes to libtomcrypt */
  register_hash(&sha1_desc);
  register_hash(&sha224_desc);
  register_hash(&sha256_desc);
  register_hash(&sha384_desc);
  register_hash(&sha512_desc);

  /* register hashes with rfc5444 signature API */
  for (i = 0; i < ARRAYSIZE(_hashes); i++) {
    _hashes[i].idx = find_hash(_hashes[i].tomcrypt_name);
    if (_hashes[i].idx != -1) {
      OONF_INFO(LOG_HASH_TOMCRYPT, "Add %s hash to rfc7182 API", rfc7182_get_hash_name(_hashes[i].h.type));
      rfc7182_add_hash(&_hashes[i].h);
    }
  }

  rfc7182_add_crypt(&_hmac);
  OONF_INFO(LOG_HASH_TOMCRYPT, "Add hmac to rfc7182 API");
  return 0;
}

/**
 * Destructor of subsystem
 */
static void
_cleanup(void) {
  size_t i;

  /* unregister hashes with rfc5444 signature API */
  for (i = 0; i < ARRAYSIZE(_hashes); i++) {
    if (_hashes[i].idx != -1) {
      rfc7182_remove_hash(&_hashes[i].h);
    }
  }

  rfc7182_remove_crypt(&_hmac);
}

/**
 * Generic SHA1/2 hash implementation based on libtomcrypt
 * @param hash rfc7182 hash
 * @param dst output buffer for hash
 * @param dst_len pointer to length of output buffer,
 *   will be set to hash length afterwards
 * @param src original data to hash
 * @param src_len length of original data
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_sha_hash(struct rfc7182_hash *hash, void *dst, size_t *dst_len, const void *src, size_t src_len) {
  struct tomcrypt_hash *tomhash;
  int result;

  tomhash = container_of(hash, struct tomcrypt_hash, h);

  result = hash_memory(tomhash->idx, src, (unsigned long)src_len, dst, (unsigned long *)dst_len);
  if (result) {
    OONF_WARN(LOG_HASH_TOMCRYPT, "tomcrypt error: %s", error_to_string(result));
    return -1;
  }
  return 0;
}

/**
 * @param crypt cryptographic function
 * @param hash hash function
 * @return length of signature based on chosen hash
 */
static size_t
_cb_get_cryptsize(struct rfc7182_crypt *crypt __attribute__((unused)), struct rfc7182_hash *hash) {
  return hash->hash_length;
}

/**
 * HMAC function based on libtomcrypt
 * @param crypt this crypto definition
 * @param hash the definition of the hash
 * @param dst output buffer for cryptographic signature
 * @param dst_len pointer to length of output buffer, will be set to
 *   length of signature afterwards
 * @param src unsigned original data
 * @param src_len length of original data
 * @param key key material for signature
 * @param key_len length of key material
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_hmac_sign(struct rfc7182_crypt *crypt __attribute__((unused)), struct rfc7182_hash *hash, void *dst,
  size_t *dst_len, const void *src, size_t src_len, const void *key, size_t key_len) {
  size_t i;
  int result;

  OONF_DEBUG_HEX(LOG_HASH_TOMCRYPT, src, src_len, "Calculate hash:");

  for (i = 0; i < ARRAYSIZE(_hashes); i++) {
    if (&_hashes[i].h == hash) {
      result = hmac_memory(
        _hashes[i].idx, key, (unsigned long)key_len, src, (unsigned long)src_len, dst, (unsigned long *)dst_len);
      if (result) {
        OONF_WARN(LOG_HASH_TOMCRYPT, "tomcrypt error: %s", error_to_string(result));
        return -1;
      }
      return 0;
    }
  }
  OONF_WARN(LOG_HASH_TOMCRYPT, "Unsupported Hash for Tomcrypt HMAC: %u", hash->type);
  return -1;
}
