
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

#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/avl_comp.h>
#include <oonf/oonf.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_class.h>
#include <oonf/librfc5444/rfc5444_iana.h>

#include <oonf/crypto/rfc7182_provider/rfc7182_provider.h>

#define LOG_RFC7182_PROVIDER _rfc7182_provider_subsystem.logging

/* prototypes */
static int _init(void);
static void _cleanup(void);
static int _cb_identity_hash(struct rfc7182_hash *hash, void *dst, size_t *dst_len, const void *src, size_t src_len);
static int _cb_identity_crypt(struct rfc7182_crypt *crypt, void *dst, size_t *dst_len, const void *src, size_t src_len,
  const void *key, size_t key_len);

static bool _cb_validate_by_sign(struct rfc7182_crypt *, struct rfc7182_hash *, const void *encrypted,
  size_t encrypted_length, const void *src, size_t src_len, const void *key, size_t key_len);
static int _cb_sign_by_crypthash(struct rfc7182_crypt *crypt, struct rfc7182_hash *hash, void *dst, size_t *dst_len,
  const void *src, size_t src_len, const void *key, size_t key_len);

/* plugin declaration */
static const char *_dependencies[] = {
  OONF_CLASS_SUBSYSTEM,
};
static struct oonf_subsystem _rfc7182_provider_subsystem = {
  .name = OONF_RFC7182_PROVIDER_SUBSYSTEM,
  .descr = "OONF RFC7182 crypto provider plugin",
  .author = "Henning Rogge",
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),

  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_rfc7182_provider_subsystem);

/* identity hash/crypt function */
static struct rfc7182_hash _identity_hash = {
  .type = RFC7182_ICV_HASH_IDENTITY,
  .hash = _cb_identity_hash,
};

static struct rfc7182_crypt _identity_crypt = {
  .type = RFC7182_ICV_CRYPT_IDENTITY,
  .encrypt = _cb_identity_crypt,
};

/* tree of hash/crypt functions */
static struct avl_tree _crypt_functions;
static struct avl_tree _hash_functions;

static struct oonf_class _hash_class = {
  .name = OONF_RFC7182_HASH_CLASS,
  .size = sizeof(struct rfc7182_hash),
};
static struct oonf_class _crypt_class = {
  .name = OONF_RFC7182_CRYPTO_CLASS,
  .size = sizeof(struct rfc7182_crypt),
};

/* static buffer for crypto calculation */
static uint8_t _crypt_buffer[1500];

/**
 * Constructor of subsystem
 * @return -1 if rfc5444 protocol was not available, 0 otherwise
 */
static int
_init(void) {
  avl_init(&_crypt_functions, avl_comp_uint8, false);
  avl_init(&_hash_functions, avl_comp_uint8, false);

  oonf_class_add(&_hash_class);
  oonf_class_add(&_crypt_class);

  rfc7182_add_hash(&_identity_hash);
  rfc7182_add_crypt(&_identity_crypt);

  return 0;
}

/**
 * Destructor of subsystem
 */
static void
_cleanup(void) {
  struct rfc7182_hash *hash, *hash_it;
  struct rfc7182_crypt *crypt, *crypt_it;

  avl_for_each_element_safe(&_hash_functions, hash, _node, hash_it) {
    rfc7182_remove_hash(hash);
  }
  avl_for_each_element_safe(&_crypt_functions, crypt, _node, crypt_it) {
    rfc7182_remove_crypt(crypt);
  }

  oonf_class_remove(&_hash_class);
  oonf_class_remove(&_crypt_class);
}

/**
 * Register a hash function to the API
 * @param hash pointer to hash definition
 */
void
rfc7182_add_hash(struct rfc7182_hash *hash) {
  /* hook key into avl node */
  hash->_node.key = &hash->type;

  /* hook hash into hash tree */
  avl_insert(&_hash_functions, &hash->_node);

  oonf_class_event(&_hash_class, hash, OONF_OBJECT_ADDED);
}

/**
 * Remove hash function from signature API
 * @param hash pointer to hash definition
 */
void
rfc7182_remove_hash(struct rfc7182_hash *hash) {
  oonf_class_event(&_hash_class, hash, OONF_OBJECT_REMOVED);
  avl_remove(&_hash_functions, &hash->_node);
}

/**
 * Get tree of RFC7182 hashes
 * @return tree of hashes
 */
struct avl_tree *
rfc7182_get_hash_tree(void) {
  return &_hash_functions;
}

/**
 * Add a crypto function to the API
 * @param crypt pointer to signature definition
 */
void
rfc7182_add_crypt(struct rfc7182_crypt *crypt) {
  /* hook key into avl node */
  crypt->_node.key = &crypt->type;

  /* use default checker if necessary */
  if (!crypt->validate) {
    crypt->validate = _cb_validate_by_sign;
  }

  if (!crypt->sign) {
    crypt->sign = _cb_sign_by_crypthash;
  }

  /* hook crypt function into crypt tree */
  avl_insert(&_crypt_functions, &crypt->_node);

  oonf_class_event(&_hash_class, crypt, OONF_OBJECT_ADDED);
}

/**
 * Remove a crypto function from the API
 * @param crypt pointer to signature definition
 */
void
rfc7182_remove_crypt(struct rfc7182_crypt *crypt) {
  oonf_class_event(&_crypt_class, crypt, OONF_OBJECT_REMOVED);
  avl_remove(&_crypt_functions, &crypt->_node);
}

/**
 * Get tree of RFC7182 crypto
 * @return tree of crypto functions
 */
struct avl_tree *
rfc7182_get_crypt_tree(void) {
  return &_crypt_functions;
}

/**
 * 'Identity' hash function as defined in RFC7182
 * @param sig rfc5444 signature
 * @param dst output buffer for signature
 * @param dst_len pointer to length of output buffer,
 *   will be set to signature length afterwards
 * @param src unsigned original data
 * @param src_len length of original data
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_identity_hash(
  struct rfc7182_hash *hash __attribute__((unused)), void *dst, size_t *dst_len, const void *src, size_t src_len) {
  *dst_len = src_len;
  memcpy(dst, src, src_len);
  return 0;
}

/**
 * 'Identity' crypto function as defined in RFC7182
 * @param sig rfc5444 signature
 * @param dst output buffer for cryptographic signature
 * @param dst_len pointer to length of output buffer, will be set to
 *   length of signature afterwards
 * @param src unsigned original data
 * @param src_len length of original data
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_identity_crypt(struct rfc7182_crypt *crypt __attribute((unused)), void *dst, size_t *dst_len, const void *src,
  size_t src_len, const void *key __attribute((unused)), size_t key_len __attribute((unused))) {
  /* just copy */
  *dst_len = src_len;
  memcpy(dst, src, src_len);
  return 0;
}

/**
 * Callback to check a signature by generating a local signature
 * with the 'crypto' callback and then comparing both.
 * @param crypt this crypto definition
 * @param hash the definition of the hash
 * @param encrypted pointer to encrypted signature
 * @param encrypted_length length of encrypted signature
 * @param src unsigned original data
 * @param src_len length of original data
 * @param key key material for signature
 * @param key_len length of key material
 * @return true if signature matches, false otherwise
 */
static bool
_cb_validate_by_sign(struct rfc7182_crypt *crypt, struct rfc7182_hash *hash, const void *encrypted,
  size_t encrypted_length, const void *src, size_t src_len, const void *key, size_t key_len) {
  size_t crypt_length;
  int result;

  /* run encryption function */
  crypt_length = sizeof(_crypt_buffer);
  if (crypt->sign(crypt, hash, _crypt_buffer, &crypt_length, src, src_len, key, key_len)) {
    OONF_INFO(LOG_RFC7182_PROVIDER, "Crypto-error when checking signature");
    return -1;
  }

  /* compare length of both signatures */
  if (crypt_length != encrypted_length) {
    OONF_INFO(LOG_RFC7182_PROVIDER,
      "signature has wrong length: "
      "%" PRINTF_SIZE_T_SPECIFIER " != %" PRINTF_SIZE_T_SPECIFIER,
      crypt_length, encrypted_length);
    return -1;
  }

  /* binary compare both signatures */
  result = memcmp(encrypted, _crypt_buffer, crypt_length);
  if (result) {
    OONF_INFO_HEX(LOG_RFC7182_PROVIDER, encrypted, crypt_length, "Received signature:");
    OONF_INFO_HEX(LOG_RFC7182_PROVIDER, _crypt_buffer, crypt_length, "Expected signature:");
  }
  return result == 0;
}

static int
_cb_sign_by_crypthash(struct rfc7182_crypt *crypt, struct rfc7182_hash *hash, void *dst, size_t *dst_len,
  const void *src, size_t src_len, const void *key, size_t key_len) {
  size_t hashed_length;

  hashed_length = sizeof(_crypt_buffer);
  if (hash->hash(hash, _crypt_buffer, &hashed_length, src, src_len)) {
    OONF_WARN(LOG_RFC7182_PROVIDER, "Could not generate hash %u", hash->type);
    return -1;
  }

  if (crypt->encrypt(crypt, dst, dst_len, _crypt_buffer, hashed_length, key, key_len)) {
    OONF_WARN(LOG_RFC7182_PROVIDER, "Could not generate crypt %u", crypt->type);
    return -1;
  }

  return 0;
}
