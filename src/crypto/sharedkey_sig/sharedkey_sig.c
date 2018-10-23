
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
#include <oonf/libcommon/bitmap256.h>
#include <oonf/oonf.h>
#include <oonf/libconfig/cfg_schema.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/crypto/rfc5444_signature/rfc5444_signature.h>
#include <oonf/base/oonf_class.h>
#include <oonf/base/oonf_rfc5444.h>
#include <oonf/librfc5444/rfc5444_iana.h>

#include <oonf/crypto/sharedkey_sig/sharedkey_sig.h>

#define LOG_SHAREDKEY_SIG _sharedkey_sig_subsystem.logging

/**
 * Configuration of a shared-key signature
 */
struct sharedkey_signature {
  /*! name of the signature for registration */
  char name[16];

  /*! cryptographic key for signature */
  char key[256];

  /*! id of signature, might have length 0 */
  char id[256];

  /*! bitarray of messages the signature should be applied to */
  struct bitmap256 msgtype;

  /*! true if signature should be applied on packet level */
  bool packet;

  /*! true if source IP should be included into signature */
  bool source_specific;

  /*! true if message/packet should be dropped if signature is bad/missing */
  bool drop_if_invalid;

  /*! hash id for signature */
  enum rfc7182_icv_hash hash;

  /*! crypto id for signature */
  enum rfc7182_icv_crypt crypt;

  /*! rfc7182 signature provider */
  struct rfc5444_signature _signature;

  /*! hook into tree of configured shared key signatures */
  struct avl_node _node;
};
/* function prototypes */
static void _early_cfg_init(void);
static int _init(void);
static void _cleanup(void);

static enum rfc5444_sigid_check _cb_verify_id(struct rfc5444_signature *sig, const void *id, size_t len);
static bool _cb_is_matching_signature(struct rfc5444_signature *sig, int msg_type);
static const void *_cb_getCryptoKey(struct rfc5444_signature *sig, size_t *length);
static const void *_cb_getKeyId(struct rfc5444_signature *sig, size_t *length);

static struct sharedkey_signature *_add_sig(const char *name);
static struct sharedkey_signature *_get_sig(const char *name);
static void _remove_sig(struct sharedkey_signature *sig);

static void _cb_config_changed(void);

/* shared key signature subsystem definition */
enum
{
  IDX_CFG_KEY,
  IDX_CFG_ID,
  IDX_CFG_MSG,
  IDX_CFG_PACKET,
  IDX_CFG_SRCSPEC,
  IDX_CFG_DROP,
  IDX_CFG_HASH,
  IDX_CFG_CRYPTO,
};
static const char *_dummy[] = { "" };

static struct cfg_schema_entry _sharedkey_entries[] = {
  [IDX_CFG_KEY] = CFG_MAP_STRING_ARRAY(sharedkey_signature, key, "key", NULL, "Key for signature cryptofunction", 256),
  [IDX_CFG_ID] = CFG_MAP_STRING_ARRAY(sharedkey_signature, id, "id", "", "Key ID for signature", 256),
  [IDX_CFG_MSG] =
    CFG_MAP_BITMAP256(sharedkey_signature, msgtype, "msgtype", BITMAP256_NONE, "Array of message-types to sign"),
  [IDX_CFG_PACKET] = CFG_MAP_BOOL(
    sharedkey_signature, packet, "packet", "false", "Set to true to create a packet level rfc7182 signature"),
  [IDX_CFG_SRCSPEC] = CFG_MAP_BOOL(sharedkey_signature, source_specific, "source_specific", "false",
    "Set to true to include source-ip address into signature"),
  [IDX_CFG_DROP] = CFG_MAP_BOOL(sharedkey_signature, drop_if_invalid, "drop_if_invalid", "true",
    "Drop message/packet if signature cannot be validated"),
  [IDX_CFG_HASH] = CFG_MAP_CHOICE(
    sharedkey_signature, hash, "hash", "sha256", "Select the hash to be used for the signature generation", _dummy),
  [IDX_CFG_CRYPTO] = CFG_MAP_CHOICE(sharedkey_signature, crypt, "crypt", "hmac",
    "Select the crypto-function to be used for the signature generation", _dummy),
};

static struct cfg_schema_section _sharedkey_section = {
  .type = OONF_SHAREDKEY_SIG_SUBSYSTEM,
  .mode = CFG_SSMODE_NAMED,
  .cb_delta_handler = _cb_config_changed,
  .entries = _sharedkey_entries,
  .entry_count = ARRAYSIZE(_sharedkey_entries),
};

static const char *_dependencies[] = {
  OONF_CLASS_SUBSYSTEM,
  OONF_RFC5444_SIG_SUBSYSTEM,
  OONF_RFC5444_SUBSYSTEM,
};
static struct oonf_subsystem _sharedkey_sig_subsystem = {
  .name = OONF_SHAREDKEY_SIG_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "RFC5444 shared-key signature plugin",
  .author = "Henning Rogge",

  .early_cfg_init = _early_cfg_init,
  .init = _init,
  .cleanup = _cleanup,

  .cfg_section = &_sharedkey_section,
};
DECLARE_OONF_PLUGIN(_sharedkey_sig_subsystem);

/* storage for configured signatures */
static struct oonf_class _sig_class = {
  .name = "Shared signature",
  .size = sizeof(struct sharedkey_signature),
};

static struct avl_tree _sig_tree;

/**
 * Initialize configuration parameters for subsystem
 */
static void
_early_cfg_init(void) {
  /* we cannot do this statically because we draw the data from another subsystem */
  _sharedkey_entries[IDX_CFG_HASH].validate_param[0].ptr = rfc7182_get_hashes();
  _sharedkey_entries[IDX_CFG_HASH].validate_param[1].s = RFC7182_ICV_HASH_COUNT;

  _sharedkey_entries[IDX_CFG_CRYPTO].validate_param[0].ptr = rfc7182_get_crypto();
  _sharedkey_entries[IDX_CFG_CRYPTO].validate_param[1].s = RFC7182_ICV_CRYPT_COUNT;
}

/**
 * Constructor for subsystem
 * @return always 0
 */
static int
_init(void) {
  oonf_class_add(&_sig_class);
  avl_init(&_sig_tree, avl_comp_strcasecmp, false);
  return 0;
}

/**
 * Destructor of subsystem
 */
static void
_cleanup(void) {
  struct sharedkey_signature *sig, *sig_it;

  avl_for_each_element_safe(&_sig_tree, sig, _node, sig_it) {
    _remove_sig(sig);
  }
  oonf_class_remove(&_sig_class);
}

/**
 * Add a signature instance to tree
 * @param name name of signature instance
 * @return initialized signature instance, NULL if out of memory
 */
static struct sharedkey_signature *
_add_sig(const char *name) {
  struct sharedkey_signature *sig;

  sig = oonf_class_malloc(&_sig_class);
  if (sig) {
    /* initialize key */
    strscpy(sig->name, name, sizeof(sig->name));
    sig->_node.key = sig->name;
    avl_insert(&_sig_tree, &sig->_node);

    sig->_signature.verify_id = _cb_verify_id;
    sig->_signature.is_matching_signature = _cb_is_matching_signature;
    sig->_signature.getCryptoKey = _cb_getCryptoKey;
    sig->_signature.getKeyId = _cb_getKeyId;
  }
  return sig;
}

/**
 * @param name name of a signature instance
 * @return pointer to signature instance, NULL if not found
 */
static struct sharedkey_signature *
_get_sig(const char *name) {
  struct sharedkey_signature *sig;

  return avl_find_element(&_sig_tree, name, sig, _node);
}

/**
 * Removes a signature instance from tree
 * @param sig pointer to signature instance
 */
static void
_remove_sig(struct sharedkey_signature *sig) {
  rfc5444_sig_remove(&sig->_signature);
  avl_remove(&_sig_tree, &sig->_node);
  oonf_class_free(&_sig_class, sig);
}

/**
 * Callback to verify the signature ID
 * @param sig signature instance
 * @param id pointer to signature ID
 * @param len length of signature ID
 * @return okay, skip or drop
 */
static enum rfc5444_sigid_check
_cb_verify_id(struct rfc5444_signature *sig, const void *id, size_t len) {
  struct sharedkey_signature *sk_sig;
  bool result = false;

  sk_sig = container_of(sig, struct sharedkey_signature, _signature);

  if (len == strlen(sk_sig->id)) {
    result = memcmp(id, sk_sig->id, len) == 0;
  }

  OONF_DEBUG_HEX(
    LOG_SHAREDKEY_SIG, id, len, "verify id %s = %s: %s", sk_sig->name, sk_sig->id, result ? "true" : "false");
  return result ? RFC5444_SIGID_OKAY : RFC5444_SIGID_DROP;
}

/**
 * Callback to check if a signature type is handled by this subsystem
 * @param sig signature instance
 * @param msg_type RFC5444 message type, -1 for packet signature
 * @return true if subsystem will handle this signature
 */
static bool
_cb_is_matching_signature(struct rfc5444_signature *sig, int msg_type) {
  struct sharedkey_signature *sk_sig;

  sk_sig = container_of(sig, struct sharedkey_signature, _signature);
  if (msg_type == RFC5444_WRITER_PKT_POSTPROCESSOR) {
    OONF_DEBUG(LOG_SHAREDKEY_SIG, "is packet signature %s: %s", sk_sig->name, sk_sig->packet ? "true" : "false");

    return sk_sig->packet;
  }

  OONF_DEBUG_HEX(LOG_SHAREDKEY_SIG, &sk_sig->msgtype, sizeof(sk_sig->msgtype), "is message (type=%u) signature %s: %s",
    msg_type, sk_sig->name, bitmap256_get(&sk_sig->msgtype, msg_type) ? "true" : "false");

  return bitmap256_get(&sk_sig->msgtype, msg_type);
}

/**
 * Get the cryptographic key for the signature
 * @param sig signature instance
 * @param length pointer to length field to store key length
 * @returns pointer to cryptographic key
 */
static const void *
_cb_getCryptoKey(struct rfc5444_signature *sig, size_t *length) {
  struct sharedkey_signature *sk_sig;

  sk_sig = container_of(sig, struct sharedkey_signature, _signature);

  OONF_DEBUG(LOG_SHAREDKEY_SIG, "getcryptokey %s: %s", sk_sig->name, sk_sig->key);

  *length = strlen(sk_sig->key);
  return sk_sig->key;
}

/**
 * Get key id of signature
 * @param sig signature instance
 * @param length pointer to length field to store id length
 * @returns pointer to id
 */
static const void *
_cb_getKeyId(struct rfc5444_signature *sig, size_t *length) {
  struct sharedkey_signature *sk_sig;

  sk_sig = container_of(sig, struct sharedkey_signature, _signature);

  OONF_DEBUG(LOG_SHAREDKEY_SIG, "getkeyid %s: %s", sk_sig->name, sk_sig->id);

  *length = strlen(sk_sig->id);
  return sk_sig->id;
}

/**
 * Callback to handle configuration changes
 */
static void
_cb_config_changed(void) {
  struct sharedkey_signature *sig;

  if (!_sharedkey_section.pre) {
    /* new section */
    sig = _add_sig(_sharedkey_section.section_name);
    if (!sig) {
      return;
    }
  }
  else {
    sig = _get_sig(_sharedkey_section.section_name);
  }

  if (!_sharedkey_section.post) {
    /* remove old section */
    _remove_sig(sig);
    return;
  }

  if (cfg_schema_tobin(sig, _sharedkey_section.post, _sharedkey_entries, ARRAYSIZE(_sharedkey_entries))) {
    OONF_WARN(LOG_SHAREDKEY_SIG, "Cannot convert configuration for " OONF_SHAREDKEY_SIG_SUBSYSTEM);
    return;
  }

  if (_sharedkey_section.pre) {
    /* remove old signature */
    rfc5444_sig_remove(&sig->_signature);
  }

  /* (re-)initialize data that can be configured */
  sig->_signature.key.crypt_function = sig->crypt;
  sig->_signature.key.hash_function = sig->hash;
  sig->_signature.drop_if_invalid = sig->drop_if_invalid;
  sig->_signature.source_specific = sig->source_specific;

  /* add signature */
  rfc5444_sig_add(&sig->_signature);
}
