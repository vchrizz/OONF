
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

#include <oonf/libcommon/autobuf.h>
#include <oonf/oonf.h>

#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_rfc5444.h>

#include <oonf/nhdp/nhdp/nhdp_interfaces.h>

#include <oonf/nhdp/nhdpcheck/nhdpcheck.h>

/* Definitions */
#define LOG_NHDPCHECK _olsrv2_nhdpcheck_subsystem.logging

/* prototypes */
static int _init(void);
static void _cleanup(void);

/* plugin declaration */
static const char *_dependencies[] = {
  OONF_RFC5444_SUBSYSTEM,
  OONF_NHDP_SUBSYSTEM,
};
static struct oonf_subsystem _olsrv2_nhdpcheck_subsystem = {
  .name = OONF_NHDPCHECK_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "OLSRv2 nhdpcheck plugin",
  .author = "Henning Rogge",

  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_olsrv2_nhdpcheck_subsystem);

/* NHDP message TLV array index */
enum
{
  IDX_TLV_ITIME,
  IDX_TLV_VTIME,
};

/* NHDP address TLV array index pass 1 */
enum
{
  IDX_ADDRTLV_LOCAL_IF,
  IDX_ADDRTLV_LINK_STATUS,
  IDX_ADDRTLV_OTHER_NEIGHB,
};

/* prototypes */
static enum rfc5444_result _cb_message_start_callback(struct rfc5444_reader_tlvblock_context *context);
static enum rfc5444_result _cb_messagetlvs(struct rfc5444_reader_tlvblock_context *context);
static enum rfc5444_result _cb_addresstlvs(struct rfc5444_reader_tlvblock_context *context);

/* definition of the RFC5444 reader components */
static struct rfc5444_reader_tlvblock_consumer _nhdp_message_consumer = {
  .order = RFC5444_VALIDATOR_PRIORITY,
  .msg_id = RFC6130_MSGTYPE_HELLO,
  .start_callback = _cb_message_start_callback,
  .block_callback = _cb_messagetlvs,
};

static struct rfc5444_reader_tlvblock_consumer_entry _nhdp_message_tlvs[] = {
  [IDX_TLV_ITIME] = { .type = RFC5497_MSGTLV_INTERVAL_TIME },
  [IDX_TLV_VTIME] = { .type = RFC5497_MSGTLV_VALIDITY_TIME },
};

static struct rfc5444_reader_tlvblock_consumer _nhdp_address_consumer = {
  .order = RFC5444_VALIDATOR_PRIORITY,
  .msg_id = RFC6130_MSGTYPE_HELLO,
  .block_callback = _cb_addresstlvs,
};

static struct rfc5444_reader_tlvblock_consumer_entry _nhdp_address_tlvs[] = {
  [IDX_ADDRTLV_LOCAL_IF] = { .type = RFC6130_ADDRTLV_LOCAL_IF },
  [IDX_ADDRTLV_LINK_STATUS] = { .type = RFC6130_ADDRTLV_LINK_STATUS },
  [IDX_ADDRTLV_OTHER_NEIGHB] = { .type = RFC6130_ADDRTLV_OTHER_NEIGHB },
};

/* nhdp multiplexer/protocol */
static struct oonf_rfc5444_protocol *_protocol = NULL;

/**
 * Initialize plugin
 * @return always returns 0 (cannot fail)
 */
static int
_init(void) {
  _protocol = oonf_rfc5444_get_default_protocol();
  if (_protocol == NULL) {
    return -1;
  }

  rfc5444_reader_add_message_consumer(
    &_protocol->reader, &_nhdp_message_consumer, _nhdp_message_tlvs, ARRAYSIZE(_nhdp_message_tlvs));
  rfc5444_reader_add_message_consumer(
    &_protocol->reader, &_nhdp_address_consumer, _nhdp_address_tlvs, ARRAYSIZE(_nhdp_address_tlvs));

  return 0;
}

/**
 * Cleanup plugin
 */
static void
_cleanup(void) {
  rfc5444_reader_remove_message_consumer(&_protocol->reader, &_nhdp_message_consumer);
  rfc5444_reader_remove_message_consumer(&_protocol->reader, &_nhdp_address_consumer);
  _protocol = NULL;
}

/**
 * Callback triggered when a NHDP hello message is received by the stack
 * @param context rfc5444 tlvblock reader context
 * @return see rfc5444_result enum
 */
static enum rfc5444_result
_cb_message_start_callback(struct rfc5444_reader_tlvblock_context *context) {
#ifdef OONF_LOG_INFO
  struct nhdp_interface *interf;

  interf = nhdp_interface_get(_protocol->input.interface->name);
  OONF_ASSERT(interf, LOG_NHDPCHECK, "Could not find NHDP interface %s", _protocol->input.interface->name);
#endif

  /* check address length */
  if (context->addr_len != 4 && context->addr_len != 16) {
    OONF_INFO(LOG_NHDPCHECK, "Dropped NHDP message with addrlen %d on interface %s", context->addr_len,
      nhdp_interface_get_name(interf));
    return RFC5444_DROP_MESSAGE;
  }

  /* drop if message has hoplimit and its not 1 */
  if (context->has_hoplimit && context->hoplimit != 1) {
    OONF_INFO(LOG_NHDPCHECK, "Dropped NHDP message with hoplimit %d", context->hoplimit);
    return RFC5444_DROP_MESSAGE;
  }

  /* drop if message has hopcount and its not 0 */
  if (context->has_hopcount && context->hopcount != 0) {
    OONF_INFO(LOG_NHDPCHECK, "Dropped NHDP message with hopcount %d", context->hopcount);
    return RFC5444_DROP_MESSAGE;
  }

  return RFC5444_OKAY;
}

/**
 * Callblack triggered to deliver the message TLVs received in a NHDP Hello
 * @param context rfc5444 tlvblock reader context
 * @return see rfc5444_result enum
 */
static enum rfc5444_result
_cb_messagetlvs(struct rfc5444_reader_tlvblock_context *context __attribute__((unused))) {
  /* drop message if it has no VTIME TLV or has more than one */
  if (_nhdp_message_tlvs[IDX_TLV_VTIME].tlv == NULL || _nhdp_message_tlvs[IDX_TLV_VTIME].tlv->next_entry != NULL) {
    OONF_INFO(LOG_NHDPCHECK, "Dropped NHDP message with no or multiple VTIME TLVs");
    return RFC5444_DROP_MESSAGE;
  }

  /* check if VTIME TLV has length 1 */
  if (_nhdp_message_tlvs[IDX_TLV_VTIME].tlv->length != 1) {
    OONF_INFO(
      LOG_NHDPCHECK, "Dropped NHDP message with VTIME TLV length %d", _nhdp_message_tlvs[IDX_TLV_VTIME].tlv->length);
    return RFC5444_DROP_MESSAGE;
  }

  if (_nhdp_message_tlvs[IDX_TLV_ITIME].tlv) {
    /* check if message has multiple ITIME TLVs */
    if (_nhdp_message_tlvs[IDX_TLV_ITIME].tlv->next_entry != NULL) {
      OONF_INFO(LOG_NHDPCHECK, "Dropped NHDP message with multiple ITIME TLVs");
      return RFC5444_DROP_MESSAGE;
    }
    if (_nhdp_message_tlvs[IDX_TLV_ITIME].tlv->length != 1) {
      OONF_INFO(
        LOG_NHDPCHECK, "Dropped NHDP message with ITIME TLV length %d", _nhdp_message_tlvs[IDX_TLV_ITIME].tlv->length);
      return RFC5444_DROP_MESSAGE;
    }

    if (_nhdp_message_tlvs[IDX_TLV_ITIME].tlv->single_value[0] >
        _nhdp_message_tlvs[IDX_TLV_VTIME].tlv->single_value[0]) {
      OONF_INFO(LOG_NHDPCHECK,
        "Dropped NHDP message because ITIME 0x%02x is larger"
        "than VTIME 0x%02x",
        _nhdp_message_tlvs[IDX_TLV_ITIME].tlv->single_value[0], _nhdp_message_tlvs[IDX_TLV_VTIME].tlv->single_value[0]);
      return RFC5444_DROP_MESSAGE;
    }
  }
  return RFC5444_OKAY;
}

/**
 * Callblack triggered to deliver the address TLVs received in a NHDP Hello
 * @param context rfc5444 tlvblock reader context
 * @return see rfc5444_result enum
 */

static enum rfc5444_result
_cb_addresstlvs(struct rfc5444_reader_tlvblock_context *context __attribute__((unused))) {
#ifdef OONF_LOG_INFO
  struct netaddr_str buf;
#endif

  if (_nhdp_address_tlvs[IDX_ADDRTLV_LOCAL_IF].tlv != NULL) {
    /* check for duplicate LOCAL_IF TLV */
    if (_nhdp_address_tlvs[IDX_ADDRTLV_LOCAL_IF].tlv->next_entry != NULL) {
      OONF_INFO(LOG_NHDPCHECK, "Dropped NHDP message, address %s had multiple LOCAL_IF TLVs", buf.buf);
      return RFC5444_DROP_MESSAGE;
    }

    /* check for bad length of LOCAL_IF TLV */
    if (_nhdp_address_tlvs[IDX_ADDRTLV_LOCAL_IF].tlv->length != 1) {
      OONF_INFO(LOG_NHDPCHECK, "Dropped NHDP message, address %s had LOCAL_IF TLV length %d", buf.buf,
        _nhdp_address_tlvs[IDX_ADDRTLV_LOCAL_IF].tlv->length);
      return RFC5444_DROP_MESSAGE;
    }

    /* check if address had both LOCAL_IF and LINK_STATUS TLV */
    if (_nhdp_address_tlvs[IDX_ADDRTLV_LINK_STATUS].tlv != NULL) {
      OONF_INFO(LOG_NHDPCHECK, "Dropped NHDP message, address %s had LOCAL_IF and LINK_STATUS TLV", buf.buf);
      return RFC5444_DROP_MESSAGE;
    }

    /* check if address had both LOCAL_IF and OTHER_NEIGH TLV */
    if (_nhdp_address_tlvs[IDX_ADDRTLV_OTHER_NEIGHB].tlv != NULL) {
      OONF_INFO(LOG_NHDPCHECK, "Dropped NHDP message, address %s had LOCAL_IF and OTHER_NEIGHB TLV", buf.buf);
      return RFC5444_DROP_MESSAGE;
    }
  }

  if (_nhdp_address_tlvs[IDX_ADDRTLV_LINK_STATUS].tlv != NULL) {
    /* check for duplicate LINK_STATUS TLV */
    if (_nhdp_address_tlvs[IDX_ADDRTLV_LINK_STATUS].tlv->next_entry != NULL) {
      OONF_INFO(LOG_NHDPCHECK, "Dropped NHDP message, address %s had multiple LINK_STATUS TLVs", buf.buf);
      return RFC5444_DROP_MESSAGE;
    }

    /* check for bad length of LINK_STATUS TLV */
    if (_nhdp_address_tlvs[IDX_ADDRTLV_LINK_STATUS].tlv->length != 1) {
      OONF_INFO(LOG_NHDPCHECK, "Dropped NHDP message, address %s had LINK_STATUS TLV length %d", buf.buf,
        _nhdp_address_tlvs[IDX_ADDRTLV_LINK_STATUS].tlv->length);
      return RFC5444_DROP_MESSAGE;
    }
  }

  if (_nhdp_address_tlvs[IDX_ADDRTLV_OTHER_NEIGHB].tlv != NULL) {
    /* check for duplicate OTHER_NEIGH TLV */
    if (_nhdp_address_tlvs[IDX_ADDRTLV_OTHER_NEIGHB].tlv->next_entry != NULL) {
      OONF_INFO(LOG_NHDPCHECK, "Dropped NHDP message, address %s had multiple OTHER_NEIGHB TLVs", buf.buf);
      return RFC5444_DROP_MESSAGE;
    }

    /* check for bad length of OTHER_NEIGH TLV */
    if (_nhdp_address_tlvs[IDX_ADDRTLV_OTHER_NEIGHB].tlv->length != 1) {
      OONF_INFO(LOG_NHDPCHECK, "Dropped NHDP message, address %s had OTHER_NEIGH TLV length %d", buf.buf,
        _nhdp_address_tlvs[IDX_ADDRTLV_OTHER_NEIGHB].tlv->length);
      return RFC5444_DROP_MESSAGE;
    }
  }

  return RFC5444_OKAY;
}
