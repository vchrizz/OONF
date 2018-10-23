
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
#include <oonf/libcommon/avl.h>
#include <oonf/oonf.h>
#include <oonf/base/oonf_timer.h>

#include <oonf/generic/dlep/dlep_extension.h>
#include <oonf/generic/dlep/dlep_iana.h>
#include <oonf/generic/dlep/dlep_reader.h>
#include <oonf/generic/dlep/dlep_writer.h>

#include <oonf/generic/dlep/ext_lid/lid.h>

static void _cb_session_deactivate(struct dlep_session *session);
static int _write_lid_only(struct dlep_extension *ext, struct dlep_session *session, const struct oonf_layer2_neigh_key *neigh);
static int _write_session_init_ack(struct dlep_extension *ext, struct dlep_session *session, const struct oonf_layer2_neigh_key *neigh);
static enum dlep_parser_error _process_session_init_ack(struct dlep_extension *ext, struct dlep_session *session);

/* session initialization ack */
static const uint16_t _session_initack_tlvs[] = {
  DLEP_LID_LENGTH_TLV,
};

/* destination up */
static const uint16_t _dst_up_tlvs[] = {
  DLEP_LID_TLV,
};

/* destination up ack */
static const uint16_t _dst_up_ack_tlvs[] = {
  DLEP_LID_TLV,
};

/* destination down */
static const uint16_t _dst_down_tlvs[] = {
  DLEP_LID_TLV,
};

/* destination down ack */
static const uint16_t _dst_down_ack_tlvs[] = {
  DLEP_LID_TLV,
};

/* destination update */
static const uint16_t _dst_update_tlvs[] = {
  DLEP_LID_TLV,
};

/* link characteristics request */
static const uint16_t _linkchar_req_tlvs[] = {
  DLEP_LID_TLV,
};

/* link characteristics ack */
static const uint16_t _linkchar_ack_tlvs[] = {
  DLEP_LID_TLV,
};

/* supported signals of this extension, parsing the LID TLV is done by dlep_extension */
static struct dlep_extension_signal _signals[] = {
  {
    .id = DLEP_SESSION_INITIALIZATION_ACK,
    .supported_tlvs = _session_initack_tlvs,
    .supported_tlv_count = ARRAYSIZE(_session_initack_tlvs),
    .process_router = _process_session_init_ack,
    .add_radio_tlvs = _write_session_init_ack,
  },
  {
    .id = DLEP_DESTINATION_UP,
    .supported_tlvs = _dst_up_tlvs,
    .supported_tlv_count = ARRAYSIZE(_dst_up_tlvs),
    .add_radio_tlvs = _write_lid_only,
  },
  {
    .id = DLEP_DESTINATION_UP_ACK,
    .supported_tlvs = _dst_up_ack_tlvs,
    .supported_tlv_count = ARRAYSIZE(_dst_up_ack_tlvs),
    .add_router_tlvs = _write_lid_only,
  },
  {
    .id = DLEP_DESTINATION_DOWN,
    .supported_tlvs = _dst_down_tlvs,
    .supported_tlv_count = ARRAYSIZE(_dst_down_tlvs),
    .add_radio_tlvs = _write_lid_only,
  },
  {
    .id = DLEP_DESTINATION_DOWN_ACK,
    .supported_tlvs = _dst_down_ack_tlvs,
    .supported_tlv_count = ARRAYSIZE(_dst_down_ack_tlvs),
    .add_router_tlvs = _write_lid_only,
  },
  {
    .id = DLEP_DESTINATION_UPDATE,
    .supported_tlvs = _dst_update_tlvs,
    .supported_tlv_count = ARRAYSIZE(_dst_update_tlvs),
    .add_radio_tlvs = _write_lid_only,
  },
  {
    .id = DLEP_LINK_CHARACTERISTICS_REQUEST,
    .supported_tlvs = _linkchar_req_tlvs,
    .supported_tlv_count = ARRAYSIZE(_linkchar_req_tlvs),
    .add_router_tlvs = _write_lid_only,
  },
  {
    .id = DLEP_LINK_CHARACTERISTICS_ACK,
    .supported_tlvs = _linkchar_ack_tlvs,
    .supported_tlv_count = ARRAYSIZE(_linkchar_ack_tlvs),
    .add_radio_tlvs = _write_lid_only,
  },
};

/* supported TLVs of this extension */
static struct dlep_extension_tlv _tlvs[] = {
  { DLEP_LID_TLV, 1, OONF_LAYER2_MAX_LINK_ID },
  { DLEP_LID_LENGTH_TLV, 2, 2 },
};

/* DLEP base extension, radio side */
static struct dlep_extension _lid = {
  .id = DLEP_EXTENSION_LINK_ID,
  .name = "linkid",

  .signals = _signals,
  .signal_count = ARRAYSIZE(_signals),
  .tlvs = _tlvs,
  .tlv_count = ARRAYSIZE(_tlvs),

  .cb_session_deactivate_radio = _cb_session_deactivate,
  .cb_session_deactivate_router = _cb_session_deactivate,
};

/**
 * Get link-id DLEP extension
 * @return this extension
 */
struct dlep_extension *
dlep_lid_init(void) {
  dlep_extension_add(&_lid);
  return &_lid;
}

static void
_cb_session_deactivate(struct dlep_session *session) {
  session->cfg.lid_length = 0;
}

/**
 * Write the link-id TLV into the DLEP message
 * @param ext (this) dlep extension
 * @param session dlep session
 * @param neigh layer2 neighbor key to write into TLV
 * @return -1 if an error happened, 0 otherwise
 */
static int
_write_lid_only(
  struct dlep_extension *ext __attribute__((unused)), struct dlep_session *session, const struct oonf_layer2_neigh_key *neigh) {
  return dlep_writer_add_lid_tlv(&session->writer, neigh);
}

/**
* Write link-id-length TLV if necessary
 * @param ext (this) dlep extension
 * @param session dlep session
 * @param neigh layer2 neighbor key to write into TLV (NULL in this case)
 * @return -1 if an error happened, 0 otherwise
 */
static int
_write_session_init_ack(struct dlep_extension *ext __attribute__((unused)), struct dlep_session *session,
                        const struct oonf_layer2_neigh_key *neigh __attribute__((unused))) {
  if (session->cfg.lid_length == 0 || session->cfg.lid_length == DLEP_DEFAULT_LID_LENGTH) {
    return 0;
  }

  return dlep_writer_add_lid_length_tlv(&session->writer, session->cfg.lid_length);
}

/**
 * Handle incoming link-id-length TLV
 * @param ext (this) dlep extension
 * @param session dlep session
 * @return parser return code
 */
static enum dlep_parser_error
_process_session_init_ack(struct dlep_extension *ext __attribute__((unused)), struct dlep_session *session) {
  uint16_t length;

  if (dlep_reader_lid_length_tlv(&length, session, NULL)) {
    session->cfg.lid_length = DLEP_DEFAULT_LID_LENGTH;
    return DLEP_NEW_PARSER_OKAY;
  }

  if (length > OONF_LAYER2_MAX_LINK_ID) {
    dlep_session_generate_signal_status(session, DLEP_SESSION_TERMINATION, NULL, DLEP_STATUS_REQUEST_DENIED,
        "Cannot handle link-id length this large");
    return DLEP_NEW_PARSER_TERMINDATED;
  }

  session->cfg.lid_length = length;
  return DLEP_NEW_PARSER_OKAY;
}
