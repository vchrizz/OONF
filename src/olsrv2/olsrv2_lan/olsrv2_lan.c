
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

#include <errno.h>

#include <oonf/libcommon/avl.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/list.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcommon/netaddr_acl.h>
#include <oonf/libconfig/cfg_schema.h>
#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/olsrv2/olsrv2/olsrv2_lan.h>

#include <oonf/olsrv2/olsrv2_lan/olsrv2_lan.h>

/*! logging for plugin */
#define LOG_OLSRV2_LAN _olsrv2_lan_subsystem.logging

/*! locally attached network option for source-specific prefix */
#define LAN_DEFAULT_DOMAIN -1

/**
 * Additional parameters of a single locally attached network
 */
struct _lan_data {
  /*! prefix for OLSRv2 LAN */
  struct os_route_key prefix;

  /*! extension domain of LAN */
  int32_t extension;

  /*! olsrv2 metric */
  int32_t metric;

  /*! routing metric (distance) */
  int32_t distance;
};

/* prototypes */
static int _init(void);
static void _cleanup(void);

static void _cb_cfg_olsrv2_lan_changed(void);

static struct cfg_schema_entry _olsrv2_lan_entries[] = {
  CFG_MAP_NETADDR_V46(_lan_data, prefix.dst, "prefix", NULL, "locally attached network prefix", true, false),
  CFG_MAP_INT32_MINMAX(
    _lan_data, extension, "domain", "-1", "domain for this LAN entry, -1 for all domains", 0, -1, 255),
  CFG_MAP_NETADDR_V6(
    _lan_data, prefix.src, "source_prefix", "-", "source prefix for lan (source specific routing)", true, true),
  CFG_MAP_INT32_MINMAX(
    _lan_data, metric, "metric", "2", "metric value for this LAN entry", 0, RFC7181_METRIC_MIN, RFC7181_METRIC_MAX),
  CFG_MAP_INT32_MINMAX(_lan_data, distance, "distance", "1", "routing table distance for this LAN entry", 0, 1, 255),
};

static struct cfg_schema_section _olsrv2_lan_section = {
  .type = OONF_OLSRV2_LAN_SUBSYSTEM,
  .mode = CFG_SSMODE_NAMED,
  .cb_delta_handler = _cb_cfg_olsrv2_lan_changed,
  .entries = _olsrv2_lan_entries,
  .entry_count = ARRAYSIZE(_olsrv2_lan_entries),
};

static const char *_dependencies[] = {
  OONF_OLSRV2_SUBSYSTEM,
};
static struct oonf_subsystem _olsrv2_lan_subsystem = {
  .name = OONF_OLSRV2_LAN_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .init = _init,
  .cleanup = _cleanup,
  .cfg_section = &_olsrv2_lan_section,
};
DECLARE_OONF_PLUGIN(_olsrv2_lan_subsystem);

/**
 * Initialize OLSRV2 old LAN subsystem
 * @return -1 if an error happened, 0 otherwise
 */
static int
_init(void) {
  return 0;
}

/**
 * Cleanup OLSRV2 subsystem
 */
static void
_cleanup(void) {
  /* TODO: cleanup set LAN entries */
}

/**
 * Add or remove a set of "lan data" gathered from config
 * @param data data to add/remove
 * @param add true to add data, false to remove it
 */
static void
_apply_lan_data(struct _lan_data *data, bool add) {
  struct nhdp_domain *domain;

  if (netaddr_is_unspec(&data->prefix.src)) {
    switch (netaddr_get_address_family(&data->prefix.dst)) {
      case AF_INET:
        memcpy(&data->prefix.src, &NETADDR_IPV4_ANY, sizeof(data->prefix.src));
        break;
      case AF_INET6:
        memcpy(&data->prefix.src, &NETADDR_IPV6_ANY, sizeof(data->prefix.src));
        break;
      default:
        return;
    }
  }

  if (data->extension == LAN_DEFAULT_DOMAIN) {
    /* all domains */
    list_for_each_element(nhdp_domain_get_list(), domain, _node) {
      if (add) {
        olsrv2_lan_add(domain, &data->prefix, data->metric, data->distance);
      }
      else {
        olsrv2_lan_remove(domain, &data->prefix);
      }
    }
  }
  else {
    domain = nhdp_domain_add(data->extension);
    if (domain) {
      if (add) {
        olsrv2_lan_add(domain, &data->prefix, data->metric, data->distance);
      }
      else {
        olsrv2_lan_remove(domain, &data->prefix);
      }
    }
  }
}

/**
 * Callback fired when olsrv2 section changed
 */
static void
_cb_cfg_olsrv2_lan_changed(void) {
  struct _lan_data data;

  if (_olsrv2_lan_section.pre) {
    if (cfg_schema_tobin(&data, _olsrv2_lan_section.pre, _olsrv2_lan_entries, ARRAYSIZE(_olsrv2_lan_entries))) {
      OONF_WARN(LOG_OLSRV2_LAN, "Could not convert section %s to binary", _olsrv2_lan_section.type);
      return;
    }

    _apply_lan_data(&data, false);
  }
  if (_olsrv2_lan_section.post) {
    if (cfg_schema_tobin(&data, _olsrv2_lan_section.post, _olsrv2_lan_entries, ARRAYSIZE(_olsrv2_lan_entries))) {
      OONF_WARN(LOG_OLSRV2_LAN, "Could not convert section %s to binary", _olsrv2_lan_section.type);
      return;
    }

    _apply_lan_data(&data, true);
  }
}
