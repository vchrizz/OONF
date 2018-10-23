
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

#include <oonf/olsrv2/olsrv2_old_lan/old_lan.h>

/*! logging for plugin */
#define LOG_OLD_LAN _old_lan_subsystem.logging

/*! configuration option for locally attached networks */
#define _LOCAL_ATTACHED_NETWORK_KEY "lan"

/**
 * Default values for locally attached network parameters
 */
enum _lan_option_defaults
{
  LAN_DEFAULT_DOMAIN = 0,   //!< LAN_DEFAULT_DOMAIN
  LAN_DEFAULT_METRIC = 1,   //!< LAN_DEFAULT_METRIC
  LAN_DEFAULT_DISTANCE = 2, //!< LAN_DEFAULT_DISTANCE
};

/*! locally attached network option for source-specific prefix */
#define LAN_OPTION_SRC "src="

/*! locally attached network option for outgoing metric */
#define LAN_OPTION_METRIC "metric="

/*! locally attached network option for domain */
#define LAN_OPTION_DOMAIN "domain="

/*! locally attached network option for hopcount distance */
#define LAN_OPTION_DIST "dist="

/**
 * Additional parameters of a single locally attached network
 */
struct _lan_data {
  /*! extension domain of LAN */
  int32_t ext;

  /*! source prefix */
  struct netaddr source_prefix;

  /*! olsrv2 metric */
  uint32_t metric;

  /*! routing metric (distance) */
  uint32_t dist;
};

/* prototypes */
static int _init(void);
static void _cleanup(void);

static const char *_parse_lan_parameters(struct os_route_key *prefix, struct _lan_data *dst, const char *src);
static void _parse_lan_array(struct cfg_named_section *section, bool add);

static void _cb_cfg_olsrv2_changed(void);

static struct cfg_schema_entry _olsrv2_entries[] = {
  CFG_VALIDATE_LAN(_LOCAL_ATTACHED_NETWORK_KEY, "",
    "locally attached network, a combination of an"
    " ip address or prefix followed by an up to four optional parameters"
    " which define link metric cost, hopcount distance, domain of the prefix"
    " and the source-prefix ( <" LAN_OPTION_METRIC "...> <" LAN_OPTION_DIST "...>"
    " <" LAN_OPTION_DOMAIN "<num>/all> <" LAN_OPTION_SRC "...> ).",
    .list = true),
};

static struct cfg_schema_section _olsrv2_section = {
  .type = CFG_OLSRV2_SECTION,
  .cb_delta_handler = _cb_cfg_olsrv2_changed,
  .entries = _olsrv2_entries,
  .entry_count = ARRAYSIZE(_olsrv2_entries),
};

static const char *_dependencies[] = {
  OONF_OLSRV2_SUBSYSTEM,
};
static struct oonf_subsystem _old_lan_subsystem = {
  .name = OONF_OLD_LAN_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .init = _init,
  .cleanup = _cleanup,
  .cfg_section = &_olsrv2_section,
};
DECLARE_OONF_PLUGIN(_old_lan_subsystem);

/**
 * Initialize OLSRV2 old LAN subsystem
 * @return -1 if an error happened, 0 otherwise
 */
static int
_init(void) {
  OONF_WARN(LOG_OLD_LAN, "Old LAN plugin does add support for the"
                         " deprecated olsrv2/lan config option");
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
 * Schema entry validator for an attached network.
 * See CFG_VALIDATE_ACL_*() macros.
 * @param entry pointer to schema entry
 * @param section_name name of section type and name
 * @param value value of schema entry
 * @param out pointer to autobuffer for validator output
 * @return 0 if validation found no problems, -1 otherwise
 */
int
olsrv2_validate_lan(
  const struct cfg_schema_entry *entry, const char *section_name, const char *value, struct autobuf *out) {
  struct netaddr_str buf;
  struct _lan_data data;
  const char *ptr, *result;
  struct os_route_key prefix;

  if (value == NULL) {
    cfg_schema_help_netaddr(entry, out);
    cfg_append_printable_line(out, "    This value is followed by a list of four optional parameters.");
    cfg_append_printable_line(out,
      "    - '" LAN_OPTION_SRC "<prefix>' the source specific prefix of this attached network."
      " The default is 2.");
    cfg_append_printable_line(out,
      "    - '" LAN_OPTION_METRIC "<m>' the link metric of the LAN (between %u and %u)."
      " The default is 0.",
      RFC7181_METRIC_MIN, RFC7181_METRIC_MAX);
    cfg_append_printable_line(out,
      "    - '" LAN_OPTION_DOMAIN "<d>' the domain of the LAN (between 0 and 255) or 'all'."
      " The default is all.");
    cfg_append_printable_line(out,
      "    - '" LAN_OPTION_DIST "<d>' the hopcount distance of the LAN (between 0 and 255)."
      " The default is 2.");
    return 0;
  }

  ptr = str_cpynextword(buf.buf, value, sizeof(buf));
  if (cfg_schema_validate_netaddr(entry, section_name, buf.buf, out)) {
    /* check prefix first */
    return -1;
  }

  if (netaddr_from_string(&prefix.dst, buf.buf)) {
    return -1;
  }

  result = _parse_lan_parameters(&prefix, &data, ptr);
  if (result) {
    cfg_append_printable_line(out,
      "Value '%s' for entry '%s'"
      " in section %s has %s",
      value, entry->key.entry, section_name, result);
    return -1;
  }

  if (data.metric < RFC7181_METRIC_MIN || data.metric > RFC7181_METRIC_MAX) {
    cfg_append_printable_line(out, "Metric %u for prefix %s must be between %u and %u", data.metric, buf.buf,
      RFC7181_METRIC_MIN, RFC7181_METRIC_MAX);
    return -1;
  }
  if (data.dist > 255) {
    cfg_append_printable_line(out, "Distance %u for prefix %s must be between 0 and 255", data.dist, buf.buf);
    return -1;
  }

  return 0;
}

/**
 * Parse parameters of lan prefix string
 * @param prefix source specific prefix (to store source prefix)
 * @param dst pointer to data structure to store results.
 * @param src source string
 * @return NULL if parser worked without an error, a pointer
 *   to the suffix of the error message otherwise.
 */
static const char *
_parse_lan_parameters(struct os_route_key *prefix, struct _lan_data *dst, const char *src) {
  char buffer[64];
  const char *ptr, *next;
  unsigned ext;

  ptr = src;
  dst->ext = -1;
  dst->metric = LAN_DEFAULT_METRIC;
  dst->dist = LAN_DEFAULT_DISTANCE;

  while (ptr != NULL) {
    next = str_cpynextword(buffer, ptr, sizeof(buffer));

    if (strncasecmp(buffer, LAN_OPTION_METRIC, 7) == 0) {
      dst->metric = strtoul(&buffer[7], NULL, 0);
      if (dst->metric == 0 && errno != 0) {
        return "an illegal metric parameter";
      }
    }
    else if (strncasecmp(buffer, LAN_OPTION_DOMAIN, 7) == 0) {
      if (strcasecmp(&buffer[7], "all") == 0) {
        dst->ext = -1;
      }
      else {
        ext = strtoul(&buffer[7], NULL, 10);
        if ((ext == 0 && errno != 0) || ext > 255) {
          return "an illegal domain parameter";
        }
        dst->ext = ext;
      }
    }
    else if (strncasecmp(buffer, LAN_OPTION_DIST, 5) == 0) {
      dst->dist = strtoul(&buffer[5], NULL, 10);
      if (dst->dist == 0 && errno != 0) {
        return "an illegal distance parameter";
      }
    }
    else if (strncasecmp(buffer, LAN_OPTION_SRC, 4) == 0) {
      if (netaddr_from_string(&prefix->src, &buffer[4])) {
        return "an illegal source prefix";
      }
      if (netaddr_get_address_family(&prefix->dst) != netaddr_get_address_family(&prefix->src)) {
        return "an illegal source prefix address type";
      }
      if (!os_routing_supports_source_specific(netaddr_get_address_family(&prefix->dst))) {
        return "an unsupported sourc specific prefix";
      }
    }
    else {
      return "an unknown parameter";
    }
    ptr = next;
  }
  return NULL;
}

/**
 * Takes a named configuration section, extracts the attached network
 * array and apply it
 * @param section pointer to configuration section.
 * @param add true if new lan entries should be created, false if
 *   existing entries should be removed.
 */
static void
_parse_lan_array(struct cfg_named_section *section, bool add) {
  struct netaddr_str addr_buf;
  struct netaddr addr;
  struct os_route_key prefix;
  struct _lan_data data;
  struct nhdp_domain *domain;

  const char *value, *ptr;
  struct cfg_entry *entry;

  if (section == NULL) {
    return;
  }

  entry = cfg_db_get_entry(section, _LOCAL_ATTACHED_NETWORK_KEY);
  if (entry == NULL) {
    return;
  }

  strarray_for_each_element(&entry->val, value) {
    /* extract data */
    ptr = str_cpynextword(addr_buf.buf, value, sizeof(addr_buf));
    if (netaddr_from_string(&addr, addr_buf.buf)) {
      continue;
    }

    os_routing_init_sourcespec_prefix(&prefix, &addr);

    /* truncate address */
    netaddr_truncate(&prefix.dst, &prefix.dst);

    if (_parse_lan_parameters(&prefix, &data, ptr)) {
      continue;
    }

    if (data.ext == -1) {
      list_for_each_element(nhdp_domain_get_list(), domain, _node) {
        if (add) {
          olsrv2_lan_add(domain, &prefix, data.metric, data.dist);
        }
        else {
          olsrv2_lan_remove(domain, &prefix);
        }
      }
    }
    else {
      domain = nhdp_domain_add(data.ext);
      if (!domain) {
        continue;
      }
      if (add) {
        olsrv2_lan_add(domain, &prefix, data.metric, data.dist);
      }
      else {
        olsrv2_lan_remove(domain, &prefix);
      }
    }
  }
}

/**
 * Callback fired when olsrv2 section changed
 */
static void
_cb_cfg_olsrv2_changed(void) {
  /* run through all pre-update LAN entries and remove them */
  _parse_lan_array(_olsrv2_section.pre, false);

  /* run through all post-update LAN entries and add them */
  _parse_lan_array(_olsrv2_section.post, true);
}
