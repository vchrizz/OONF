
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
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_class.h>
#include <oonf/base/oonf_rfc5444.h>

#include <oonf/nhdp/nhdp/nhdp.h>
#include <oonf/olsrv2/olsrv2/olsrv2.h>
#include <oonf/olsrv2/olsrv2/olsrv2_lan.h>
#include <oonf/olsrv2/olsrv2/olsrv2_routing.h>

static void _remove(struct olsrv2_lan_entry *entry);

/* originator set class and timer */
static struct oonf_class _lan_class = {
  .name = "OLSRV2 LAN set",
  .size = sizeof(struct olsrv2_lan_entry),
};

/* global tree of originator set entries */
static struct avl_tree _lan_tree;

/**
 * Initialize olsrv2 lan set
 */
void
olsrv2_lan_init(void) {
  oonf_class_add(&_lan_class);

  avl_init(&_lan_tree, os_routing_avl_cmp_route_key, false);
}

/**
 * Cleanup all resources allocated by orignator set
 */
void
olsrv2_lan_cleanup(void) {
  struct olsrv2_lan_entry *entry, *e_it;

  /* remove all originator entries */
  avl_for_each_element_safe(&_lan_tree, entry, _node, e_it) {
    _remove(entry);
  }

  /* remove class */
  oonf_class_remove(&_lan_class);
}

/**
 * Add a new entry to the olsrv2 local attached network
 * @param domain NHDP domain for data
 * @param prefix local attacked network prefix
 * @param metric outgoing metric
 * @param distance hopcount distance
 * @return pointer to lan entry, NULL if out of memory
 */
struct olsrv2_lan_entry *
olsrv2_lan_add(struct nhdp_domain *domain, const struct os_route_key *prefix, uint32_t metric, uint8_t distance) {
  struct olsrv2_lan_entry *entry;
  struct olsrv2_lan_domaindata *lan_data;
  uint8_t tmp_dist;
  int i;

  entry = olsrv2_lan_get(prefix);
  if (entry == NULL) {
    entry = oonf_class_malloc(&_lan_class);
    if (entry == NULL) {
      return NULL;
    }

    /* copy key and append to tree */
    memcpy(&entry->prefix, prefix, sizeof(*prefix));
    entry->_node.key = &entry->prefix;
    avl_insert(&_lan_tree, &entry->_node);

    entry->same_distance = true;

    /* initialize linkcost */
    for (i = 0; i < NHDP_MAXIMUM_DOMAINS; i++) {
      entry->_domaindata[i].outgoing_metric = RFC7181_METRIC_INFINITE;
    }
  }

  lan_data = olsrv2_lan_get_domaindata(domain, entry);
  lan_data->outgoing_metric = metric;
  lan_data->distance = distance;
  lan_data->active = true;
  olsrv2_routing_domain_changed(domain, true);

  tmp_dist = 0;
  entry->same_distance = true;
  for (i = 0; i < NHDP_MAXIMUM_DOMAINS; i++) {
    lan_data = &entry->_domaindata[i];
    if (lan_data->active) {
      if (tmp_dist == 0) {
        /* copy first valid distance */
        tmp_dist = lan_data->distance;
      }
      if (tmp_dist != lan_data->distance) {
        /* we found a difference */
        entry->same_distance = false;
        break;
      }
    }
  }
  return entry;
}

/**
 * Remove a local attached network entry
 * @param prefix local attacked network prefix
 * @param domain NHDP domain for data
 */
void
olsrv2_lan_remove(struct nhdp_domain *domain, const struct os_route_key *prefix) {
  struct olsrv2_lan_entry *entry;
  struct olsrv2_lan_domaindata *lan_data;
  int i;

  entry = olsrv2_lan_get(prefix);
  if (!entry) {
    return;
  }

  lan_data = olsrv2_lan_get_domaindata(domain, entry);
  lan_data->active = false;
  olsrv2_routing_domain_changed(domain, true);

  for (i = 0; i < NHDP_MAXIMUM_DOMAINS; i++) {
    if (entry->_domaindata[i].active) {
      /* entry is still in use */
      return;
    }
  }
  _remove(entry);
}

/**
 * Get tree of locally attached networks
 * @return lan tree
 */
struct avl_tree *
olsrv2_lan_get_tree(void) {
  return &_lan_tree;
}

/**
 * Remove a local attached network entry
 * @param entry LAN entry
 */
static void
_remove(struct olsrv2_lan_entry *entry) {
  avl_remove(&_lan_tree, &entry->_node);
  oonf_class_free(&_lan_class, entry);
}
