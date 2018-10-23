
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

#define _LINUX_IP_H

#include <arpa/inet.h>
#include <errno.h>
//#include <linux/if_tunnel.h>
//#include <linux/ip.h>
//#include <linux/ip6_tunnel.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/avl_comp.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/os_system.h>
#include <oonf/base/os_tunnel.h>

/* Definitions */
#define LOG_OS_TUNNEL _oonf_os_tunnel_subsystem.logging

/*
 * private copy of linux tunnel definitions to prevent bad mixture of include files
 */

#define SIOCADDTUNNEL (SIOCDEVPRIVATE + 1)
#define SIOCDELTUNNEL (SIOCDEVPRIVATE + 2)

#define IP6_TNL_F_USE_ORIG_TCLASS 0x2
#define IP6_TNL_F_USE_ORIG_FLOWLABEL 0x4

struct ip_tunnel_parm {
  char name[IF_NAMESIZE];
  int link;
  uint16_t i_flags;
  uint16_t o_flags;
  uint32_t i_key;
  uint32_t o_key;
  struct iphdr iph;
};

struct my_ip6_tnl_parm2 {
  char name[IFNAMSIZ];
  int link;
  uint8_t proto;
  uint8_t encap_limit;
  uint8_t hop_limit;
  uint32_t flowinfo;
  uint32_t flags;
  struct in6_addr laddr;
  struct in6_addr raddr;

  uint16_t i_flags;
  uint16_t o_flags;
  uint32_t i_key;
  uint32_t o_key;
};

/* prototypes */
static int _init(void);
static void _cleanup(void);

static int _handle_ipv4_tunnel(struct os_tunnel *tunnel, bool add);
static int _handle_ipv6_tunnel(struct os_tunnel *tunnel, bool add);
static int _handle_tunnel(struct os_tunnel *tunnel, bool add);

/* subsystem definition */
static const char *_dependencies[] = {
  OONF_OS_SYSTEM_SUBSYSTEM,
};

static struct oonf_subsystem _oonf_os_tunnel_subsystem = {
  .name = OONF_OS_TUNNEL_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_oonf_os_tunnel_subsystem);

enum _tunnel_if_type
{
  _TUNNEL_IP_IN_IP,
  _TUNNEL_IP_IN_IP6,
  _TUNNEL_IP6_IN_IP,
  _TUNNEL_IP6_IN_IP6,
  _TUNNEL_GRE_IN_IP,
  _TUNNEL_GRE_IN_IP6,

  /* must be last entry */
  _TUNNEL_IF_TYPE_COUNT,
};
static const char *_tunnel_base_if[] = {
  [_TUNNEL_IP_IN_IP] = "tunl0",
  [_TUNNEL_IP_IN_IP6] = "ip6tnl0",
  [_TUNNEL_IP6_IN_IP] = "sit0",
  [_TUNNEL_IP6_IN_IP6] = "ip6tnl0",
  [_TUNNEL_GRE_IN_IP] = "gre0",
  [_TUNNEL_GRE_IN_IP6] = "ip6gre0",
};

static bool _tunnel_base_up[_TUNNEL_IF_TYPE_COUNT];

static struct avl_tree _tunnel_tree;

/**
 * Initialize tunnel interface subsystem
 * @return -1 if an error happened, 0 otherwise
 */
static int
_init(void) {
  avl_init(&_tunnel_tree, avl_comp_strcasecmp, false);
  memset(_tunnel_base_up, 0, sizeof(_tunnel_base_up));
  return 0;
}

/**
 * Cleanup tunnel interface subsystem
 */
static void
_cleanup(void) {
  struct os_tunnel *tunnel, *tunnel_it;

  avl_for_each_element_safe(&_tunnel_tree, tunnel, _node, tunnel_it) {
    os_tunnel_remove(tunnel);
  }
}

/**
 * Add a new tunnel to the kernel system
 * @param tunnel initialized tunnel data
 * @return -1 if an error happened, 0 otherwise
 */
int
os_tunnel_linux_add(struct os_tunnel *tunnel) {
  int result;

  if (avl_is_node_added(&tunnel->_node)) {
    return -1;
  }

  result = _handle_tunnel(tunnel, true);
  if (!result) {
    tunnel->_node.key = tunnel->p.tunnel_if;
    avl_insert(&_tunnel_tree, &tunnel->_node);

    tunnel->if_index = if_nametoindex(tunnel->p.tunnel_if);
  }
  else {
    tunnel->if_index = 0;
  }
  return result;
}

/**
 * Remove an existing tunnel to the kernel system
 * @param tunnel initialized tunnel data
 * @return -1 if an error happened, 0 otherwise
 */
int
os_tunnel_linux_remove(struct os_tunnel *tunnel) {
  int result;

  if (!avl_is_node_added(&tunnel->_node)) {
    return -1;
  }

  result = _handle_tunnel(tunnel, false);
  if (!result) {
    avl_remove(&_tunnel_tree, &tunnel->_node);
  }
  return result;
}

static void
_set_base_tunnel_up(enum _tunnel_if_type type) {
  struct ifreq ifr;
  int oldflags;

  if (!_tunnel_base_up[type]) {
    /* make sure base interface is up for incoming tunnel traffic */
    memset(&ifr, 0, sizeof(ifr));
    strscpy(ifr.ifr_name, _tunnel_base_if[type], IF_NAMESIZE);

    if (ioctl(os_system_linux_linux_get_ioctl_fd(AF_INET), SIOCGIFFLAGS, &ifr) < 0) {
      OONF_WARN(LOG_OS_TUNNEL, "ioctl SIOCGIFFLAGS (get flags) error on device %s: %s (%d)\n", _tunnel_base_if[type],
        strerror(errno), errno);
      return;
    }

    oldflags = ifr.ifr_flags;
    ifr.ifr_flags |= IFF_UP;

    if (oldflags == ifr.ifr_flags) {
      /* interface is already up/down */
      return;
    }

    if (ioctl(os_system_linux_linux_get_ioctl_fd(AF_INET), SIOCSIFFLAGS, &ifr) < 0) {
      OONF_WARN(LOG_OS_TUNNEL, "ioctl SIOCSIFFLAGS (set flags up) error on device %s: %s (%d)\n", _tunnel_base_if[type],
        strerror(errno), errno);
      return;
    }

    _tunnel_base_up[type] = true;
  }
}

/**
 * Add or remove an IPv4 based tunnel
 * @param tunnel initialized tunnel data
 * @param add true if tunnel should be added, false for removal
 * @return -1 if an error happened, 0 otherwise
 */
static int
_handle_ipv4_tunnel(struct os_tunnel *tunnel, bool add) {
  struct ip_tunnel_parm p;
  enum _tunnel_if_type type;
  struct ifreq ifr;
  int err;

  memset(&p, 0, sizeof(p));
  memset(&ifr, 0, sizeof(ifr));

  p.iph.version = 4;
  p.iph.ihl = 5;
  p.iph.frag_off = htons(IP_DF);

  strscpy(p.name, tunnel->p.tunnel_if, IF_NAMESIZE);
  if (tunnel->p.base_if[0]) {
    p.link = if_nametoindex(tunnel->p.base_if);
  }
  ifr.ifr_ifru.ifru_data = (void *)&p;

  switch (tunnel->p.inner_type) {
    case OS_TUNNEL_IPV4:
      p.iph.protocol = IPPROTO_IPIP;
      type = _TUNNEL_IP_IN_IP;
      break;
    case OS_TUNNEL_IPV6:
      p.iph.protocol = IPPROTO_IPV6;
      type = _TUNNEL_IP_IN_IP;
      break;
    case OS_TUNNEL_GRE:
      p.iph.protocol = IPPROTO_GRE;
      type = _TUNNEL_IP_IN_IP;
      break;
    default:
      return -1;
  }

  /* inherit TTL by default */
  p.iph.ttl = tunnel->p.tunnel_ttl;

  /* try to inherit TOS */
  if (tunnel->p.inhert_tos) {
    p.iph.tos = 1;
  }

  strscpy(ifr.ifr_name, _tunnel_base_if[type], IF_NAMESIZE);

  netaddr_to_binary(&p.iph.saddr, &tunnel->p.local, sizeof(p.iph.saddr));
  netaddr_to_binary(&p.iph.daddr, &tunnel->p.remote, sizeof(p.iph.daddr));

  err = ioctl(os_system_linux_linux_get_ioctl_fd(AF_INET), add ? SIOCADDTUNNEL : SIOCDELTUNNEL, &ifr);
  if (err) {
    if (add && (errno == EEXIST)) {
      /* tunnel with this name already exists, try to remove it! */
      err = ioctl(os_system_linux_linux_get_ioctl_fd(AF_INET), SIOCDELTUNNEL, &ifr);
      if (err) {
        OONF_WARN(LOG_OS_TUNNEL, "Error while %s tunnel %s: tunnel already exists and could not be removed",
          add ? "adding" : "removing", tunnel->p.tunnel_if);
        return -1;
      }
      return _handle_ipv4_tunnel(tunnel, true);
    }
    OONF_WARN(LOG_OS_TUNNEL, "Error while %s tunnel %s: %s (%d)", add ? "adding" : "removing", tunnel->p.tunnel_if,
      strerror(errno), errno);
    return -1;
  }

  if (add) {
    _set_base_tunnel_up(type);
  }
  return 0;
}

/**
 * Add or remove an IPv6 based tunnel
 * @param tunnel initialized tunnel data
 * @param add true if tunnel should be added, false for removal
 * @return -1 if an error happened, 0 otherwise
 */
static int
_handle_ipv6_tunnel(struct os_tunnel *tunnel, bool add) {
  struct my_ip6_tnl_parm2 p;
  enum _tunnel_if_type type;
  struct ifreq ifr;
  int err;
  struct netaddr_str nbuf1, nbuf2;

  memset(&p, 0, sizeof(p));
  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_ifru.ifru_data = (void *)&p;
  if (tunnel->p.base_if[0]) {
    p.link = if_nametoindex(tunnel->p.base_if);
  }

  strscpy(p.name, tunnel->p.tunnel_if, IF_NAMESIZE);

  switch (tunnel->p.inner_type) {
    case OS_TUNNEL_IPV4:
      p.proto = IPPROTO_IPIP;
      type = _TUNNEL_IP_IN_IP6;
      break;
    case OS_TUNNEL_IPV6:
      p.proto = IPPROTO_IPV6;
      type = _TUNNEL_IP6_IN_IP6;
      break;
    case OS_TUNNEL_GRE:
      p.proto = IPPROTO_GRE;
      type = _TUNNEL_GRE_IN_IP6;
      break;
    default:
      return -1;
  }

  /* set tunnel flags */
  if (tunnel->p.inhert_tos) {
    p.flags |= IP6_TNL_F_USE_ORIG_TCLASS;
  }
  if (tunnel->p.inhert_flowlabel) {
    p.flags |= IP6_TNL_F_USE_ORIG_FLOWLABEL;
  }
  if (tunnel->p.tunnel_ttl) {
    p.hop_limit = tunnel->p.tunnel_ttl;
  }

  strscpy(ifr.ifr_name, _tunnel_base_if[type], IF_NAMESIZE);

  netaddr_to_binary(&p.laddr, &tunnel->p.local, sizeof(p.laddr));
  netaddr_to_binary(&p.raddr, &tunnel->p.remote, sizeof(p.raddr));

  err = ioctl(os_system_linux_linux_get_ioctl_fd(AF_INET6), add ? SIOCADDTUNNEL : SIOCDELTUNNEL, &ifr);
  if (err) {
    OONF_WARN(LOG_OS_TUNNEL, "Error while %s tunnel %s (%d,%s,%s): %s (%d)", add ? "add" : "remove",
      tunnel->p.tunnel_if, tunnel->p.inner_type, netaddr_to_string(&nbuf1, &tunnel->p.local),
      netaddr_to_string(&nbuf2, &tunnel->p.remote), strerror(errno), errno);
    return -1;
  }

  if (add) {
    _set_base_tunnel_up(type);
  }
  return 0;
}

/**
 * Add or remove a tunnel
 * @param tunnel initialized tunnel data
 * @param add true if tunnel should be added, false for removal
 * @return -1 if an error happened, 0 otherwise
 */
static int
_handle_tunnel(struct os_tunnel *tunnel, bool add) {
  int af_type;
  struct netaddr_str nbuf1, nbuf2;

  af_type = netaddr_get_address_family(&tunnel->p.local);
  if (af_type != netaddr_get_address_family(&tunnel->p.remote)) {
    OONF_WARN(LOG_OS_TUNNEL, "Inconsistent tunnel endpoints for tunnel %s: local=%s remote=%s", tunnel->p.tunnel_if,
      netaddr_to_string(&nbuf1, &tunnel->p.local), netaddr_to_string(&nbuf2, &tunnel->p.remote));
    return -1;
  }

  switch (af_type) {
    case AF_INET:
      return _handle_ipv4_tunnel(tunnel, add);
    case AF_INET6:
      return _handle_ipv6_tunnel(tunnel, add);
    default:
      OONF_WARN(LOG_OS_TUNNEL, "Bad address family for tunnel %s: %u", tunnel->p.tunnel_if, af_type);
      return -1;
  }
}
