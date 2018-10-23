
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

#include <errno.h>
#include <fcntl.h>

#include <oonf/oonf.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcommon/string.h>
#include <oonf/libcore/oonf_logging.h>
#include <oonf/base/os_interface.h>

#include <oonf/base/os_fd.h>

/**
 * Join a socket into a multicast group
 * @param sock filedescriptor of socket
 * @param multicast multicast-group to join
 * @param os_if pointer to outgoing interface data for multicast
 * @param log_src logging source for error messages
 * @return -1 if an error happened, 0 otherwise
 */
int
os_fd_generic_join_mcast_recv(struct os_fd *sock, const struct netaddr *multicast, const struct os_interface *os_if,
  enum oonf_log_source log_src __attribute__((unused))) {
  struct netaddr_str buf1, buf2;
  struct ip_mreq v4_mreq;
  struct ipv6_mreq v6_mreq;
  const char *ifname = "*";

  if (os_if) {
    ifname = os_if->name;
  }

  if (netaddr_get_address_family(multicast) == AF_INET) {
    const struct netaddr *src;

    if (os_if) {
      if (netaddr_is_unspec(os_if->if_linklocal_v4)) {
        src = os_if->if_v4;
      }
      else {
        src = os_if->if_linklocal_v4;
      }
    }
    else {
      src = &NETADDR_IPV4_ANY;
    }

    OONF_DEBUG(log_src, "Socket on interface %s joining receiving multicast %s (src %s)\n", ifname,
      netaddr_to_string(&buf2, multicast), netaddr_to_string(&buf1, src));

    netaddr_to_binary(&v4_mreq.imr_multiaddr, multicast, 4);
    netaddr_to_binary(&v4_mreq.imr_interface, src, 4);

    if (setsockopt(sock->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &v4_mreq, sizeof(v4_mreq)) < 0) {
      OONF_WARN(log_src, "Cannot join multicast group %s (src %s) on interface %s: %s (%d)\n",
        netaddr_to_string(&buf1, multicast), netaddr_to_string(&buf2, src), ifname, strerror(errno), errno);
      return -1;
    }
  }
  else {
    int if_index;

    if_index = os_if == NULL ? 0 : os_if->index;

    OONF_DEBUG(log_src, "Socket on interface %s joining receiving multicast %s (if %d)\n", ifname,
      netaddr_to_string(&buf2, multicast), if_index);

    netaddr_to_binary(&v6_mreq.ipv6mr_multiaddr, multicast, 16);
    v6_mreq.ipv6mr_interface = if_index;

    if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &v6_mreq, sizeof(v6_mreq)) < 0) {
      OONF_WARN(log_src, "Cannot join multicast group %s on interface %s: %s (%d)\n",
        netaddr_to_string(&buf1, multicast), ifname, strerror(errno), errno);
      return -1;
    }
  }
  return 0;
}

/**
 * Join a socket into a multicast group
 * @param sock filedescriptor of socket
 * @param multicast multicast ip/port to join
 * @param os_if pointer to outgoing interface data for multicast
 * @param loop true if multicast loop should be activated, false otherwise
 * @param ttl TTL of the multicast, 0 will be considered as ttl 1
 * @param log_src logging source for error messages
 * @return -1 if an error happened, 0 otherwise
 */
int
os_fd_generic_join_mcast_send(struct os_fd *sock, const struct netaddr *multicast, const struct os_interface *os_if,
  bool loop, uint8_t ttl, enum oonf_log_source log_src __attribute__((unused))) {
  struct netaddr_str buf1, buf2;
  unsigned i;

  if (netaddr_get_address_family(multicast) == AF_INET) {
    OONF_DEBUG(log_src, "Socket on interface %s joining sending multicast %s (src %s)\n", os_if->name,
      netaddr_to_string(&buf2, multicast), netaddr_to_string(&buf1, os_if->if_v4));

    if (setsockopt(sock->fd, IPPROTO_IP, IP_MULTICAST_IF, netaddr_get_binptr(os_if->if_v4), 4) < 0) {
      OONF_WARN(log_src, "Cannot set multicast %s on interface %s (src %s): %s (%d)\n",
        netaddr_to_string(&buf2, multicast), os_if->name, netaddr_to_string(&buf1, os_if->if_v4), strerror(errno),
        errno);
      return -1;
    }

    i = loop ? 1 : 0;
    if (setsockopt(sock->fd, IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&i, sizeof(i)) < 0) {
      OONF_WARN(log_src, "Cannot %sactivate local loop of multicast interface: %s (%d)\n", loop ? "" : "de",
        strerror(errno), errno);
      return -1;
    }

    i = ttl > 0 ? ttl : 1;
    if (setsockopt(sock->fd, IPPROTO_IP, IP_MULTICAST_TTL, &i, sizeof(i)) < 0) {
      OONF_WARN(log_src, "Cannot set multicast TTL to %u: %s (%d)", i, strerror(errno), errno);
      return -1;
    }
  }
  else {
    OONF_DEBUG(log_src, "Socket on interface %s (%d) joining sending multicast %s (src %s)\n", os_if->name,
      os_if->index, netaddr_to_string(&buf2, multicast), netaddr_to_string(&buf1, os_if->if_linklocal_v6));

    if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &os_if->index, sizeof(os_if->index)) < 0) {
      OONF_WARN(log_src, "Cannot set multicast %s on interface %s (src %s): %s (%d)\n",
        netaddr_to_string(&buf2, multicast), os_if->name, netaddr_to_string(&buf1, os_if->if_linklocal_v6),
        strerror(errno), errno);
      return -1;
    }

    i = loop ? 1 : 0;
    if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &i, sizeof(i)) < 0) {
      OONF_WARN(log_src, "Cannot deactivate local loop of multicast interface: %s (%d)\n", strerror(errno), errno);
      return -1;
    }

    i = ttl > 0 ? ttl : 1;
    if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &i, sizeof(i)) < 0) {
      OONF_WARN(log_src, "Cannot set multicast TTL to %u: %s (%d)", i, strerror(errno), errno);
      return -1;
    }
  }
  return 0;
}
