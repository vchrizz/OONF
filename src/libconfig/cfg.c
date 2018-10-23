
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

#include <stdio.h>
#include <strings.h>

#include <oonf/libcommon/autobuf.h>
#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/avl_comp.h>
#include <oonf/oonf.h>
#include <oonf/libconfig/cfg.h>
#include <oonf/libconfig/cfg_io.h>

static int avl_comp_cfgio(const void *txt1, const void *txt2);

/* phy interface conversion function pointer */
static int (*_get_phy_if)(char *phy_ifname, const char *ifname) = NULL;

/**
 * Initialize a configuration instance
 * @param instance pointer to cfg_instance
 */
void
cfg_add(struct cfg_instance *instance) {
  avl_init(&instance->io_tree, avl_comp_cfgio, false);
}

/**
 * Cleanup a configuration instance
 * @param instance pointer to cfg_instance
 */
void
cfg_remove(struct cfg_instance *instance) {
  struct cfg_io *io, *iit;

  CFG_FOR_ALL_IO(instance, io, iit) {
    cfg_io_remove(instance, io);
  }
}

/**
 * Appends a single line to an autobuffer.
 * The function replaces all non-printable characters with '.'
 * and will append a newline at the end
 * @param autobuf pointer to autobuf object
 * @param fmt printf format string
 * @return -1 if an out-of-memory error happened, 0 otherwise
 */
int
cfg_append_printable_line(struct autobuf *autobuf, const char *fmt, ...) {
  unsigned char *_value;
  size_t len;
  int rv;
  va_list ap;

  if (autobuf == NULL)
    return 0;

  _value = (unsigned char *)abuf_getptr(autobuf) + abuf_getlen(autobuf);
  len = abuf_getlen(autobuf);

  va_start(ap, fmt);
  rv = abuf_vappendf(autobuf, fmt, ap);
  va_end(ap);

  if (rv < 0) {
    return rv;
  }

  /* convert everything non-printable to '.' */
  while (*_value && len++ < abuf_getlen(autobuf)) {
    if (*_value < 32 || *_value == 127 || *_value == 255) {
      *_value = '.';
    }
    _value++;
  }
  abuf_append_uint8(autobuf, '\n');
  return 0;
}

/**
 * Tests on the pattern [a-zA-Z_][a-zA-Z0-9_]*
 * @param key section_type or entry name
 * @return true if input string is valid for this parser,
 *   false otherwise
 */
bool
cfg_is_allowed_key(const char *key) {
  static const char *valid = "_0123456789"
                             "abcdefghijklmnopqrstuvwxyz"
                             "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  /* test for [a-zA-Z_][a-zA-Z0-9_]* */
  if (*key >= '0' && *key <= '9') {
    return false;
  }

  return key[strspn(key, valid)] == 0;
}

/**
 * Null-pointer safe avl compare function for keys implementation.
 * NULL is considered a string smaller than all normal strings.
 * @param p1 pointer to key 1
 * @param p2 pointer to key 2
 * @return similar to strcmp()
 */
int
cfg_avlcmp_keys(const void *p1, const void *p2) {
  const char *str1 = p1;
  const char *str2 = p2;

  if (str1 == NULL) {
    return str2 == NULL ? 0 : -1;
  }
  if (str2 == NULL) {
    return 1;
  }

  return strcasecmp(str1, str2);
}

/**
 * Returns an element of a string array for the CHOICE schema entry
 * @param idx index of the array
 * @param ptr pointer to the string array
 * @return element of the string array at the index
 */
const char *
cfg_get_choice_array_value(size_t idx, const void *ptr) {
  const char *const *string_array;

  string_array = ptr;

  return string_array[idx];
}

/**
 * Looks up the index of a string within a string array
 * @param key pointer to string to be looked up in the array
 * @param callback pointer to the callback that returns choice options
 * @param choices_count number of choices
 * @param ptr (optional) pointer for choice callback
 * @return index of the string inside the array, -1 if not found
 */
int
cfg_get_choice_index(
  const char *key, const char *(*callback)(size_t idx, const void *ptr), size_t choices_count, const void *ptr) {
  size_t i;

  for (i = 0; i < choices_count; i++) {
    if (strcasecmp(key, callback(i, ptr)) == 0) {
      return (int)i;
    }
  }
  return -1;
}

/**
 * Set a handler to transform a logical interface name into a physical one
 * @param get_phy_if function pointer to transformer function, NULL to reset
 */
void
cfg_set_ifname_handler(int (*get_phy_if)(char *phy_ifname, const char *ifname)) {
  _get_phy_if = get_phy_if;
}

/**
 * Get a physical interface name from a logical one. If no handler
 * is available it will fall back to the identity function
 * (phyiscal = logical name)
 * @param phy_if target buffer for physical interface name,
 *    must be IF_NAMESIZE sized
 * @param ifname logical interface name
 * @return physical interface name (will never be NULL)
 */
const char *
cfg_get_phy_if(char *phy_if, const char *ifname) {
  if (_get_phy_if && !_get_phy_if(phy_if, ifname)) {
    return phy_if;
  }

  if (phy_if != ifname) {
    strscpy(phy_if, ifname, IF_NAMESIZE);
  }
  return phy_if;
}

/**
 * AVL tree comparator for case insensitive strings.
 * Custom pointer is the length of the memory to compare.
 * @param txt1 pointer to string 1
 * @param txt2 pointer to string 2
 * @return +1 if k1>k2, -1 if k1<k2, 0 if k1==k2
 */
static int
avl_comp_cfgio(const void *txt1, const void *txt2) {
  const char *url1 = txt1;
  const char *url2 = txt2;
  const char *ptr;
  ssize_t maxlen = -1;

  ptr = strstr(url1, CFG_IO_URL_SPLITTER);
  if (ptr) {
    maxlen = ptr - url1;
  }
  ptr = strstr(url2, CFG_IO_URL_SPLITTER);
  if (ptr) {
    if ((ptr - url2) > maxlen) {
      maxlen = ptr - url2;
    }
  }

  if (maxlen != -1) {
    return strncasecmp(url1, url2, maxlen);
  }
  return strcasecmp(txt1, txt2);
}
