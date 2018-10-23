
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

#include <oonf/libcommon/autobuf.h>
#include <oonf/libcommon/bitmap256.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/isonumber.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcommon/netaddr_acl.h>

#include <oonf/libconfig/cfg.h>
#include <oonf/libconfig/cfg_help.h>

static const char *_get_enumerator(char *buffer, size_t length, size_t idx);

/**
 * Produce help text for string with maximum length
 * @param out output buffer
 * @param len maximum length
 */
void
cfg_help_strlen(struct autobuf *out, size_t len) {
  cfg_append_printable_line(out,
    CFG_HELP_INDENT_PREFIX "Parameter must have a maximum"
                           " length of %" PRINTF_SIZE_T_SPECIFIER " characters",
    len);
}

/**
 * Produce help text for printable string with maximum length
 * @param out output buffer
 * @param len maximum length
 */
void
cfg_help_printable(struct autobuf *out, size_t len) {
  cfg_help_strlen(out, len);
  cfg_append_printable_line(out, CFG_HELP_INDENT_PREFIX "Parameter must only contain printable characters.");
}

/**
 * Produce help text for a choice of multiple constants
 * @param out output buffer
 * @param preamble true if preamble should be printed
 * @param callback callback function that provides the choices for configuration
 * @param choice_count number of strings in list
 * @param ptr customization pointer for callback
 */
void
cfg_help_choice(struct autobuf *out, bool preamble, const char *(*callback)(size_t idx, const void *ptr),
  size_t choice_count, const void *ptr) {
  size_t i;

  if (preamble) {
    cfg_append_printable_line(out, CFG_HELP_INDENT_PREFIX "Parameter must be on of the following list:");
  }

  abuf_puts(out, "    ");
  for (i = 0; i < choice_count; i++) {
    abuf_appendf(out, "%s'%s'", i == 0 ? "" : ", ", callback(i, ptr));
  }
  abuf_puts(out, "\n");
}

/**
 * Produce help text for an fixed point interger
 * @param out output buffer
 * @param min minimal value
 * @param max maximal value
 * @param bytelen number of bytes the storage types has
 * @param fraction number of fractional digits
 */
void
cfg_help_int(struct autobuf *out, int64_t min, int64_t max, uint16_t bytelen, uint16_t fraction) {
  struct isonumber_str hbuf1, hbuf2;
  int64_t min64, max64;
  uint64_t j, scaling;

  min64 = INT64_MIN >> (8 * (8 - bytelen));
  max64 = INT64_MAX >> (8 * (8 - bytelen));

  for (j = 0, scaling = 1; j < fraction; j++, scaling*=10);

  /* get string representation of min/max */
  isonumber_from_s64(&hbuf1, min, "", scaling, true);
  isonumber_from_s64(&hbuf2, max, "", scaling, true);

  if (min > min64) {
    if (max < max64) {
      cfg_append_printable_line(out,
        CFG_HELP_INDENT_PREFIX "Parameter must be a %d-byte fractional integer"
                               " between %s and %s with a maximum of %d fractional digits",
        bytelen, hbuf1.buf, hbuf2.buf, fraction );
    }
    else {
      cfg_append_printable_line(out,
        CFG_HELP_INDENT_PREFIX "Parameter must be a %d-byte fractional integer"
                               " larger or equal than %s with a maximum of %d fractional digits",
        bytelen, hbuf1.buf, fraction );
    }
  }
  else {
    if (max < max64) {
      cfg_append_printable_line(out,
        CFG_HELP_INDENT_PREFIX "Parameter must be a %d-byte fractional integer"
                               " smaller or equal than %s with a maximum of %d fractional digits",
        bytelen, hbuf2.buf, fraction );
    }
    else {
      cfg_append_printable_line(out,
        CFG_HELP_INDENT_PREFIX "Parameter must be a %d-byte signed integer"
                               " with a maximum of %d fractional digits",
        bytelen, fraction );
    }
  }
}

/**
 * Produce help text for a network address
 * @param out output buffer
 * @param preamble true if preamble should be printed
 * @param prefix true if address can be a prefix, false for addresses only
 * @param af_types array of address family types
 * @param af_types_count number of address family types
 */
void
cfg_help_netaddr(struct autobuf *out, bool preamble, bool prefix, const int8_t *af_types, size_t af_types_count) {
  int8_t type;
  bool first;
  size_t i;

  if (preamble) {
    abuf_puts(out, CFG_HELP_INDENT_PREFIX "Parameter must be an address of the following type: ");
  }

  first = true;
  for (i = 0; i < af_types_count; i++) {
    type = af_types[i];

    if (type == -1) {
      continue;
    }

    if (first) {
      first = false;
    }
    else {
      abuf_puts(out, ", ");
    }

    switch (type) {
      case AF_INET:
        abuf_puts(out, "IPv4");
        break;
      case AF_INET6:
        abuf_puts(out, "IPv6");
        break;
      case AF_MAC48:
        abuf_puts(out, "MAC48");
        break;
      case AF_EUI64:
        abuf_puts(out, "EUI64");
        break;
      default:
        abuf_puts(out, "Unspec (-)");
        break;
    }
  }

  if (prefix) {
    abuf_puts(out, "\n" CFG_HELP_INDENT_PREFIX "    (the address can have an optional prefix)");
  }
  abuf_puts(out, "\n");
}

/**
 * Produce help text for access control list
 * @param out output buffer
 * @param preamble true if preamble should be printed
 * @param prefix true if ACL can accept a prefix
 * @param af_types array of address family types
 * @param af_types_count number of address family types
 */
void
cfg_help_acl(struct autobuf *out, bool preamble, bool prefix, const int8_t *af_types, size_t af_types_count) {
  if (preamble) {
    abuf_puts(out, CFG_HELP_INDENT_PREFIX "Parameter is an apache2 style access control list made from a list of "
                                          "network addresses of the following types:\n");
  }

  cfg_help_netaddr(out, false, prefix, af_types, af_types_count);

  abuf_puts(out, CFG_HELP_INDENT_PREFIX
    "    Each of the addresses/prefixes can start with a"
    " '+' to add them to the whitelist and '-' to add it to the blacklist"
    " (default is the whitelist).\n" CFG_HELP_INDENT_PREFIX
    "    In addition to this there are four keywords to configure the ACL:\n" CFG_HELP_INDENT_PREFIX
    "    - '" ACL_FIRST_ACCEPT "' to parse the whitelist first\n" CFG_HELP_INDENT_PREFIX "    - '" ACL_FIRST_REJECT
    "' to parse the blacklist first\n" CFG_HELP_INDENT_PREFIX "    - '" ACL_DEFAULT_ACCEPT
    "' to accept input if it doesn't match either list\n" CFG_HELP_INDENT_PREFIX "    - '" ACL_DEFAULT_REJECT
    "' to not accept it if it doesn't match either list\n" CFG_HELP_INDENT_PREFIX
    "    (default mode is '" ACL_FIRST_ACCEPT "' and '" ACL_DEFAULT_REJECT "')\n");
}

/**
 * Produce help text for bitmap of 256 bit length
 * @param out output buffer
 * @param preamble true if preamble should be printed
 */
void
cfg_help_bitmap256(struct autobuf *out, bool preamble) {
  if (preamble) {
    abuf_puts(out, CFG_HELP_INDENT_PREFIX "Parameter is a list of bit-numbers to define a bit-array.");
  }

  abuf_puts(out, CFG_HELP_INDENT_PREFIX
    "    Each of the bit-numbers must be between 0 and 255\n" CFG_HELP_INDENT_PREFIX
    "    In addition to this there are two keywords to configure the bit-array:\n" CFG_HELP_INDENT_PREFIX
    "    - '" BITMAP256_ALL "' to set all bits in the bit-array\n" CFG_HELP_INDENT_PREFIX "    - '" BITMAP256_NONE
    "' to reset all bits in the bit-array\n");
}

/**
 * Generate help text for space separated token config option
 * @param out output buffer for help text
 * @param preamble true if preamble should be printed
 * @param token_entry token entry
 * @param sub_entries sub entries that define the tokens elements
 * @param entry_count number of sub entries
 * @param customizer callbacks for customizing validation,
 *    binary conversion or help text, NULL, if none
 */
void
cfg_help_token(struct autobuf *out, bool preamble, const struct cfg_schema_entry *token_entry,
  const struct cfg_schema_entry *sub_entries, size_t entry_count,
  const struct cfg_schema_token_customizer *customizer) {
  char enum_buffer[20];
  size_t i;

  if (preamble) {
    abuf_appendf(out,
      CFG_HELP_INDENT_PREFIX "Parameter is a list of"
                             " %" PRINTF_SIZE_T_SPECIFIER " whitespace separater tokens (",
      entry_count);
    for (i = 0; i < entry_count; i++) {
      abuf_appendf(out, "%s%s", i == 0 ? "" : ", ", sub_entries[i].key.entry);
    }
    abuf_puts(out, ").\n" CFG_HELP_INDENT_PREFIX "The last token gets the rest of the string, regardless of"
                   " the number of whitespaces used.\n\n");
  }
  if (customizer && customizer->cb_valhelp) {
    customizer->cb_valhelp(token_entry, out);
  }

  for (i = 0; i < entry_count; i++) {
    abuf_appendf(out, CFG_HELP_INDENT_PREFIX "Description of the %s token '%s':\n",
      _get_enumerator(enum_buffer, sizeof(enum_buffer), i), sub_entries[i].key.entry);

    if (sub_entries[i].help) {
      abuf_appendf(out, CFG_HELP_INDENT_PREFIX CFG_HELP_INDENT_PREFIX "%s\n", sub_entries[i].help);
    }
    if (sub_entries[i].cb_valhelp) {
      sub_entries[i].cb_valhelp(&sub_entries[i], out);
    }
    abuf_puts(out, "\n");
  }
}

/**
 * Get enumeration word for a certain index (first, second, ...)
 * @param buffer target buffer to copy word into
 * @param length length of buffer
 * @param idx index of word, starting with zero
 * @return pointer to buffer
 */
static const char *
_get_enumerator(char *buffer, size_t length, size_t idx) {
  static const char *_ENUMERATIONS[] = { "first", "second", "third", "fourth", "fifth", "sixth", "seventh", "eight",
    "ninth", "tenth" };

  if (idx < ARRAYSIZE(_ENUMERATIONS)) {
    strscpy(buffer, _ENUMERATIONS[idx], length);
  }
  else {
    snprintf(buffer, length, "%" PRINTF_SIZE_T_SPECIFIER ".", idx + 1);
  }
  return buffer;
}
