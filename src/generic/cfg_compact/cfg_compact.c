
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
#include <glob.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <oonf/libcommon/autobuf.h>
#include <oonf/libconfig/cfg.h>
#include <oonf/libconfig/cfg_io.h>
#include <oonf/libcore/oonf_subsystem.h>

#include <oonf/libcore/oonf_cfg.h>

#include <oonf/generic/cfg_compact/cfg_compact.h>

static void _early_cfg_init(void);
static void _cleanup(void);

static struct cfg_db *_cb_compact_loadall(const char *param, struct autobuf *log);
static int _cb_compact_save(const char *param, struct cfg_db *src, struct autobuf *log);

static int _cb_compact_load(struct cfg_db *db, const char *param, struct autobuf *log);
static int _compact_parse(struct cfg_db *db, struct autobuf *input, struct autobuf *log);
static int _compact_serialize(struct autobuf *dst, struct cfg_db *src, struct autobuf *log);
static int _parse_line(
  struct cfg_db *db, char *line, char *section, size_t section_size, char *name, size_t name_size, struct autobuf *log);

static struct oonf_subsystem _oonf_cfg_compact_subsystem = {
  .name = OONF_CFG_COMPACT_SUBSYSTEM,
  .descr = "OONFD compact configuration file handler",
  .author = "Henning Rogge",

  .cleanup = _cleanup,
  .early_cfg_init = _early_cfg_init,

  .no_logging = true,
};
DECLARE_OONF_PLUGIN(_oonf_cfg_compact_subsystem);

static struct cfg_io _cfg_compact = {
  .name = "compact",
  .load = _cb_compact_loadall,
  .save = _cb_compact_save,
  .def = true,
};

/**
 * Callback to hook plugin into configuration system.
 */
static void
_early_cfg_init(void) {
  cfg_io_add(oonf_cfg_get_instance(), &_cfg_compact);
}

/**
 * Destructor of plugin
 */
static void
_cleanup(void) {
  cfg_io_remove(oonf_cfg_get_instance(), &_cfg_compact);
}

/**
 * Reads all files from filesystem which match the given pattern,
 * parse them with the help of a configuration parser and returns
 * a configuration database.
 * @param param file pattern to be read
 * @param log autobuffer for logging purpose
 * @return pointer to configuration database, NULL if an error happened
 */
static struct cfg_db *
_cb_compact_loadall(const char *param, struct autobuf *log) {
  glob_t globbuf;
  struct cfg_db *db;
  size_t i;

  db = cfg_db_add();
  if (!db) {
    cfg_append_printable_line(log, "Out of memory for database");
    return NULL;
  }

  memset(&globbuf, 0, sizeof(globbuf));
  switch (glob(param, GLOB_DOOFFS, NULL, &globbuf)) {
    case GLOB_NOSPACE:
      cfg_append_printable_line(log, "Out of memory for glob (%s)", param);
      break;
    case GLOB_ABORTED:
      cfg_append_printable_line(log, "glob aborted (%s)", param);
      break;
    case GLOB_NOMATCH:
      cfg_append_printable_line(log, "no match for file pattern '%s'", param);
      break;
    default:
      for (i = 0; i < globbuf.gl_pathc; i++) {
        if (_cb_compact_load(db, globbuf.gl_pathv[i], log)) {
          break;
        }
      }
      globfree(&globbuf);
      return db;
  }

  cfg_db_remove(db);
  globfree(&globbuf);
  return NULL;
}

/**
 * Reads a file from a filesystem, parse it with the help of a
 * configuration parser and returns a configuration database.
 * @param db pointer to configuration database
 * @param param file to be read
 * @param log autobuffer for logging purpose
 * @return -1 if an error happened, 0 otherwise
 */

static int
_cb_compact_load(struct cfg_db *db, const char *param, struct autobuf *log) {
  struct autobuf dst;
  char buffer[1024];
  int fd = 0, result;
  ssize_t bytes;

  fd = open(param, O_RDONLY, 0);
  if (fd == -1) {
    cfg_append_printable_line(
      log, "Cannot open file '%s' to read configuration: %s (%d)", param, strerror(errno), errno);
    return -1;
  }

  bytes = 1;
  if (abuf_init(&dst)) {
    cfg_append_printable_line(log, "Out of memory error while allocating io buffer");
    close(fd);
    return -1;
  }

  /* read file into binary buffer */
  while (bytes > 0) {
    bytes = read(fd, buffer, sizeof(buffer));
    if (bytes < 0 && errno != EINTR) {
      cfg_append_printable_line(log, "Error while reading file '%s': %s (%d)", param, strerror(errno), errno);
      close(fd);
      abuf_free(&dst);
      return -1;
    }

    if (bytes > 0) {
      abuf_memcpy(&dst, buffer, (size_t)bytes);
    }
  }
  close(fd);

  if (abuf_has_failed(&dst)) {
    return -1;
  }
  result = _compact_parse(db, &dst, log);

  abuf_free(&dst);
  return result;
}

/**
 * Stores a configuration database into a file. It will use a
 * parser (the serialization part) to translate the database into
 * a storage format.
 * @param param pathname to write configuration file into
 * @param src_db source configuration database
 * @param log autobuffer for logging purpose
 * @return 0 if database was stored sucessfully, -1 otherwise
 */
static int
_cb_compact_save(const char *param, struct cfg_db *src_db, struct autobuf *log) {
  int fd = 0;
  ssize_t bytes;
  size_t total;
  struct autobuf abuf;

  if (abuf_init(&abuf)) {
    cfg_append_printable_line(log, "Out of memory error while allocating io buffer");
    return -1;
  }
  if (_compact_serialize(&abuf, src_db, log)) {
    abuf_free(&abuf);
    return -1;
  }

  fd = open(param, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  if (fd == -1) {
    cfg_append_printable_line(
      log, "Cannot open file '%s' for writing configuration: %s (%d)", param, strerror(errno), errno);
    return -1;
  }

  total = 0;
  while (total < abuf_getlen(&abuf)) {
    bytes = write(fd, abuf_getptr(&abuf) + total, abuf_getlen(&abuf) - total);
    if (bytes <= 0 && errno != EINTR) {
      cfg_append_printable_line(log, "Error while writing to file '%s': %s (%d)", param, strerror(errno), errno);
      close(fd);
      return -1;
    }

    if (bytes > 0) {
      total += (size_t)bytes;
    }
  }
  close(fd);
  abuf_free(&abuf);

  return 0;
}

/**
 * Parse a buffer into a configuration database
 * @param db pointer to configuration database
 * @param input autobuffer with configuration input
 * @param log autobuffer for logging output
 * @return -1 if an error happened, 0 otherwise
 */
static int
_compact_parse(struct cfg_db *db, struct autobuf *input, struct autobuf *log) {
  char section[128];
  char name[128];
  char *src;
  size_t len, eol, line;

  src = abuf_getptr(input);
  len = abuf_getlen(input);

  memset(section, 0, sizeof(section));
  memset(name, 0, sizeof(name));

  line = 0;
  while (line < len) {
    /* find end of line */
    eol = line;
    while (src[eol] != 0 && src[eol] != '\n') {
      eol++;
    }

    /* termiate line with zero byte */
    src[eol] = 0;
    if (eol > line && src[eol - 1] == '\r') {
      /* handle \r\n line ending */
      src[eol - 1] = 0;
    }

    if (_parse_line(db, &src[line], section, sizeof(section), name, sizeof(name), log)) {
      return -1;
    }
    line = eol + 1;
  }
  return 0;
}

/**
 * Serialize a configuration database into a buffer
 * @param dst target buffer
 * @param src source configuration database
 * @param log autbuffer for logging
 * @return 0 if database was serialized, -1 otherwise
 */
static int
_compact_serialize(struct autobuf *dst, struct cfg_db *src, struct autobuf *log __attribute__((unused))) {
  struct cfg_section_type *section, *s_it;
  struct cfg_named_section *name, *n_it;
  struct cfg_entry *entry, *e_it;
  char *ptr;

  CFG_FOR_ALL_SECTION_TYPES(src, section, s_it) {
    CFG_FOR_ALL_SECTION_NAMES(section, name, n_it) {
      if (cfg_db_is_named_section(name)) {
        abuf_appendf(dst, "[%s=%s]\n", section->type, name->name);
      }
      else {
        abuf_appendf(dst, "[%s]\n", section->type);
      }

      CFG_FOR_ALL_ENTRIES(name, entry, e_it) {
        strarray_for_each_element(&entry->val, ptr) {
          abuf_appendf(dst, "\t%s %s\n", entry->name, ptr);
        }
      }
    }
  }
  return 0;
}

/**
 * Parse a single line of the compact format
 * @param db pointer to configuration database
 * @param line pointer to line to be parsed (will be modified
 *   during parsing)
 * @param section pointer to array with current section type
 *   (might be modified during parsing)
 * @param section_size number of bytes for section type
 * @param name pointer to array with current section name
 *   (might be modified during parsing)
 * @param name_size number of bytes for section name
 * @param log autobuffer for logging output
 * @return 0 if line was parsed successfully, -1 otherwise
 */
static int
_parse_line(struct cfg_db *db, char *line, char *section, size_t section_size, char *name, size_t name_size,
  struct autobuf *log) {
  char *first, *ptr;
  bool dummy;

  /* trim leading and trailing whitespaces */
  first = str_trim(line);

  if (*first == 0 || *first == '#') {
    /* empty line or comment */
    return 0;
  }

  if (*first == '[') {
    first++;
    ptr = strchr(first, ']');
    if (ptr == NULL) {
      cfg_append_printable_line(log, "Section syntax error in line: '%s'", line);
      return -1;
    }
    *ptr = 0;

    ptr = strchr(first, '=');
    if (ptr) {
      /* trim section name */
      *ptr++ = 0;
      ptr = str_trim(ptr);
    }

    /* trim section name */
    first = str_trim(first);
    if (*first == 0) {
      cfg_append_printable_line(log, "Section syntax error, no section type found");
      return -1;
    }

    /* copy section type */
    strscpy(section, first, section_size);

    /* copy section name */
    if (ptr) {
      strscpy(name, ptr, name_size);
    }
    else {
      *name = 0;
    }

    /* validity of section type (and name) */
    if (!cfg_is_allowed_key(section)) {
      cfg_append_printable_line(log, "Illegal section type: '%s'", section);
      return -1;
    }

    if (*name != 0 && !cfg_is_allowed_section_name(name)) {
      cfg_append_printable_line(log, "Illegal section name: '%s'", name);
      return -1;
    }

    /* add section to db */
    if (_cfg_db_add_section(db, section, *name ? name : NULL, &dummy) == NULL) {
      return -1;
    }
    return 0;
  }

  if (*section == 0) {
    cfg_append_printable_line(log, "Entry before first section is not allowed in this format");
    return -1;
  }

  ptr = first;

  /* look for separator */
  while (!isspace(*ptr)) {
    ptr++;
  }

  *ptr++ = 0;

  /* trim second token */
  ptr = str_trim(ptr);

  if (*ptr == 0) {
    cfg_append_printable_line(log, "No second token found in line '%s'", line);
    return -1;
  }

  if (!cfg_is_allowed_key(first)) {
    cfg_append_printable_line(log, "Illegal key type: '%s'", first);
    return -1;
  }

  /* found two tokens */
  if (!cfg_db_add_entry(db, section, *name ? name : NULL, first, ptr)) {
    return -1;
  }
  return 0;
}
