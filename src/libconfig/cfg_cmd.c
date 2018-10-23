
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

#include <regex.h>
#include <stdlib.h>
#include <strings.h>

#include <oonf/libcommon/autobuf.h>
#include <oonf/oonf.h>
#include <oonf/libconfig/cfg_cmd.h>
#include <oonf/libconfig/cfg_help.h>
#include <oonf/libconfig/cfg_io.h>

/**
 *  contains data parsing logic */
struct _parsed_argument {
  /*! pointer to null terminated section type, NULL if no section type */
  char *section_type;

  /*! pointer to null terminated section name, NULL if no section name */
  char *section_name;

  /*! pointer to null terminated key, NULL if no key */
  char *entry_key;

  /*! pointer to null terminated value, NULL if no value */
  char *entry_value;
};

static int _print_schema_section(struct autobuf *log, struct cfg_db *db, const char *section);
static int _print_schema_entry(struct autobuf *log, struct cfg_db *db, const char *section, const char *entry);
static int _do_parse_arg(char *arg, struct _parsed_argument *pa, struct autobuf *log);

/**
 * Implements the 'set' command for the command line
 * @param instance pointer to cfg_instance
 * @param db pointer to cfg_db to be modified
 * @param arg argument of command
 * @param log pointer for logging
 * @return 0 if succeeded, -1 otherwise
 */
int
cfg_cmd_handle_set(
  struct cfg_instance *instance __attribute__((unused)), struct cfg_db *db, const char *arg, struct autobuf *log) {
  struct _parsed_argument pa;
  char *ptr;
  bool dummy;
  int result;

  /* get temporary copy of argument string */
  ptr = strdup(arg);
  if (!ptr)
    return -1;

  /* prepare for cleanup */
  result = -1;

  if (_do_parse_arg(ptr, &pa, log)) {
    goto handle_set_cleanup;
  }

  if (pa.entry_value != NULL) {
    if (cfg_db_set_entry(db, pa.section_type, pa.section_name, pa.entry_key, pa.entry_value, true)) {
      result = 0;
    }
    else {
      cfg_append_printable_line(log, "Cannot create entry: '%s'\n", arg);
    }
    result = 0;
    goto handle_set_cleanup;
  }

  if (pa.entry_key != NULL) {
    cfg_append_printable_line(log, "Key without value is not allowed for set command: %s", arg);
    goto handle_set_cleanup;
  }

  /* set section */
  if (NULL == _cfg_db_add_section(db, pa.section_type, pa.section_name, &dummy)) {
    cfg_append_printable_line(log, "Cannot create section: '%s'\n", arg);
    goto handle_set_cleanup;
  }
  result = 0;

handle_set_cleanup:
  free(ptr);
  return result;
}

/**
 * Implements the 'remove' command for the command line
 * @param instance pointer to cfg_instance
 * @param db pointer to cfg_db to be modified
 * @param arg argument of command
 * @param log pointer for logging
 * @return 0 if succeeded, -1 otherwise
 */
int
cfg_cmd_handle_remove(
  struct cfg_instance *instance __attribute__((unused)), struct cfg_db *db, const char *arg, struct autobuf *log) {
  struct _parsed_argument pa;
  char *ptr;
  int result;

  /* get temporary copy of argument string */
  ptr = strdup(arg);
  if (!ptr)
    return -1;

  /* prepare for cleanup */
  result = -1;

  if (_do_parse_arg(ptr, &pa, log)) {
    goto handle_remove_cleanup;
  }

  if (pa.entry_value != NULL) {
    cfg_append_printable_line(log, "Value is not allowed for remove command: %s", arg);
    goto handle_remove_cleanup;
  }

  if (pa.entry_key != NULL) {
    if (!cfg_db_remove_entry(db, pa.section_type, pa.section_name, pa.entry_key)) {
      result = 0;
    }
    else {
      cfg_append_printable_line(log, "Cannot remove entry: '%s'\n", arg);
    }
    goto handle_remove_cleanup;
  }

  if (pa.section_name) {
    if (cfg_db_remove_namedsection(db, pa.section_type, pa.section_name)) {
      cfg_append_printable_line(log, "Cannot remove section: '%s'\n", arg);
      goto handle_remove_cleanup;
    }
  }

  if (pa.section_type) {
    if (cfg_db_remove_sectiontype(db, pa.section_type)) {
      cfg_append_printable_line(log, "Cannot remove section: '%s'\n", arg);
      goto handle_remove_cleanup;
    }
  }
  result = 0;

handle_remove_cleanup:
  free(ptr);
  return result;
}

/**
 * Implements the 'get' command for the command line
 * @param instance pointer to cfg_instance
 * @param db pointer to cfg_db to be modified
 * @param arg argument of command
 * @param log pointer for logging
 * @return 0 if succeeded, -1 otherwise
 */
int
cfg_cmd_handle_get(
  struct cfg_instance *instance __attribute__((unused)), struct cfg_db *db, const char *arg, struct autobuf *log) {
  struct cfg_section_type *type, *type_it;
  struct cfg_named_section *named, *named_it;
  struct cfg_entry *entry, *entry_it;
  struct _parsed_argument pa;
  char *arg_copy, *tmp;
  int result;

  if (arg == NULL || *arg == 0) {
    cfg_append_printable_line(log, "Section types in database:");

    CFG_FOR_ALL_SECTION_TYPES(db, type, type_it) {
      cfg_append_printable_line(log, "%s", type->type);
    }
    return 0;
  }

  arg_copy = strdup(arg);
  if (!arg_copy) {
    return -1;
  }

  /* prepare for cleanup */
  result = -1;

  if (_do_parse_arg(arg_copy, &pa, log)) {
    goto handle_get_cleanup;
  }

  if (pa.entry_value != NULL) {
    cfg_append_printable_line(log, "Value is not allowed for view command: %s", arg);
    goto handle_get_cleanup;
  }

  if (pa.entry_key != NULL) {
    if (NULL == (entry = cfg_db_find_entry(db, pa.section_type, pa.section_name, pa.entry_key))) {
      cfg_append_printable_line(log, "Cannot find data for entry: '%s'\n", arg);
      goto handle_get_cleanup;
    }

    cfg_append_printable_line(log, "Key '%s' has value:", arg);
    strarray_for_each_element(&entry->val, tmp) {
      cfg_append_printable_line(log, "%s", tmp);
    }
    result = 0;
    goto handle_get_cleanup;
  }

  if (pa.section_name == NULL) {
    type = cfg_db_find_sectiontype(db, pa.section_type);
    if (type == NULL || type->names.count == 0) {
      cfg_append_printable_line(log, "Cannot find data for section type: %s", arg);
      goto handle_get_cleanup;
    }

    named = avl_first_element(&type->names, named, node);
    if (cfg_db_is_named_section(named)) {
      cfg_append_printable_line(log, "Named sections in section type: %s", pa.section_type);
      CFG_FOR_ALL_SECTION_NAMES(type, named, named_it) {
        cfg_append_printable_line(log, "%s", named->name);
      }
      result = 0;
      goto handle_get_cleanup;
    }
  }

  named = cfg_db_find_namedsection(db, pa.section_type, pa.section_name);
  if (named == NULL) {
    cfg_append_printable_line(log, "Cannot find data for section: %s", arg);
    goto handle_get_cleanup;
  }

  cfg_append_printable_line(log, "Entry keys for section '%s':", arg);
  CFG_FOR_ALL_ENTRIES(named, entry, entry_it) {
    cfg_append_printable_line(log, "%s", entry->name);
  }
  result = 0;

handle_get_cleanup:
  free(arg_copy);
  return result;
}

/**
 * Implements the 'query' command for the command line
 * @param instance pointer to cfg_instance
 * @param db pointer to cfg_db to be modified
 * @param arg argument of command
 * @param log pointer for logging
 * @return 0 if succeeded, -1 otherwise
 */
int
cfg_cmd_handle_query(
  struct cfg_instance *instance __attribute__((unused)), struct cfg_db *db, const char *arg, struct autobuf *log) {
  struct _parsed_argument pa;
  const struct const_strarray *array;
  const char *tmp;
  char *arg_copy;
  int result;

  if (arg == NULL || *arg == 0) {
    cfg_append_printable_line(log, "Query needs section and key, but no value: %s", arg);
    return 0;
  }

  arg_copy = strdup(arg);
  if (!arg_copy) {
    return -1;
  }

  /* prepare for cleanup */
  result = -1;

  if (_do_parse_arg(arg_copy, &pa, log)) {
    goto handle_get_cleanup;
  }

  if (pa.entry_key == NULL || pa.entry_value != NULL) {
    cfg_append_printable_line(log, "Query needs section and key, but no value: %s", arg);
    goto handle_get_cleanup;
  }

  array = cfg_db_get_entry_value(db, pa.section_type, pa.section_name, pa.entry_key);
  if (array) {
    cfg_append_printable_line(log, "Key '%s' has value:", arg);
    strarray_for_each_element(array, tmp) {
      cfg_append_printable_line(log, "%s", tmp);
    }
    result = 0;
  }
  else {
    cfg_append_printable_line(log, "Key '%s' has no value:", arg);
  }

handle_get_cleanup:
  free(arg_copy);
  return result;
}

/**
 * Implements the 'load' command for the command line
 * @param instance pointer to cfg_instance
 * @param db pointer to cfg_db to be modified
 * @param arg argument of command
 * @param log pointer for logging
 * @return 0 if succeeded, -1 otherwise
 */
int
cfg_cmd_handle_load(struct cfg_instance *instance, struct cfg_db *db, const char *arg, struct autobuf *log) {
  struct cfg_db *temp_db;

  temp_db = cfg_io_load(instance, arg, log);
  if (temp_db != NULL) {
    cfg_db_copy(db, temp_db);
    cfg_db_remove(temp_db);
  }
  return temp_db != NULL ? 0 : -1;
}

/**
 * Implements the 'save' command for the command line
 * @param instance pointer to cfg_instance
 * @param db pointer to cfg_db to be modified
 * @param arg argument of command
 * @param log pointer for logging
 * @return 0 if succeeded, -1 otherwise
 */
int
cfg_cmd_handle_save(struct cfg_instance *instance, struct cfg_db *db, const char *arg, struct autobuf *log) {
  return cfg_io_save(instance, arg, db, log);
}

/**
 * Implements the 'schema' command for the configuration system
 * @param db pointer to cfg_db to be modified
 * @param arg argument of command
 * @param log pointer for logging
 * @return 0 if succeeded, -1 otherwise
 */
int
cfg_cmd_handle_schema(struct cfg_db *db, const char *arg, struct autobuf *log) {
  struct cfg_schema_section *s_section;
  char *copy, *ptr;
  int result;

  if (db->schema == NULL) {
    abuf_puts(log, "Internal error, database not connected to schema\n");
    return -1;
  }

  if (arg == NULL || *arg == 0) {
    abuf_puts(log, "List of section types:\n"
                   "(use this command with the types as parameter for more information)\n");
    avl_for_each_element(&db->schema->sections, s_section, _section_node) {
      if (!s_section->_section_node.follower) {
        cfg_append_printable_line(log, CFG_HELP_INDENT_PREFIX "%s (%s)%s%s", s_section->type,
          CFG_SCHEMA_SECTIONMODE[s_section->mode], s_section->help ? ": " : "", s_section->help ? s_section->help : "");
      }
      else if (s_section->help) {
        cfg_append_printable_line(log, CFG_HELP_INDENT_PREFIX CFG_HELP_INDENT_PREFIX "%s", s_section->help);
      }
    }
    return 0;
  }

  if (strcmp(arg, "all") == 0) {
    const char *last_type = NULL;

    avl_for_each_element(&db->schema->sections, s_section, _section_node) {
      if (last_type == NULL || strcasecmp(s_section->type, last_type) != 0) {
        if (last_type != NULL) {
          abuf_puts(log, "\n");
        }
        _print_schema_section(log, db, s_section->type);
        last_type = s_section->type;
      }
    }
    return 0;
  }

  /* copy string into stack*/
  copy = strdup(arg);

  /* prepare for cleanup */
  result = -1;

  ptr = strchr(copy, '.');
  if (ptr) {
    *ptr++ = 0;
  }

  if (ptr == NULL) {
    result = _print_schema_section(log, db, copy);
  }
  else {
    result = _print_schema_entry(log, db, copy, ptr);
  }

  free(copy);
  return result;
}

static int
_print_schema_section(struct autobuf *log, struct cfg_db *db, const char *section) {
  struct cfg_schema_entry *s_entry, *s_entry_it;
  struct cfg_schema_entry_key key;

  /* show all schema entries for a section */
  key.type = section;
  key.entry = NULL;

  s_entry = avl_find_ge_element(&db->schema->entries, &key, s_entry, _node);
  if (s_entry == NULL || cfg_cmp_keys(s_entry->key.type, section) != 0) {
    cfg_append_printable_line(log, "Unknown section type '%s'", section);
    return -1;
  }

  if (s_entry->_parent->mode == CFG_SSMODE_NAMED_WITH_DEFAULT) {
    cfg_append_printable_line(
      log, "Section '%s' has default name '%s'", s_entry->_parent->type, s_entry->_parent->def_name);
  }

  if (s_entry->_parent->help) {
    cfg_append_printable_line(log, "%s", s_entry->_parent->help);
  }

  cfg_append_printable_line(log, "List of entries in section type '%s':", section);
  abuf_puts(log, "(use this command with 'type.name' as parameter for more information)\n");

  s_entry_it = s_entry;
  avl_for_element_to_last(&db->schema->entries, s_entry, s_entry_it, _node) {
    if (cfg_cmp_keys(s_entry_it->key.type, section) != 0) {
      break;
    }

    if (!s_entry_it->_node.follower) {
      cfg_append_printable_line(log, CFG_HELP_INDENT_PREFIX "%s%s%s", s_entry_it->key.entry,
        strarray_is_empty_c(&s_entry_it->def) ? " (mandatory)" : "", s_entry_it->list ? " (list)" : "");
    }
#if !defined(REMOVE_HELPTEXT)
    if (s_entry_it->help) {
      cfg_append_printable_line(log, CFG_HELP_INDENT_PREFIX CFG_HELP_INDENT_PREFIX "%s", s_entry_it->help);
    }
#endif
  }
  return 0;
}

static int
_print_schema_entry(struct autobuf *log, struct cfg_db *db, const char *section, const char *entry) {
  struct cfg_schema_entry *s_entry_it, *s_entry_first, *s_entry_last;
  struct cfg_schema_entry_key key;
  const char *c_ptr;

  /* show all schema entries of a type/entry pair */
  key.type = section;
  key.entry = entry;

  s_entry_last = NULL;

  avl_for_each_elements_with_key(&db->schema->entries, s_entry_it, _node, s_entry_first, &key) {
    if (s_entry_it == s_entry_first) {
      /* print type/parameter */
      cfg_append_printable_line(log, CFG_HELP_INDENT_PREFIX "%s%s%s", s_entry_it->key.entry,
        strarray_is_empty_c(&s_entry_it->def) ? " (mandatory)" : "", s_entry_it->list ? " (list)" : "");

      /* print defaults */
      if (!strarray_is_empty_c(&s_entry_it->def)) {
        cfg_append_printable_line(log, CFG_HELP_INDENT_PREFIX "Default value:");
        strarray_for_each_element(&s_entry_it->def, c_ptr) {
          cfg_append_printable_line(log, CFG_HELP_INDENT_PREFIX CFG_HELP_INDENT_PREFIX "'%s'", c_ptr);
        }
      }
    }

    if (s_entry_it->cb_valhelp) {
      /* print validator help if different from last validator */
      if (s_entry_last == NULL || s_entry_last->cb_valhelp != s_entry_it->cb_valhelp ||
          memcmp(&s_entry_last->validate_param, &s_entry_it->validate_param, sizeof(s_entry_it->validate_param)) != 0) {
        s_entry_it->cb_valhelp(s_entry_it, log);
        s_entry_last = s_entry_it;
      }
    }
  }

#if !defined(REMOVE_HELPTEXT)
  avl_for_each_elements_with_key(&db->schema->entries, s_entry_it, _node, s_entry_first, &key) {
    /* print help text */
    if (s_entry_it->help) {
      if (s_entry_it == s_entry_first) {
        abuf_puts(log, CFG_HELP_INDENT_PREFIX "Description:\n");
      }
      cfg_append_printable_line(log, CFG_HELP_INDENT_PREFIX CFG_HELP_INDENT_PREFIX "%s", s_entry_it->help);
    }
  }
#endif
  return 0;
}

/**
 * Parse the parameter string for most commands
 * @param arg argument of command
 * @param pa pointer to parsed argument struct for more return data
 * @param log pointer for logging
 * @return 0 if succeeded, negative otherwise
 */
static int
_do_parse_arg(char *arg, struct _parsed_argument *pa, struct autobuf *log) {
  static const char *pattern = "^(([a-zA-Z_][a-zA-Z_0-9]*)(\\[([^]]*)\\])?\\.)?([a-zA-Z_][a-zA-Z_0-9]*)?(=(.*))?$";
  regex_t regexp;
  regmatch_t matchers[8];

  if (regcomp(&regexp, pattern, REG_EXTENDED)) {
    /* error in regexp implementation */
    cfg_append_printable_line(log, "Error while formatting regular expression for parsing.");
    return -2;
  }

  if (regexec(&regexp, arg, ARRAYSIZE(matchers), matchers, 0)) {
    cfg_append_printable_line(log, "Illegal input for command: %s", arg);
    regfree(&regexp);
    return -1;
  }

  memset(pa, 0, sizeof(*pa));
  if (matchers[2].rm_so != -1) {
    pa->section_type = &arg[matchers[2].rm_so];
    arg[matchers[2].rm_eo] = 0;
  }
  if (matchers[4].rm_so != -1) {
    pa->section_name = &arg[matchers[4].rm_so];
    arg[matchers[4].rm_eo] = 0;
  }
  if (matchers[5].rm_so != -1) {
    pa->entry_key = &arg[matchers[5].rm_so];
    arg[matchers[5].rm_eo] = 0;
  }
  if (matchers[7].rm_so != -1) {
    pa->entry_value = &arg[matchers[7].rm_so];
  }

  regfree(&regexp);
  return 0;
}
