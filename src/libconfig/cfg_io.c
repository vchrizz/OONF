
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

#ifndef WIN32
#include <alloca.h>
#else
#include <malloc.h>
#endif
#include <assert.h>
#include <string.h>

#include <oonf/libcommon/autobuf.h>
#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/avl_comp.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/string.h>

#include <oonf/libconfig/cfg.h>
#include <oonf/libconfig/cfg_io.h>

static struct cfg_io *_find_io(
  struct cfg_instance *instance, const char *url, const char **io_param, struct autobuf *log);

/**
 * Add a new io-handler to the registry. Name of io handler
 * must be already initialized.
 * @param instance pointer to cfg_instance
 * @param io pointer to io handler object
 */
void
cfg_io_add(struct cfg_instance *instance, struct cfg_io *io) {
  assert(io->name);
  io->node.key = io->name;
  avl_insert(&instance->io_tree, &io->node);
}

/**
 * Unregister an io-handler.
 * @param instance pointer to cfg_instance
 * @param io pointer to io handler
 */
void
cfg_io_remove(struct cfg_instance *instance, struct cfg_io *io) {
  if (avl_is_node_added(&io->node)) {
    avl_remove(&instance->io_tree, &io->node);
    io->node.key = NULL;
  }
}

/**
 * Load a configuration database from an external source
 * @param instance pointer to cfg_instance
 * @param url URL specifying the external source
 *   might contain io-handler specification with {iohandler}://
 *   syntax.
 * @param log pointer to autobuffer to contain logging output
 *   by loader.
 * @return pointer to configuration database, NULL if an error happened
 */
struct cfg_db *
cfg_io_load(struct cfg_instance *instance, const char *url, struct autobuf *log) {
  struct cfg_io *io;
  const char *io_param = NULL;

  io = _find_io(instance, url, &io_param, log);
  if (io == NULL) {
    cfg_append_printable_line(log, "Error, unknown config io '%s'.", url);
    return NULL;
  }

  if (io->load == NULL) {
    cfg_append_printable_line(log, "Error, config io '%s' does not support loading.", io->name);
    return NULL;
  }
  return io->load(io_param, log);
}

/**
 * Store a configuration database into an external destination.
 * @param instance pointer to cfg_instance
 * @param url URL specifying the external source
 *   might contain io-handler specification with {iohandler}://
 *   syntax.
 * @param src configuration database to be stored
 * @param log pointer to autobuffer to contain logging output
 *   by storage.
 * @return 0 if data was stored, -1 if an error happened
 */
int
cfg_io_save(struct cfg_instance *instance, const char *url, struct cfg_db *src, struct autobuf *log) {
  struct cfg_io *io;
  const char *io_param = NULL;

  io = _find_io(instance, url, &io_param, log);
  if (io == NULL) {
    cfg_append_printable_line(log, "Error, unknown config io '%s'.", url);
    return -1;
  }

  if (io->save == NULL) {
    cfg_append_printable_line(log, "Error, config io '%s' does not support saving.", io->name);
    return -1;
  }
  return io->save(io_param, src, log);
}

/**
 * Decode the URL string for load/storage
 * @param instance pointer to cfg_instance
 * @param url url string
 * @param io_param pointer to a charpointer, will be used as a second
 *   return parameter for URL postfix
 * @param log pointer to autobuffer to contain logging output
 *   by storage.
 * @return pointer to io handler, NULL if none found or an error
 *   happened
 */
static struct cfg_io *
_find_io(struct cfg_instance *instance, const char *url, const char **io_param, struct autobuf *log) {
  struct cfg_io *io = NULL;
  const char *ptr1;

  ptr1 = strstr(url, CFG_IO_URL_SPLITTER);
  if (ptr1 == url) {
    cfg_append_printable_line(log, "Illegal URL '%s' as parameter for io selection", url);
    return NULL;
  }
  if (ptr1 == NULL) {
    /* use default handler, if none was specified */
    ptr1 = url;
    url = instance->default_io;
  }
  else {
    ptr1 += sizeof(CFG_IO_URL_SPLITTER) - 1;
  }

  if (url) {
    /* we either have a handler specified or a defined default handler */
    io = avl_find_element(&instance->io_tree, url, io, node);
  }
  else {
    /* no default, nothing specified, just use the first handler */
    io = avl_first_element(&instance->io_tree, io, node);
  }

  if (io == NULL) {
    cfg_append_printable_line(log, "Cannot find loader for parameter '%s'", url);
    return NULL;
  }

  *io_param = ptr1;
  return io;
}
