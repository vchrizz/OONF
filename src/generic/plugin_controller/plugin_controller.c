
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

#include <oonf/libcommon/autobuf.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcommon/netaddr_acl.h>
#include <oonf/libconfig/cfg_schema.h>
#include <oonf/libcore/oonf_cfg.h>
#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_telnet.h>

#include <oonf/generic/plugin_controller/plugin_controller.h>

/* definitions */
#define LOG_PLUGINCTRL _oonf_plugin_controller_subsystem.logging

/**
 * Plugin conroller configuration
 */
struct _plugin_controller_config {
  /*! access control list for telnet command */
  struct netaddr_acl acl;
};

/* prototypes */
static int _init(void);
static void _cleanup(void);

static enum oonf_telnet_result _cb_telnet_plugin(struct oonf_telnet_data *data);
static void _cb_config_changed(void);

static struct oonf_telnet_command _telnet_commands[] = {
  TELNET_CMD("plugin", _cb_telnet_plugin,
    "control plugins dynamically, parameters are 'list',"
    "'load <plugin>' and 'unload <plugin>'"),
};

/* configuration */
static struct cfg_schema_entry _plugin_controller_entries[] = {
  CFG_MAP_ACL(_plugin_controller_config, acl, "acl", ACL_LOCALHOST_ONLY, "acl for plugin controller"),
};

static struct cfg_schema_section _plugin_controller_section = {
  .type = OONF_PLUGIN_CONTROLLER_SUBSYSTEM,
  .cb_delta_handler = _cb_config_changed,
  .entries = _plugin_controller_entries,
  .entry_count = ARRAYSIZE(_plugin_controller_entries),
};

static struct _plugin_controller_config _config;

/* plugin declaration */
static const char *_dependencies[] = {
  OONF_TELNET_SUBSYSTEM,
};

static struct oonf_subsystem _oonf_plugin_controller_subsystem = {
  .name = OONF_PLUGIN_CONTROLLER_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "OONFD plugin controller plugin",
  .author = "Henning Rogge",

  .cfg_section = &_plugin_controller_section,

  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_oonf_plugin_controller_subsystem);

/**
 * Constructor of plugin
 * @return 0 if initialization was successful, -1 otherwise
 */
static int
_init(void) {
  netaddr_acl_add(&_config.acl);
  _telnet_commands[0].acl = &_config.acl;

  oonf_telnet_add(&_telnet_commands[0]);
  return 0;
}

/**
 * Destructor of plugin
 */
static void
_cleanup(void) {
  oonf_telnet_remove(&_telnet_commands[0]);
  netaddr_acl_remove(&_config.acl);
}

/**
 * Telnet command 'plugin'
 * @param data pointer to telnet data
 * @return telnet command result
 */
static enum oonf_telnet_result
_cb_telnet_plugin(struct oonf_telnet_data *data) {
  struct oonf_subsystem *plugin;
  const char *plugin_name = NULL;

  if (data->parameter == NULL || strcasecmp(data->parameter, "list") == 0) {
    abuf_puts(data->out, "Plugins:\n");

    avl_for_each_element(&oonf_plugin_tree, plugin, _node) {
      abuf_appendf(data->out, "\t%s\n", plugin->name);
    }
    return TELNET_RESULT_ACTIVE;
  }

  plugin_name = strchr(data->parameter, ' ');
  if (plugin_name == NULL) {
    abuf_appendf(data->out, "Error, missing or unknown parameter\n");
    return TELNET_RESULT_ACTIVE;
  }

  /* skip whitespaces */
  while (isspace(*plugin_name)) {
    plugin_name++;
  }

  plugin = oonf_subsystem_get(plugin_name);
  if (str_hasnextword(data->parameter, "load") == NULL) {
    if (plugin != NULL) {
      abuf_appendf(data->out, "Plugin %s already loaded\n", plugin_name);
      return TELNET_RESULT_ACTIVE;
    }
    plugin = oonf_subsystem_load(plugin_name);
    if (plugin != NULL) {
      abuf_appendf(data->out, "Plugin %s successfully loaded\n", plugin_name);
    }
    else {
      abuf_appendf(data->out, "Could not load plugin %s\n", plugin_name);
    }
    return TELNET_RESULT_ACTIVE;
  }

  if (plugin == NULL) {
    abuf_appendf(data->out, "Error, could not find plugin '%s'.\n", plugin_name);
    return TELNET_RESULT_ACTIVE;
  }

  if (str_hasnextword(data->parameter, "unload") == NULL) {
    if (oonf_subsystem_unload(plugin)) {
      abuf_appendf(data->out, "Could not unload plugin %s\n", plugin_name);
    }
    else {
      abuf_appendf(data->out, "Plugin %s successfully unloaded\n", plugin_name);
    }
    return TELNET_RESULT_ACTIVE;
  }

  abuf_appendf(data->out, "Unknown command '%s %s %s'.\n", data->command, data->parameter, plugin_name);
  return TELNET_RESULT_ACTIVE;
}

/**
 * Handler for configuration changes
 */
static void
_cb_config_changed(void) {
  /* generate binary config */
  if (cfg_schema_tobin(
        &_config, _plugin_controller_section.post, _plugin_controller_entries, ARRAYSIZE(_plugin_controller_entries))) {
    OONF_WARN(LOG_PLUGINCTRL, "Could not convert " OONF_PLUGIN_CONTROLLER_SUBSYSTEM " config to bin");
    return;
  }
}
