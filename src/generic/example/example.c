
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

#include <oonf/oonf.h>
#include <oonf/libconfig/cfg_schema.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_timer.h>

#include <oonf/generic/example/example.h>

/* definitions */
#define LOG_EXAMPLE _example_subsystem.logging

/**
 * Configuration of example plugin
 */
struct _example_config {
  /*! a timestamp */
  uint64_t start;

  /*! another timestamp */
  uint64_t interval;

  /*! some internal data stored int config struct */
  uint64_t counter;
};

/* prototypes */
static int _init(void);
static void _cleanup(void);

static void _cb_counter_event(struct oonf_timer_instance *);
static void _cb_config_changed(void);

/* configuration */
static struct cfg_schema_entry _example_entries[] = {
  CFG_MAP_INT64_MINMAX(_example_config, start, "start", "0", "Starting value for counter", 0, 0, 1000),
  CFG_MAP_CLOCK_MIN(_example_config, interval, "interval", "1.0", "Interval between counter updates", 100),
};

static struct cfg_schema_section _example_section = {
  .type = OONF_EXAMPLE_SUBSYSTEM,
  .cb_delta_handler = _cb_config_changed,
  .entries = _example_entries,
  .entry_count = ARRAYSIZE(_example_entries),
};

static struct _example_config _config;

/* plugin declaration */
static const char *_dependencies[] = {
  OONF_TIMER_SUBSYSTEM,
};
static struct oonf_subsystem _example_subsystem = {
  .name = OONF_EXAMPLE_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "OONF example example plugin",
  .author = "Henning Rogge",

  .cfg_section = &_example_section,

  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_example_subsystem);

/* timer for updating counter */
static struct oonf_timer_class _counter_info = {
  .name = "nl80211 listener timer",
  .callback = _cb_counter_event,
  .periodic = true,
};

static struct oonf_timer_instance _counter_timer = { .class = &_counter_info };

static int
_init(void) {
  oonf_timer_add(&_counter_info);
  return 0;
}

static void
_cleanup(void) {
  oonf_timer_stop(&_counter_timer);
  oonf_timer_remove(&_counter_info);
}

/**
 * callback of example timer
 * @param ptr timer instance that fired
 */
static void
_cb_counter_event(struct oonf_timer_instance *ptr __attribute((unused))) {
  _config.counter++;

  OONF_INFO(LOG_EXAMPLE, "Updated counter to: %" PRIu64, _config.counter);
}

static void
_cb_config_changed(void) {
  if (cfg_schema_tobin(&_config, _example_section.post, _example_entries, ARRAYSIZE(_example_entries))) {
    OONF_WARN(LOG_EXAMPLE, "Could not convert " OONF_EXAMPLE_SUBSYSTEM " config to bin");
    return;
  }

  oonf_timer_set(&_counter_timer, _config.interval);
}
