
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

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>

#include <oonf/oonf.h>
#include <oonf/libcommon/isonumber.h>

#include <oonf/libconfig/cfg.h>
#include <oonf/libconfig/cfg_schema.h>

#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/os_clock.h>

#include <oonf/base/oonf_clock.h>

/* definitions */
#define LOG_CLOCK _oonf_clock_subsystem.logging

/* prototypes */
static int _init(void);

/* absolute monotonic clock measured in milliseconds compared to start time */
static uint64_t now_times;

/* arbitrary timestamp that represents the time oonf_clock_init() was called */
static uint64_t start_time;

/* subsystem definition */
static const char *_dependencies[] = {
  OONF_OS_CLOCK_SUBSYSTEM,
};

static struct oonf_subsystem _oonf_clock_subsystem = {
  .name = OONF_CLOCK_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .init = _init,
};
DECLARE_OONF_PLUGIN(_oonf_clock_subsystem);

/**
 * Initialize olsr clock system
 * @return -1 if an error happened, 0 otherwise
 */
static int
_init(void) {
  if (os_clock_gettime64(&start_time)) {
    OONF_WARN(LOG_CLOCK, "OS clock is not working: %s (%d)\n", strerror(errno), errno);
    return -1;
  }

  now_times = 0;

  return 0;
}

/**
 * Update the internal clock to current system time
 * @return -1 if an error happened, 0 otherwise
 */
int
oonf_clock_update(void) {
  uint64_t now;
  if (os_clock_gettime64(&now)) {
    OONF_WARN(LOG_CLOCK, "OS clock is not working: %s (%d)\n", strerror(errno), errno);
    return -1;
  }

  now_times = now - start_time;
  return 0;
}

/**
 * Calculates the current time in the internal OONF representation
 * @return current time
 */
uint64_t
oonf_clock_getNow(void) {
  return now_times;
}

/**
 * Format an internal time value into a string.
 * Displays hours:minutes:seconds.millisecond.
 *
 * @param buf string buffer for creating output
 * @param clk OONF timestamp
 * @return buffer to a formatted system time string.
 */
const char *
oonf_clock_toClockString(struct isonumber_str *buf, uint64_t clk) {
  uint64_t msec = clk % MSEC_PER_SEC;
  uint64_t sec = clk / MSEC_PER_SEC;

  snprintf(buf->buf, sizeof(*buf), "%" PRIu64 ":%02" PRIu64 ":%02" PRIu64 ".%03" PRIu64 "", sec / 3600,
    (sec % 3600) / 60, (sec % 60), msec);

  return buf->buf;
}
