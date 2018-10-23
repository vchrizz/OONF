
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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <oonf/libcommon/avl.h>
#include <oonf/oonf.h>
#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/libcore/os_core.h>
#include <oonf/base/oonf_clock.h>
#include <oonf/base/os_clock.h>

#include <oonf/base/oonf_timer.h>

/* Definitions */
#define LOG_TIMER _oonf_timer_subsystem.logging

/* prototypes */
static int _init(void);
static void _cleanup(void);

static void _calc_clock(struct oonf_timer_instance *timer, uint64_t rel_time);
static int _avlcomp_timer(const void *p1, const void *p2);

/* tree of all timers */
static struct avl_tree _timer_tree;

/* true if scheduler is active */
static bool _scheduling_now;

/* List of timer classes */
static struct list_entity _timer_info_list;

/* subsystem definition */
static const char *_dependencies[] = {
  OONF_CLOCK_SUBSYSTEM,
};

static struct oonf_subsystem _oonf_timer_subsystem = {
  .name = OONF_TIMER_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_oonf_timer_subsystem);

/**
 * Initialize timer scheduler subsystem
 * @return always returns 0
 */
int
_init(void) {
  OONF_INFO(LOG_TIMER, "Initializing timer scheduler.\n");

  avl_init(&_timer_tree, _avlcomp_timer, true);
  _scheduling_now = false;

  list_init_head(&_timer_info_list);
  return 0;
}

/**
 * Cleanup timer scheduler, this stops and deletes all timers
 */
static void
_cleanup(void) {
  struct oonf_timer_class *ti, *iterator;

  /* free all timerinfos */
  list_for_each_element_safe(&_timer_info_list, ti, _node, iterator) {
    oonf_timer_remove(ti);
  }
}

/**
 * Add a new group of timers to the scheduler
 * @param ti pointer to uninitialized timer info
 */
void
oonf_timer_add(struct oonf_timer_class *ti) {
  list_add_tail(&_timer_info_list, &ti->_node);
}

/**
 * Removes a group of timers from the scheduler
 * All pointers to timers of this info will be invalid after this.
 * @param info pointer to timer info
 */
void
oonf_timer_remove(struct oonf_timer_class *info) {
  struct oonf_timer_instance *timer, *iterator;

  if (!list_is_node_added(&info->_node)) {
    /* only free node if its hooked to the timer core */
    return;
  }

  avl_for_each_element_safe(&_timer_tree, timer, _node, iterator) {
    if (timer->class == info) {
      oonf_timer_stop(timer);
    }
  }

  list_remove(&info->_node);
}

/**
 * Start or restart a new timer.
 * @param timer initialized timer entry
 * @param first relative time when the timer should fire the first time
 * @param interval time between two timer events for periodic timers
 */
void
oonf_timer_start_ext(struct oonf_timer_instance *timer, uint64_t first, uint64_t interval) {
#ifdef OONF_LOG_DEBUG_INFO
  struct isonumber_str timebuf1;
#endif

  if (timer->_clock) {
    avl_remove(&_timer_tree, &timer->_node);
    timer->class->_stat_changes++;
  }
  else {
    timer->_node.key = timer;
    timer->class->_stat_usage++;
  }

  /*
   * Compute random numbers only once.
   */
  if (!timer->_random) {
    if (os_core_get_random(&timer->_random, sizeof(timer->_random))) {
      OONF_WARN(LOG_TIMER, "Could not get random data");
      timer->_random = 0;
    }
  }

  /* Fill entry */
  _calc_clock(timer, first);

  /* Singleshot or periodical timer ? */
  timer->_period = timer->class->periodic ? interval : 0;

  /* insert into tree */
  avl_insert(&_timer_tree, &timer->_node);

  OONF_DEBUG(LOG_TIMER, "TIMER: start timer '%s' firing in %s (%" PRIu64 ")\n", timer->class->name,
    oonf_clock_toClockString(&timebuf1, first), timer->_clock);
}

/**
 * Delete a timer.
 * @param timer the oonf_timer_entry that shall be removed
 */
void
oonf_timer_stop(struct oonf_timer_instance *timer) {
  if (timer->_clock == 0) {
    return;
  }

  OONF_DEBUG(LOG_TIMER, "TIMER: stop %s\n", timer->class->name);

  /* remove timer from tree */
  avl_remove(&_timer_tree, &timer->_node);
  timer->_clock = 0;
  timer->_random = 0;
  timer->class->_stat_usage--;

  if (timer->class->_timer_in_callback == timer) {
    timer->class->_timer_stopped = true;
  }
}

/**
 * This is the one stop shop for all sort of timer manipulation.
 * Depending on the passed in parameters a new timer is started,
 * or an existing timer is started or an existing timer is
 * terminated.
 * @param timer timer_entry pointer
 * @param first relative time when the timer should fire the first time
 * @param interval time between two timer events for periodic timers
 */
void
oonf_timer_set_ext(struct oonf_timer_instance *timer, uint64_t first, uint64_t interval) {
  if (first == 0) {
    /* No good future time provided, kill it. */
    oonf_timer_stop(timer);
  }
  else {
    /* Start or restart the timer */
    oonf_timer_start_ext(timer, first, interval);
  }
}

/**
 * Walk through the timer list and check if any timer is ready to fire.
 * Call the provided function with the context pointer.
 */
void
oonf_timer_walk(void) {
  struct oonf_timer_instance *timer;
  struct oonf_timer_class *info;
  uint64_t start_time, end_time;

  _scheduling_now = true;

  while (!avl_is_empty(&_timer_tree)) {
    timer = avl_first_element(&_timer_tree, timer, _node);

    if (timer->_clock > oonf_clock_getNow()) {
      break;
    }

    OONF_DEBUG(LOG_TIMER, "TIMER: fire '%s' at clocktick %" PRIu64 "\n", timer->class->name, timer->_clock);

    /*
     * The timer->info pointer is invalidated by oonf_timer_stop()
     */
    info = timer->class;
    info->_timer_in_callback = timer;
    info->_timer_stopped = false;

    /* update statistics */
    info->_stat_fired++;

    if (timer->_period == 0) {
      /* stop now, the data structure might not be available anymore later */
      oonf_timer_stop(timer);
    }

    /* This timer is expired, call into the provided callback function */
    os_clock_gettime64(&start_time);
    timer->class->callback(timer);
    os_clock_gettime64(&end_time);

    if (end_time - start_time > OONF_TIMER_SLICE) {
      OONF_WARN(LOG_TIMER, "Timer %s scheduling took %" PRIu64 " ms", timer->class->name, end_time - start_time);
      info->_stat_long++;
    }

    /*
     * Only act on actually running timers, the callback might have
     * called oonf_timer_stop() !
     */
    if (!info->_timer_stopped) {
      /*
       * Timer has been not been stopped, so its periodic.
       * rehash the random number and restart.
       */
      if (os_core_get_random(&timer->_random, sizeof(timer->_random))) {
        OONF_WARN(LOG_TIMER, "Could not get random data");
        timer->_random = 0;
      }
      oonf_timer_start(timer, timer->_period);
    }
  }

  _scheduling_now = false;
}

/**
 * @return timestamp when next timer will fire
 */
uint64_t
oonf_timer_getNextEvent(void) {
  struct oonf_timer_instance *first;

  if (avl_is_empty(&_timer_tree)) {
    return UINT64_MAX;
  }

  first = avl_first_element(&_timer_tree, first, _node);
  return first->_clock;
}

/**
 * get list of active timer classes
 * @return timer class list
 */
struct list_entity *
oonf_timer_get_list(void) {
  return &_timer_info_list;
}

/**
 * calculate the absolute time when a timer should fire, incuding jitter
 * @param timer timer instance that will be initialized
 * @param rel_time relative time until timer should fire
 */
static void
_calc_clock(struct oonf_timer_instance *timer, uint64_t rel_time) {
  uint64_t t = 0;
  unsigned random_jitter;

  if (timer->jitter_pct) {
    /*
     * Play some tricks to avoid overflows with integer arithmetic.
     */
    random_jitter = timer->_random / (UINT32_MAX / timer->jitter_pct);
    t = (uint64_t)random_jitter * rel_time / 100;

    OONF_DEBUG(LOG_TIMER, "TIMER: jitter %u%% (%u) rel_time %" PRIu64 "ms to %" PRIu64 "ms\n", timer->jitter_pct,
      random_jitter, rel_time, rel_time - t);

    rel_time -= t;
  }

  timer->_clock = oonf_clock_get_absolute(rel_time);

  /* round up to next timeslice */
  timer->_clock += OONF_TIMER_SLICE;
  timer->_clock -= (timer->_clock % OONF_TIMER_SLICE);
}

/**
 * Custom AVL comparator for two timer entries.
 * @param p1 first timer entry
 * @param p2 second timer entry
 * @return -1/0/1 depending on comparision of time when timer fires
 */
static int
_avlcomp_timer(const void *p1, const void *p2) {
  const struct oonf_timer_instance *t1, *t2;

  t1 = p1;
  t2 = p2;

  if (t1->_clock > t2->_clock) {
    return 1;
  }
  if (t1->_clock < t2->_clock) {
    return -1;
  }
  return 0;
}
