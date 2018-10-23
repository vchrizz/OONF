
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

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <oonf/libcore/os_core.h>

/**
 * Get some random data
 * @param dst pointer to destination buffer
 * @param length number of random bytes requested
 * @return 0 if the random data was generated, -1 if an error happened
 */
int
os_core_linux_get_random(void *dst, size_t length) {
  int random_fd;
  ssize_t result;
  uint8_t *u8ptr;

  u8ptr = dst;

  /* open urandom */
  random_fd = open("/dev/urandom", O_RDONLY);
  if (random_fd == -1) {
    return -1;
  }

  while (length > 0) {
    result = read(random_fd, u8ptr, length);
    if (result < 0) {
      close(random_fd);
      return -1;
    }

    u8ptr += result;
    length -= result;
  }
  close(random_fd);
  return 0;
}

/**
 * Create a lock file of a certain name
 * @param path name of lockfile including path
 * @return 0 if the lock was created successfully, false otherwise
 */
int
os_core_linux_create_lockfile(const char *path) {
  int lock_fd;

  /* create file for lock */
  lock_fd = open(path, O_RDWR | O_CREAT, S_IRWXU);
  if (lock_fd == -1) {
    return -1;
  }

  if (flock(lock_fd, LOCK_EX | LOCK_NB)) {
    close(lock_fd);
    return -1;
  }

  /* lock will be released when process ends */
  return 0;
}
