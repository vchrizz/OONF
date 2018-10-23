
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

#include <signal.h>
#include <stdio.h>
#include <string.h>

#include <oonf/oonf.h>
#include <oonf/libcommon/bitstream.h>

#include <oonf/cunit/cunit.h>

static uint8_t buffer[32];

static struct bitstream_r _stream_r;
static struct bitstream_w _stream_w;

static void
clear_elements(void) {
  memset(buffer, 0, sizeof(buffer));
}

static void
test_bitstream_r_1(void) {
  uint64_t result;

  START_TEST();

  buffer[0] = 0xF0; /* 11110000 */
  buffer[1] = 0x11; /* 00010001 */
  buffer[2] = 0x22; /* 00100010 */
  bitstream_r_init(&_stream_r, buffer, 3);

  /* read 111 */
  CHECK_TRUE(!bitstream_r_read(&_stream_r, &result, 3), "failed to read 3 bits");
  CHECK_TRUE(result == 0x07, "bits are not 0x07 but 0x%"PRIx64, result);

  /* read 10 */
  CHECK_TRUE(!bitstream_r_read(&_stream_r, &result, 2), "failed to read 2 bits");
  CHECK_TRUE(result == 0x02, "bits are not 0x02 but 0x%"PRIx64, result);

  /* read 00000010 */
  CHECK_TRUE(!bitstream_r_read(&_stream_r, &result, 8), "failed to read 8 bits");
  CHECK_TRUE(result == 0x02, "bits are not 0x02 but 0x%"PRIx64, result);

  /* skip over 001 */
  bitstream_r_pad(&_stream_r);

  CHECK_TRUE(_stream_r.bit_offset == 16, "bit offset is not 16 but %zu",
      _stream_r.bit_offset);

  /* read 0010 */
  CHECK_TRUE(!bitstream_r_read(&_stream_r, &result, 4), "failed to read 4 bits");
  CHECK_TRUE(result == 0x02, "bits are not 0x02 but 0x%"PRIx64, result);

  END_TEST();
}

static void
test_bitstream_r_2(void) {
  uint64_t result;

  START_TEST();

  bitstream_r_init(&_stream_r, buffer, sizeof(buffer));

  /* try to read 57 bits */
  CHECK_TRUE(bitstream_r_read(&_stream_r, &result, 57), "should fail reading 57 bits");

  END_TEST();
}

static void
test_bitstream_r_3(void) {
  uint64_t result;

  START_TEST();

  bitstream_r_init(&_stream_r, buffer, 3);

  /* try to read 24 bits */
  CHECK_TRUE(bitstream_r_read(&_stream_r, &result, 25), "should fail reading 57 bits");

  END_TEST();
}

static void
test_bitstream_r_4(void) {
  uint64_t result;

  START_TEST();

  bitstream_r_init(&_stream_r, buffer, 3);

  /* read 12 bits */
  CHECK_TRUE(!bitstream_r_read(&_stream_r, &result, 12), "failed to read 12 bits");

  /* try to read 13 bits */
  CHECK_TRUE(bitstream_r_read(&_stream_r, &result, 13), "should fail reading 13 more bits");

  END_TEST();
}

static void
test_bitstream_w_1(void) {
  START_TEST();

  bitstream_w_init(&_stream_w, buffer, 3);

  /* write 111 */
  CHECK_TRUE(!bitstream_w_write(&_stream_w, 0x07, 3), "failed writing 111");
  CHECK_TRUE(buffer[0] == 0xe0, "First byte is not 0xe0 but 0x%02x", buffer[0]);

  /* write 10 */
  CHECK_TRUE(!bitstream_w_write(&_stream_w, 0x02, 2), "failed writing 10");
  CHECK_TRUE(buffer[0] == 0xf0, "First byte is not 0xf0 but 0x%02x", buffer[0]);

  /* write 0000 0010 */
  CHECK_TRUE(!bitstream_w_write(&_stream_w, 0x02, 8), "failed writing 00000010");
  CHECK_TRUE(buffer[0] == 0xf0, "First byte is not 0xf0 but 0x%02x", buffer[0]);
  CHECK_TRUE(buffer[1] == 0x10, "Second byte is not 0x10 but 0x%02x", buffer[1]);

  /* skip over 000 */
  bitstream_w_pad(&_stream_w);

  /* write 0010 */
  CHECK_TRUE(!bitstream_w_write(&_stream_w, 0x02, 4), "failed writing 0010");
  CHECK_TRUE(buffer[0] == 0xf0, "First byte is not 0xf0 but 0x%02x", buffer[0]);
  CHECK_TRUE(buffer[1] == 0x10, "Second byte is not 0x10 but 0x%02x", buffer[1]);
  CHECK_TRUE(buffer[2] == 0x20, "Second byte is not 0x20 but 0x%02x", buffer[2]);

  /* check length */
  CHECK_TRUE(bitstream_w_get_length(&_stream_w) == 3,
      "stream was not 3 but %"PRINTF_SIZE_T_SPECIFIER" bytes long",
      bitstream_w_get_length(&_stream_w));

  END_TEST();
}

static void
test_bitstream_w_2(void) {
  START_TEST();

  bitstream_w_init(&_stream_w, buffer, sizeof(buffer));

  /* try to write 57 bits */
  CHECK_TRUE(bitstream_w_write(&_stream_w, 0, 57), "should fail writing 57 bits");

  /* check length */
  CHECK_TRUE(bitstream_w_get_length(&_stream_w) == 0,
      "stream was not 0 but %"PRINTF_SIZE_T_SPECIFIER" bytes long",
      bitstream_w_get_length(&_stream_w));

  END_TEST();
}

static void
test_bitstream_w_3(void) {
  START_TEST();

  bitstream_w_init(&_stream_w, buffer, 3);

  /* try to write 25 bits */
  CHECK_TRUE(bitstream_w_write(&_stream_w, 0, 25), "should fail writing 25 bits");

  /* check length */
  CHECK_TRUE(bitstream_w_get_length(&_stream_w) == 0,
      "stream was not 0 but %"PRINTF_SIZE_T_SPECIFIER" bytes long",
      bitstream_w_get_length(&_stream_w));

  END_TEST();
}

static void
test_bitstream_w_4(void) {
  START_TEST();

  bitstream_w_init(&_stream_w, buffer, 3);

  /* write 24 bits */
  CHECK_TRUE(!bitstream_w_write(&_stream_w, 0, 24), "failed writing 24 bits");

  /* check length */
  CHECK_TRUE(bitstream_w_get_length(&_stream_w) == 3,
      "stream was not 3 but %"PRINTF_SIZE_T_SPECIFIER" bytes long",
      bitstream_w_get_length(&_stream_w));

  END_TEST();
}

static void
test_bitstream_w_5(void) {
  START_TEST();

  bitstream_w_init(&_stream_w, buffer, 3);

  /* write 12 bits */
  CHECK_TRUE(!bitstream_w_write(&_stream_w, 0, 12), "failed to write 12 bits");

  /* try to write 13 bits */
  CHECK_TRUE(bitstream_w_write(&_stream_w, 0, 13), "should fail writing 13 more bits");

  /* check length */
  CHECK_TRUE(bitstream_w_get_length(&_stream_w) == 2,
      "stream was not 2 but %"PRINTF_SIZE_T_SPECIFIER" bytes long",
      bitstream_w_get_length(&_stream_w));

  END_TEST();
}

static void
test_bitstream_w_6(void) {
  START_TEST();

  bitstream_w_init(&_stream_w, buffer, 3);

  /* write 7 bits with too much data in input source */
  CHECK_TRUE(!bitstream_w_write(&_stream_w, 0xeeeeff, 7), "failed to write 7 bits");
  CHECK_TRUE(buffer[0] == 0xfe, "First byte is not 0xfe but 0x%02x", buffer[0]);
  CHECK_TRUE(buffer[1] == 0x00, "Second byte is not 0x00 but 0x%02x", buffer[1]);
  CHECK_TRUE(buffer[2] == 0x00, "Second byte is not 0x00 but 0x%02x", buffer[2]);

  /* check length */
  CHECK_TRUE(bitstream_w_get_length(&_stream_w) == 1,
      "stream was not 1 but %"PRINTF_SIZE_T_SPECIFIER" bytes long",
      bitstream_w_get_length(&_stream_w));
  END_TEST();
}

int
main(int argc __attribute__ ((unused)), char **argv __attribute__ ((unused))) {
  BEGIN_TESTING(clear_elements);

  test_bitstream_r_1();
  test_bitstream_r_2();
  test_bitstream_r_3();
  test_bitstream_r_4();

  test_bitstream_w_1();
  test_bitstream_w_2();
  test_bitstream_w_3();
  test_bitstream_w_4();
  test_bitstream_w_5();
  test_bitstream_w_6();

  return FINISH_TESTING();
}
