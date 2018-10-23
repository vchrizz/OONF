
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
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <oonf/libcommon/autobuf.h>
#include <oonf/librfc5444/rfc5444_context.h>
#include <oonf/librfc5444/rfc5444_print.h>
#include <oonf/librfc5444/rfc5444_writer.h>
#include <oonf/cunit/cunit.h>

#define MSG_TYPE 1
#define MSG_MTU  1280
#define IF_MTU   1281

static void write_packet(struct rfc5444_writer *,
    struct rfc5444_writer_target *, void *, size_t);
static void addAddresses(struct rfc5444_writer *wr);

static uint8_t msg_buffer[RFC5444_MAX_MESSAGE_SIZE];
static uint8_t msg_addrtlvs[65536];

static struct rfc5444_writer writer = {
  .msg_buffer = msg_buffer,
  .msg_size = sizeof(msg_buffer),
  .addrtlv_buffer = msg_addrtlvs,
  .addrtlv_size = sizeof(msg_addrtlvs),
};

static struct rfc5444_writer_content_provider cpr = {
  .msg_type = MSG_TYPE,
  .addAddresses = addAddresses,
};

static struct rfc5444_writer_tlvtype addrtlvs = {
    .type = 2,
};

static uint8_t packet_buffer_if[IF_MTU];
static struct rfc5444_writer_target out_if = {
  .packet_buffer = packet_buffer_if,
  .packet_size = sizeof(packet_buffer_if),
  .sendPacket = write_packet,
};

static int addMessageHeader(struct rfc5444_writer *wr, struct rfc5444_writer_message *msg) {
  rfc5444_writer_set_msg_header(wr, msg, false, false, false, false);
  return RFC5444_OKAY;
}

static void addAddresses(struct rfc5444_writer *wr) {
  struct netaddr ip; // = { { 10,1,0,101}, AF_INET, 32 };
  struct rfc5444_writer_address *addr;
  int value1 = 1;
  int i,j;

  CHECK_TRUE(0 == netaddr_from_string(&ip, "10.0.0.0"), "failed to initialize ip");

  for (i=0; i<100; i++) {
    for (j=0; j<100; j++) {
      ip._addr[2] = i;
      ip._addr[3] = j;
      //ip._addr[0] = 10; ip._addr[1] = 1; ip._addr[2] = 0; ip._addr[3] = 101;
      addr = rfc5444_writer_add_address(wr, cpr.creator, &ip, false);
      CHECK_TRUE(rfc5444_writer_add_addrtlv(wr, addr, &addrtlvs, &value1, sizeof(value1), false) == 0,
          "Out of memory for address tlv");
      value1++;
    }
  }
}

static void write_packet(struct rfc5444_writer *w __attribute__ ((unused)),
    struct rfc5444_writer_target *iface __attribute__((unused)),
    void *buffer __attribute((unused)), size_t length) {
  struct autobuf out;

  CHECK_TRUE(length < MSG_MTU + 1, "RFC5444 packet with %zd bytes!", length);

  abuf_init(&out);
  abuf_appendf(&out, "Packet with %zd bytes:\n", length);
  abuf_hexdump(&out, "", buffer, length);
  rfc5444_print_direct(&out, buffer, length);

  printf("%s\n", abuf_getptr(&out));
  abuf_free(&out);
}


static void clear_elements(void) {
}

static void test(void) {
  START_TEST();

  CHECK_TRUE(0 == rfc5444_writer_create_message_alltarget(&writer, 1, 4), "Parser should return 0");
  rfc5444_writer_flush(&writer, &out_if, false);

  END_TEST();
}

int main(int argc __attribute__ ((unused)), char **argv __attribute__ ((unused))) {
  struct rfc5444_writer_message *msg;

  rfc5444_writer_init(&writer);

  rfc5444_writer_register_target(&writer, &out_if);

  msg = rfc5444_writer_register_message(&writer, MSG_TYPE, false);
  msg->addMessageHeader = addMessageHeader;

  rfc5444_writer_register_msgcontentprovider(&writer, &cpr, &addrtlvs, 1);

  BEGIN_TESTING(clear_elements);

  test();

  rfc5444_writer_cleanup(&writer);

  return FINISH_TESTING();
}
