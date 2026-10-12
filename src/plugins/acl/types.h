/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#ifndef included_acl_types_h
#define included_acl_types_h

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

/* FastACL-compatible component presence bits. */
#define foreach_acl_mitigation_match                                                               \
  _ (0, DST_PREFIX)                                                                                \
  _ (1, SRC_PREFIX)                                                                                \
  _ (2, PROTO)                                                                                     \
  _ (3, DST_PORT)                                                                                  \
  _ (4, SRC_PORT)                                                                                  \
  _ (5, EITHER_PORT)                                                                               \
  _ (6, ICMP_TYPE)                                                                                 \
  _ (7, ICMP_CODE)                                                                                 \
  _ (8, TCP_FLAGS)                                                                                 \
  _ (9, PACKET_LENGTH)                                                                             \
  _ (10, DSCP)                                                                                     \
  _ (11, FRAGMENT)

typedef enum
{
#define _(bit, name) ACL_MITIGATION_##name = 1 << bit,
  foreach_acl_mitigation_match
#undef _
} acl_mitigation_match_flags_t;

#define ACL_MITIGATION_FRAG_DF	1
#define ACL_MITIGATION_FRAG_ISF 2
#define ACL_MITIGATION_FRAG_FF	4
#define ACL_MITIGATION_FRAG_LF	8

typedef struct
{
  u32 flags;
  u16 src_port_first, src_port_last;
  u16 dst_port_first, dst_port_last;
  u16 either_port_first, either_port_last;
  u16 packet_length_first, packet_length_last;
  u8 icmp_type, icmp_code;
  u8 tcp_flags_value, tcp_flags_mask;
  u8 dscp, fragment_value, fragment_mask;
} acl_mitigation_match_t;

/* Sidecar metadata: the legacy tuple and session-key ABI stay unchanged. */
typedef struct
{
  u32 packet_length;
  u8 dscp, fragment_flags;
} acl_mitigation_packet_t;

typedef struct
{
  u8 is_permit;
  u8 is_ipv6;
  ip46_address_t src;
  u8 src_prefixlen;
  ip46_address_t dst;
  u8 dst_prefixlen;
  u8 proto;
  u16 src_port_or_type_first;
  u16 src_port_or_type_last;
  u16 dst_port_or_code_first;
  u16 dst_port_or_code_last;
  u8 tcp_flags_value;
  u8 tcp_flags_mask;
  u8 is_mitigation;
  u32 logical_rule_index;
  u32 order;
  u32 sample_ratio;
  u32 sample_group;
  acl_mitigation_match_t mitigation;
} acl_rule_t;


#endif // included_acl_types_h

