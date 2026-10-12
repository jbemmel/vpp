/* SPDX-License-Identifier: Apache-2.0 */
#ifndef included_acl_mitigation_packet_h
#define included_acl_mitigation_packet_h
#include <acl/acl.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/tcp/tcp_packet.h>

/* Bound every read to both the declared IP length and the contiguous buffer.
 * Transport headers split across buffers are treated as unavailable. IP length
 * comes from the header (not Ethernet padding or the first buffer length).
 */
always_inline int
acl_mitigation_fill_packet (vlib_main_t *vm, vlib_buffer_t *b, u32 offset, fa_5tuple_t *tuple,
			    acl_mitigation_packet_t *metadata)
{
  clib_memset (tuple, 0, sizeof (*tuple));
  clib_memset (metadata, 0, sizeof (*metadata));
  if (offset >= b->current_length)
    return 0;
  u8 *ip = (u8 *) vlib_buffer_get_current (b) + offset;
  u32 avail = b->current_length - offset;
  u32 total = vlib_buffer_length_in_chain (vm, b) - offset;
  u32 length, l4_offset;
  u16 fragment_offset = 0;
  u8 more = 0, proto;
  if ((ip[0] >> 4) == 4)
    {
      if (avail < sizeof (ip4_header_t))
	return 0;
      ip4_header_t *h = (void *) ip;
      length = clib_net_to_host_u16 (h->length);
      l4_offset = ip4_header_bytes (h);
      if (l4_offset < sizeof (*h) || l4_offset > avail || length < l4_offset || length > total)
	return 0;
      tuple->ip4_addr[0] = h->src_address;
      tuple->ip4_addr[1] = h->dst_address;
      proto = h->protocol;
      metadata->dscp = ip4_header_get_dscp (h);
      fragment_offset = ip4_get_fragment_offset (h);
      more = !!ip4_get_fragment_more (h);
      if (h->flags_and_fragment_offset & clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT))
	metadata->fragment_flags |= ACL_MITIGATION_FRAG_DF;
    }
  else if ((ip[0] >> 4) == 6)
    {
      if (avail < sizeof (ip6_header_t))
	return 0;
      ip6_header_t *h = (void *) ip;
      tuple->pkt.is_ip6 = 1;
      tuple->ip6_addr[0] = h->src_address;
      tuple->ip6_addr[1] = h->dst_address;
      metadata->dscp = ip6_dscp_network_order (h);
      length = sizeof (*h) + clib_net_to_host_u16 (h->payload_length);
      if (length > total)
	return 0;
      proto = h->protocol;
      l4_offset = sizeof (*h);
      u32 end = clib_min (length, avail);
      /* Handle options, routing, destination options, fragments, and AH.
       * Each iteration advances by at least eight bytes; malformed chains fail.
       */
      while (proto == 0 || proto == 43 || proto == 60 || proto == 44 || proto == 51)
	{
	  if (l4_offset + 8 > end)
	    return 0;
	  u8 *eh = ip + l4_offset;
	  u32 size =
	    proto == 44 ? 8 : (proto == 51 ? 4 * ((u32) eh[1] + 2) : 8 * ((u32) eh[1] + 1));
	  if (size < 8 || l4_offset + size > end)
	    return 0;
	  if (proto == 44)
	    {
	      u16 bits;
	      clib_memcpy_fast (&bits, eh + 2, sizeof (bits));
	      bits = clib_net_to_host_u16 (bits);
	      fragment_offset = bits >> 3;
	      more = bits & 1;
	    }
	  proto = eh[0];
	  l4_offset += size;
	  if (fragment_offset)
	    break;
	}
    }
  else
    return 0;

  metadata->packet_length = length;
  if (more || fragment_offset)
    metadata->fragment_flags |= ACL_MITIGATION_FRAG_ISF;
  if (more && !fragment_offset)
    metadata->fragment_flags |= ACL_MITIGATION_FRAG_FF;
  if (!more && fragment_offset)
    metadata->fragment_flags |= ACL_MITIGATION_FRAG_LF;
  tuple->pkt.is_nonfirst_fragment = !!fragment_offset;
  tuple->l4.proto = proto;
  u32 end = clib_min (length, avail);
  if (fragment_offset || l4_offset >= end)
    return 1;
  u8 *l4 = ip + l4_offset;
  u32 bytes = end - l4_offset;
  if ((proto == 6 || proto == 17) && bytes >= 4)
    {
      u16 ports[2];
      clib_memcpy_fast (ports, l4, sizeof (ports));
      tuple->l4.port[0] = clib_net_to_host_u16 (ports[0]);
      tuple->l4.port[1] = clib_net_to_host_u16 (ports[1]);
      tuple->pkt.l4_valid = 1;
      if (proto == 6 && bytes >= 14)
	{
	  tuple->pkt.tcp_flags = l4[13];
	  tuple->pkt.tcp_flags_valid = 1;
	}
    }
  else if (proto == (tuple->pkt.is_ip6 ? 58 : 1) && bytes >= 2)
    {
      tuple->l4.port[0] = l4[0];
      tuple->l4.port[1] = l4[1];
      tuple->pkt.l4_valid = 1;
    }
  return 1;
}
#endif
