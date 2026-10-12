/* SPDX-License-Identifier: Apache-2.0 */
#include <acl/mitigation.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/format_fns.h>
#include <vnet/l2/l2_in_out_feat_arc.h>
#include <vnet/api_errno.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <acl/mitigation.api_enum.h>
#include <acl/mitigation.api_types.h>

acl_mitigation_main_t acl_mitigation_main;
#define REPLY_MSG_ID_BASE mm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static int
mitigation_prefix_compare (const ip46_address_t *a, u8 al, const ip46_address_t *b, u8 bl, u8 ip6)
{
  u8 common = clib_min (al, bl);
  ip46_address_t aa = *a, bb = *b;
  int c;
  if (ip6)
    {
      ip6_address_normalize (&aa.ip6, common);
      ip6_address_normalize (&bb.ip6, common);
      c = memcmp (&aa.ip6, &bb.ip6, sizeof (aa.ip6));
    }
  else
    {
      ip4_address_normalize (&aa.ip4, common);
      ip4_address_normalize (&bb.ip4, common);
      c = memcmp (&aa.ip4, &bb.ip4, sizeof (aa.ip4));
    }
  return c ? (c > 0 ? 1 : -1) : (al < bl) - (al > bl);
}

/* FastACL precedence: order, component presence/value, input index.
 * This compares the supported fixed-field model, not arbitrary BGP NLRIs.
 */
static int
mitigation_rule_compare (const void *va, const void *vb)
{
  const acl_rule_t *a = va, *b = vb;
  const acl_mitigation_match_t *ma = &a->mitigation, *mb = &b->mitigation;
  if (a->order != b->order)
    return (a->order > b->order) ? 1 : -1;
  if ((a->is_ipv6 == 1) != (b->is_ipv6 == 1))
    return a->is_ipv6 == 1 ? 1 : -1;
#define PRESENCE(bit)                                                                              \
  if ((ma->flags & (bit)) != (mb->flags & (bit)))                                                  \
  return (ma->flags & (bit)) ? -1 : 1
#define SCALAR(bit, av, bv)                                                                        \
  do                                                                                               \
    {                                                                                              \
      PRESENCE (bit);                                                                              \
      if ((ma->flags & (bit)) && (av) != (bv))                                                     \
	return (av) > (bv) ? 1 : -1;                                                               \
    }                                                                                              \
  while (0)
#define PREFIX(bit, name)                                                                          \
  do                                                                                               \
    {                                                                                              \
      PRESENCE (bit);                                                                              \
      if (ma->flags & (bit))                                                                       \
	{                                                                                          \
	  int c = mitigation_prefix_compare (&a->name, a->name##_prefixlen, &b->name,              \
					     b->name##_prefixlen, a->is_ipv6 == 1);                \
	  if (c)                                                                                   \
	    return c;                                                                              \
	}                                                                                          \
    }                                                                                              \
  while (0)
  PREFIX (ACL_MITIGATION_DST_PREFIX, dst);
  PREFIX (ACL_MITIGATION_SRC_PREFIX, src);
  SCALAR (ACL_MITIGATION_PROTO, a->proto, b->proto);
#define PAIR(bit, name)                                                                            \
  SCALAR (bit, ma->name##_first, mb->name##_first);                                                \
  SCALAR (bit, ma->name##_last, mb->name##_last)
  PAIR (ACL_MITIGATION_EITHER_PORT, either_port);
  PAIR (ACL_MITIGATION_DST_PORT, dst_port);
  PAIR (ACL_MITIGATION_SRC_PORT, src_port);
  SCALAR (ACL_MITIGATION_ICMP_TYPE, ma->icmp_type, mb->icmp_type);
  SCALAR (ACL_MITIGATION_ICMP_CODE, ma->icmp_code, mb->icmp_code);
  SCALAR (ACL_MITIGATION_TCP_FLAGS, ma->tcp_flags_value, mb->tcp_flags_value);
  SCALAR (ACL_MITIGATION_TCP_FLAGS, ma->tcp_flags_mask, mb->tcp_flags_mask);
  PAIR (ACL_MITIGATION_PACKET_LENGTH, packet_length);
  SCALAR (ACL_MITIGATION_DSCP, ma->dscp, mb->dscp);
  SCALAR (ACL_MITIGATION_FRAGMENT, ma->fragment_value, mb->fragment_value);
  SCALAR (ACL_MITIGATION_FRAGMENT, ma->fragment_mask, mb->fragment_mask);
#undef PAIR
#undef PREFIX
#undef SCALAR
#undef PRESENCE
  return (a->logical_rule_index > b->logical_rule_index) -
	 (a->logical_rule_index < b->logical_rule_index);
}

static int
mitigation_rule_validate (acl_rule_t *r)
{
  acl_mitigation_match_t *m = &r->mitigation;
  if (m->flags & ~0xfff || r->is_ipv6 > 2 || r->is_permit > 1)
    return VNET_API_ERROR_INVALID_VALUE;
  u32 addresses = m->flags & (ACL_MITIGATION_SRC_PREFIX | ACL_MITIGATION_DST_PREFIX);
  if (r->is_ipv6 == 2 && addresses)
    return VNET_API_ERROR_INVALID_VALUE;
  u8 max = r->is_ipv6 == 1 ? 128 : 32;
  if (((m->flags & ACL_MITIGATION_SRC_PREFIX) && r->src_prefixlen > max) ||
      ((m->flags & ACL_MITIGATION_DST_PREFIX) && r->dst_prefixlen > max))
    return VNET_API_ERROR_INVALID_VALUE;
#define RANGE(bit, name)                                                                           \
  if ((m->flags & (bit)) && m->name##_first > m->name##_last)                                      \
  return VNET_API_ERROR_INVALID_VALUE
  RANGE (ACL_MITIGATION_SRC_PORT, src_port);
  RANGE (ACL_MITIGATION_DST_PORT, dst_port);
  RANGE (ACL_MITIGATION_EITHER_PORT, either_port);
  RANGE (ACL_MITIGATION_PACKET_LENGTH, packet_length);
#undef RANGE
  if (((m->flags & ACL_MITIGATION_DSCP) && m->dscp > 63) ||
      ((m->flags & ACL_MITIGATION_TCP_FLAGS) && (m->tcp_flags_value & ~m->tcp_flags_mask)) ||
      ((m->flags & ACL_MITIGATION_FRAGMENT) &&
       (!m->fragment_mask || (m->fragment_mask & ~15) || (m->fragment_value & ~m->fragment_mask))))
    return VNET_API_ERROR_INVALID_VALUE;
  if (!(m->flags & ACL_MITIGATION_PROTO))
    r->proto = 0;
  if (!(m->flags & ACL_MITIGATION_SRC_PREFIX))
    r->src_prefixlen = 0;
  if (!(m->flags & ACL_MITIGATION_DST_PREFIX))
    r->dst_prefixlen = 0;
  if (r->is_ipv6 == 1)
    {
      ip6_address_normalize (&r->src.ip6, r->src_prefixlen);
      ip6_address_normalize (&r->dst.ip6, r->dst_prefixlen);
    }
  else
    {
      ip4_address_normalize (&r->src.ip4, r->src_prefixlen);
      ip4_address_normalize (&r->dst.ip4, r->dst_prefixlen);
    }
  r->is_mitigation = 1;
  /* Prefix and protocol accelerate the lookup; all other components are
   * residual predicates in the native collision verifier. This avoids treating
   * either-port as AND, or inventing ports for fragments and unknown protocols.
   */
  r->src_port_or_type_last = r->dst_port_or_code_last = 65535;
  return 0;
}

static int
mitigation_replace (acl_rule_t *logical, u32 *index, u8 *tag)
{
  acl_mitigation_main_t *mm = &acl_mitigation_main;
  acl_main_t *am = &acl_main;
  if (clib_strnlen ((char *) tag, 64) == 64)
    {
      vec_free (logical);
      return VNET_API_ERROR_INVALID_VALUE;
    }
  if (*index != ~0u && (pool_is_free_index (am->acls, *index) || !am->acls[*index].is_mitigation))
    {
      vec_free (logical);
      return VNET_API_ERROR_INVALID_VALUE;
    }
  acl_rule_t *r, *compiled = 0, *ordered = vec_dup (logical);
  int rv = 0;
  vec_foreach (r, ordered)
    {
      if ((rv = mitigation_rule_validate (r)))
	goto done;
      r->logical_rule_index = r - ordered;
    }
  /* Preserve normalized logical entries in input order for IDs and dumps. */
  vec_free (logical);
  logical = vec_dup (ordered);
  vec_sort_with_function (ordered, mitigation_rule_compare);
  vec_foreach (r, ordered)
    {
      acl_rule_t entry = *r;
      if (entry.is_ipv6 == 2)
	{
	  entry.is_ipv6 = 0;
	  vec_add1 (compiled, entry);
	  entry.is_ipv6 = 1;
	}
      vec_add1 (compiled, entry);
    }
  vlib_worker_thread_barrier_sync (am->vlib_main);
  rv = acl_replace_rule_vector (compiled, index, tag);
  if (!rv)
    {
      compiled = 0;
      am->acls[*index].is_mitigation = 1;
      vec_validate (mm->rules, *index);
      vec_free (mm->rules[*index]);
      mm->rules[*index] = logical;
      vec_validate (mm->mapping, *index);
      vec_validate (mm->rates, *index);
      vec_free (mm->mapping[*index]);
      vec_free (mm->rates[*index]);
      if (vec_len (logical))
	{
	  vec_validate (mm->mapping[*index], vec_len (logical) - 1);
	  vec_validate (mm->rates[*index], vec_len (logical) - 1);
	  for (u32 j = 0; j < vec_len (logical); j++)
	    {
	      mm->mapping[*index][j].ace[0] = ~0u;
	      mm->mapping[*index][j].ace[1] = ~0u;
	      mm->rates[*index][j].time = vlib_time_now (am->vlib_main);
	    }
	  vec_foreach (r, am->acls[*index].rules)
	    mm->mapping[*index][r->logical_rule_index].ace[r->is_ipv6] = r - am->acls[*index].rules;
	}
      logical = 0;
      acl_mitigation_worker_t *w;
      vec_foreach (w, mm->workers)
	{
	  vec_validate (w->samples, *index);
	  vec_free (w->samples[*index]);
	  if (vec_len (mm->rules[*index]))
	    vec_validate (w->samples[*index], vec_len (mm->rules[*index]) - 1);
	}
    }
  vlib_worker_thread_barrier_release (am->vlib_main);
done:
  vec_free (logical);
  vec_free (ordered);
  vec_free (compiled);
  return rv;
}

void
acl_mitigation_acl_deleted (u32 index)
{
  acl_mitigation_main_t *mm = &acl_mitigation_main;
  if (index >= vec_len (mm->rules))
    return;
  vec_free (mm->rules[index]);
  vec_free (mm->mapping[index]);
  vec_free (mm->rates[index]);
  acl_mitigation_worker_t *w;
  vec_foreach (w, mm->workers)
    if (index < vec_len (w->samples))
      vec_free (w->samples[index]);
}

static void
mitigation_update_rate (acl_mitigation_rate_t *rate, const vlib_counter_t *counter)
{
  f64 now = vlib_time_now (acl_main.vlib_main), elapsed = now - rate->time;
  if (elapsed < 0.5)
    return;
  u64 packets = counter->packets >= rate->previous.packets ?
		  counter->packets - rate->previous.packets :
		  counter->packets;
  u64 bytes =
    counter->bytes >= rate->previous.bytes ? counter->bytes - rate->previous.bytes : counter->bytes;
  rate->pps = packets / elapsed;
  rate->l3_bps = bytes * 8.0 / elapsed;
  /* Untagged Ethernet: header + FCS + preamble + interpacket gap = 38 bytes.
   * Account for minimum frame padding when interpreting small-packet rates.
   */
  rate->l1_bps = (bytes + packets * 38.0) * 8.0 / elapsed;
  rate->previous = *counter;
  rate->time = now;
}

int
acl_mitigation_bind (u32 sw_if_index, u32 acl_index)
{
  acl_mitigation_main_t *mm = &acl_mitigation_main;
  vnet_main_t *vnm = vnet_get_main ();
  if (!vnet_sw_interface_is_api_valid (vnm, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;
  if (acl_index != ~0u &&
      (pool_is_free_index (acl_main.acls, acl_index) || !acl_main.acls[acl_index].is_mitigation))
    return VNET_API_ERROR_INVALID_VALUE;
  vec_validate_init_empty (mm->contexts, sw_if_index, ~0u);
  vec_validate_init_empty (mm->bindings, sw_if_index, ~0u);
  u32 lc = mm->contexts[sw_if_index];
  if (acl_index == mm->bindings[sw_if_index])
    return 0;
  /* Enable all paths before publishing; roll back on unsupported arcs. */
  const char *arcs[] = { "ip4-unicast", "ip6-unicast", "l2-input-ip4", "l2-input-ip6" };
  const char *nodes[] = { "acl-mitigation-ip", "acl-mitigation-ip", "acl-mitigation-l2",
			  "acl-mitigation-l2" };
  vlib_worker_thread_barrier_sync (acl_main.vlib_main);
  for (int i = 0; i < 4; i++)
    {
      int rv =
	vnet_l2_feature_enable_disable (arcs[i], nodes[i], sw_if_index, acl_index != ~0u, 0, 0);
      if (rv)
	{
	  for (int j = 0; j < i; j++)
	    vnet_l2_feature_enable_disable (arcs[j], nodes[j], sw_if_index,
					    mm->bindings[sw_if_index] != ~0u, 0, 0);
	  vlib_worker_thread_barrier_release (acl_main.vlib_main);
	  return rv;
	}
    }
  if (acl_index != ~0u)
    {
      if (lc == ~0u)
	lc = mm->acl.get_lookup_context_index (mm->user_id, sw_if_index, 0);
      u32 *acls = 0;
      vec_add1 (acls, acl_index);
      mm->acl.set_acl_vec_for_context (lc, acls);
      vec_free (acls);
    }
  else if (lc != ~0u)
    {
      mm->acl.put_lookup_context_index (lc);
      lc = ~0u;
    }
  mm->bindings[sw_if_index] = acl_index;
  mm->contexts[sw_if_index] = lc;
  vlib_worker_thread_barrier_release (acl_main.vlib_main);
  return 0;
}

static clib_error_t *
mitigation_interface_delete (vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  acl_mitigation_main_t *mm = &acl_mitigation_main;
  if (!is_add && sw_if_index < vec_len (mm->contexts) && mm->contexts[sw_if_index] != ~0u)
    acl_mitigation_bind (sw_if_index, ~0u);
  return 0;
}
VNET_SW_INTERFACE_ADD_DEL_FUNCTION (mitigation_interface_delete);

/* clang-format off */
#define foreach_mitigation_u16 \
  _ (src_port_first) \
  _ (src_port_last) \
  _ (dst_port_first) \
  _ (dst_port_last) \
  _ (either_port_first) \
  _ (either_port_last) \
  _ (packet_length_first) \
  _ (packet_length_last)
#define foreach_mitigation_u8 \
  _ (icmp_type) \
  _ (icmp_code) \
  _ (tcp_flags_value) \
  _ (tcp_flags_mask) \
  _ (dscp) \
  _ (fragment_value) \
  _ (fragment_mask)
/* clang-format on */

static int
mitigation_decode (const vl_api_acl_mitigation_rule_t *api, acl_rule_t *r)
{
  clib_memset (r, 0, sizeof (*r));
  r->is_ipv6 = api->family;
  r->is_permit = api->action;
  r->order = clib_net_to_host_u32 (api->order);
  r->proto = api->proto;
  r->sample_ratio = clib_net_to_host_u32 (api->sample_ratio);
  r->sample_group = clib_net_to_host_u32 (api->sample_group);
  r->mitigation.flags = clib_net_to_host_u32 (api->flags);
#define _(name) r->mitigation.name = clib_net_to_host_u16 (api->name);
  foreach_mitigation_u16
#undef _
#define _(name) r->mitigation.name = api->name;
    foreach_mitigation_u8
#undef _
    if (r->mitigation.flags & ACL_MITIGATION_SRC_PREFIX)
  {
    if (api->src_prefix.address.af != r->is_ipv6)
      return VNET_API_ERROR_INVALID_VALUE;
    ip_address_decode (&api->src_prefix.address, &r->src);
    r->src_prefixlen = api->src_prefix.len;
  }
  if (r->mitigation.flags & ACL_MITIGATION_DST_PREFIX)
    {
      if (api->dst_prefix.address.af != r->is_ipv6)
	return VNET_API_ERROR_INVALID_VALUE;
      ip_address_decode (&api->dst_prefix.address, &r->dst);
      r->dst_prefixlen = api->dst_prefix.len;
    }
  return mitigation_rule_validate (r);
}

static void
mitigation_encode (const acl_rule_t *r, vl_api_acl_mitigation_rule_t *api)
{
  api->family = r->is_ipv6;
  api->action = r->is_permit;
  api->order = clib_host_to_net_u32 (r->order);
  api->flags = clib_host_to_net_u32 (r->mitigation.flags);
  api->proto = r->proto;
  api->sample_ratio = clib_host_to_net_u32 (r->sample_ratio);
  api->sample_group = clib_host_to_net_u32 (r->sample_group);
  if (r->is_ipv6 != 2)
    {
      ip_address_encode (&r->src, r->is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
			 &api->src_prefix.address);
      ip_address_encode (&r->dst, r->is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
			 &api->dst_prefix.address);
      api->src_prefix.len = r->src_prefixlen;
      api->dst_prefix.len = r->dst_prefixlen;
    }
#define _(name) api->name = clib_host_to_net_u16 (r->mitigation.name);
  foreach_mitigation_u16
#undef _
#define _(name) api->name = r->mitigation.name;
    foreach_mitigation_u8
#undef _
}

static void
vl_api_acl_mitigation_add_replace_t_handler (vl_api_acl_mitigation_add_replace_t *mp)
{
  acl_mitigation_main_t *mm = &acl_mitigation_main;
  vl_api_acl_mitigation_add_replace_reply_t *rmp;
  u32 index = clib_net_to_host_u32 (mp->acl_index);
  u32 count = clib_net_to_host_u32 (mp->count);
  int rv = VNET_API_ERROR_INVALID_VALUE;
  acl_rule_t *rules = 0;
  u64 expected = sizeof (*mp) + (u64) count * sizeof (mp->r[0]);
  if (expected <= vl_msg_api_get_msg_length (mp))
    {
      rv = 0;
      if (count)
	vec_validate (rules, count - 1);
      for (u32 i = 0; i < count && !rv; i++)
	rv = mitigation_decode (&mp->r[i], &rules[i]);
      if (!rv)
	{
	  rv = mitigation_replace (rules, &index, mp->tag);
	  rules = 0; /* replace consumes the vector even on failure */
	}
    }
  vec_free (rules);
  REPLY_MACRO2 (VL_API_ACL_MITIGATION_ADD_REPLACE_REPLY,
		({ rmp->acl_index = clib_host_to_net_u32 (index); }));
}

static int
mitigation_rule_change (u32 *index, u32 *rule_index, u8 is_add,
			const vl_api_acl_mitigation_rule_t *api_rule)
{
  acl_mitigation_main_t *mm = &acl_mitigation_main;
  acl_rule_t *rules = 0;
  u8 tag[64] = "mitigation";
  if (*index != ~0u)
    {
      if (pool_is_free_index (acl_main.acls, *index) || !acl_main.acls[*index].is_mitigation)
	return VNET_API_ERROR_NO_SUCH_ENTRY;
      rules = vec_dup (mm->rules[*index]);
      clib_memcpy_fast (tag, acl_main.acls[*index].tag, sizeof (tag));
    }
  if (is_add)
    {
      acl_rule_t r;
      int rv = mitigation_decode (api_rule, &r);
      if (rv)
	{
	  vec_free (rules);
	  return rv;
	}
      *rule_index = vec_len (rules);
      vec_add1 (rules, r);
    }
  else
    {
      if (*rule_index >= vec_len (rules))
	{
	  vec_free (rules);
	  return VNET_API_ERROR_NO_SUCH_ENTRY;
	}
      vec_delete (rules, 1, *rule_index);
    }
  return mitigation_replace (rules, index, tag);
}

static void
vl_api_acl_mitigation_rule_add_del_t_handler (vl_api_acl_mitigation_rule_add_del_t *mp)
{
  acl_mitigation_main_t *mm = &acl_mitigation_main;
  vl_api_acl_mitigation_rule_add_del_reply_t *rmp;
  u32 index = clib_net_to_host_u32 (mp->acl_index);
  u32 rule_index = clib_net_to_host_u32 (mp->rule_index);
  int rv = mitigation_rule_change (&index, &rule_index, mp->is_add, &mp->rule);
  REPLY_MACRO2 (VL_API_ACL_MITIGATION_RULE_ADD_DEL_REPLY, ({
		  rmp->acl_index = clib_host_to_net_u32 (index);
		  rmp->rule_index = clib_host_to_net_u32 (rule_index);
		}));
}

static void
vl_api_acl_mitigation_interface_dump_t_handler (vl_api_acl_mitigation_interface_dump_t *mp)
{
  acl_mitigation_main_t *mm = &acl_mitigation_main;
  vl_api_registration_t *reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;
  for (u32 i = 0; i < vec_len (mm->bindings); i++)
    if (mm->bindings[i] != ~0u)
      {
	vl_api_acl_mitigation_interface_details_t *d = vl_msg_api_alloc_zero (sizeof (*d));
	d->_vl_msg_id =
	  clib_host_to_net_u16 (VL_API_ACL_MITIGATION_INTERFACE_DETAILS + mm->msg_id_base);
	d->context = mp->context;
	d->sw_if_index = clib_host_to_net_u32 (i);
	d->acl_index = clib_host_to_net_u32 (mm->bindings[i]);
	vl_api_send_msg (reg, (u8 *) d);
      }
}

static void
vl_api_acl_mitigation_interface_set_t_handler (vl_api_acl_mitigation_interface_set_t *mp)
{
  acl_mitigation_main_t *mm = &acl_mitigation_main;
  vl_api_acl_mitigation_interface_set_reply_t *rmp;
  int rv = acl_mitigation_bind (clib_net_to_host_u32 (mp->sw_if_index),
				clib_net_to_host_u32 (mp->acl_index));
  REPLY_MACRO (VL_API_ACL_MITIGATION_INTERFACE_SET_REPLY);
}

static void
vl_api_acl_mitigation_config_t_handler (vl_api_acl_mitigation_config_t *mp)
{
  acl_mitigation_main_t *mm = &acl_mitigation_main;
  vl_api_acl_mitigation_config_reply_t *rmp;
  int rv = acl_mitigation_psample_enable (mp->psample_enable);
  if (!rv)
    mm->per_rule_counters = mp->per_rule_counters;
  REPLY_MACRO (VL_API_ACL_MITIGATION_CONFIG_REPLY);
}

static void
mitigation_get_counts (u32 index, u32 logical, vlib_counter_t *counter, u64 *sampled, u64 *failed)
{
  acl_mitigation_main_t *mm = &acl_mitigation_main;
  clib_memset (counter, 0, sizeof (*counter));
  *sampled = *failed = 0;
  for (u32 family = 0; family < 2; family++)
    {
      u32 ace = mm->mapping[index][logical].ace[family];
      if (ace == ~0u)
	continue;
      vlib_counter_t c;
      vlib_get_combined_counter (&acl_main.combined_acl_counters[index], ace, &c);
      counter->packets += c.packets;
      counter->bytes += c.bytes;
    }
  acl_mitigation_worker_t *w;
  vec_foreach (w, mm->workers)
    {
      *sampled += w->samples[index][logical].sampled;
      *failed += w->samples[index][logical].failed;
    }
}

static void
vl_api_acl_mitigation_dump_t_handler (vl_api_acl_mitigation_dump_t *mp)
{
  acl_mitigation_main_t *mm = &acl_mitigation_main;
  vl_api_registration_t *reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;
  u32 selected = clib_net_to_host_u32 (mp->acl_index);
  acl_list_t *a;
  pool_foreach (a, acl_main.acls)
    {
      u32 index = a - acl_main.acls;
      if (!a->is_mitigation || (selected != ~0u && selected != index))
	continue;
      acl_rule_t *r;
      vec_foreach (r, mm->rules[index])
	{
	  vl_api_acl_mitigation_details_t *d = vl_msg_api_alloc_zero (sizeof (*d));
	  d->_vl_msg_id = clib_host_to_net_u16 (VL_API_ACL_MITIGATION_DETAILS + mm->msg_id_base);
	  d->context = mp->context;
	  d->acl_index = clib_host_to_net_u32 (index);
	  d->rule_index = clib_host_to_net_u32 (r->logical_rule_index);
	  clib_memcpy_fast (d->tag, a->tag, sizeof (d->tag));
	  mitigation_encode (r, &d->rule);
	  vlib_counter_t c;
	  u64 sampled, failed;
	  mitigation_get_counts (index, r->logical_rule_index, &c, &sampled, &failed);
	  acl_mitigation_rate_t *rate = &mm->rates[index][r->logical_rule_index];
	  mitigation_update_rate (rate, &c);
	  d->pps = clib_host_to_net_f64 (rate->pps);
	  d->l3_bps = clib_host_to_net_f64 (rate->l3_bps);
	  d->l1_bps = clib_host_to_net_f64 (rate->l1_bps);
	  d->packets = clib_host_to_net_u64 (c.packets);
	  d->bytes = clib_host_to_net_u64 (c.bytes);
	  d->sampled = clib_host_to_net_u64 (sampled);
	  d->sample_failed = clib_host_to_net_u64 (failed);
	  vl_api_send_msg (reg, (u8 *) d);
	}
    }
}

static void
vl_api_acl_mitigation_stats_get_t_handler (vl_api_acl_mitigation_stats_get_t *mp)
{
  acl_mitigation_main_t *mm = &acl_mitigation_main;
  vl_api_acl_mitigation_stats_get_reply_t *rmp;
  int rv = 0;
  vlib_counter_t processed, dropped;
  vlib_get_combined_counter (&mm->aggregate, 0, &processed);
  vlib_get_combined_counter (&mm->aggregate, 1, &dropped);
  mitigation_update_rate (&mm->aggregate_rates[0], &processed);
  mitigation_update_rate (&mm->aggregate_rates[1], &dropped);
  REPLY_MACRO2 (VL_API_ACL_MITIGATION_STATS_GET_REPLY, ({
		  rmp->processed_packets = clib_host_to_net_u64 (processed.packets);
		  rmp->processed_bytes = clib_host_to_net_u64 (processed.bytes);
		  rmp->dropped_packets = clib_host_to_net_u64 (dropped.packets);
		  rmp->dropped_bytes = clib_host_to_net_u64 (dropped.bytes);
		  rmp->processed_pps = clib_host_to_net_f64 (mm->aggregate_rates[0].pps);
		  rmp->processed_l3_bps = clib_host_to_net_f64 (mm->aggregate_rates[0].l3_bps);
		  rmp->processed_l1_bps = clib_host_to_net_f64 (mm->aggregate_rates[0].l1_bps);
		  rmp->dropped_pps = clib_host_to_net_f64 (mm->aggregate_rates[1].pps);
		  rmp->dropped_l3_bps = clib_host_to_net_f64 (mm->aggregate_rates[1].l3_bps);
		  rmp->dropped_l1_bps = clib_host_to_net_f64 (mm->aggregate_rates[1].l1_bps);
		}));
}

static clib_error_t *
mitigation_bind_cli (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u32 sw_if_index, index = ~0u;
  if (!unformat (input, "%U", unformat_vnet_sw_interface, vnet_get_main (), &sw_if_index))
    return clib_error_return (0, "expected interface");
  if (!unformat (input, "acl %u", &index) && !unformat (input, "disable"))
    return clib_error_return (0, "expected acl <index> or disable");
  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unexpected input");
  int rv = acl_mitigation_bind (sw_if_index, index);
  return rv ? clib_error_return (0, "binding failed: %d", rv) : 0;
}
VLIB_CLI_COMMAND (mitigation_bind_command, static) = {
  .path = "set interface acl-mitigation",
  .short_help = "set interface acl-mitigation <interface> acl <index> | disable",
  .function = mitigation_bind_cli,
};

static clib_error_t *
mitigation_rule_cli (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u32 index = ~0u;
  acl_rule_t rule = { .is_ipv6 = 2 };
  acl_mitigation_match_t *m = &rule.mitigation;
  u32 action = ~0u, x, y;
  ip46_address_t address = { 0 };
  u32 len;
  u8 tag[64] = "mitigation";
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "acl %u", &index))
	;
      else if (unformat (input, "order %u", &rule.order))
	;
      else if (unformat (input, "action drop"))
	action = 0;
      else if (unformat (input, "action permit"))
	action = 1;
      else if (unformat (input, "sample %u", &rule.sample_ratio))
	;
      else if (unformat (input, "sample-group %u", &rule.sample_group))
	;
#define PREFIX(token, bit, field, family, parser, member)                                          \
  else if (unformat (input, token " %U/%u", parser, &address.member, &len))                        \
  {                                                                                                \
    if (len > (family ? 128 : 32) || (rule.is_ipv6 != 2 && rule.is_ipv6 != family))                \
      return clib_error_return (0, "invalid prefix or mixed families");                            \
    rule.is_ipv6 = family;                                                                         \
    rule.field = address;                                                                          \
    rule.field##_prefixlen = len;                                                                  \
    m->flags |= bit;                                                                               \
  }
      PREFIX ("src4", ACL_MITIGATION_SRC_PREFIX, src, 0, unformat_ip4_address, ip4)
      PREFIX ("dst4", ACL_MITIGATION_DST_PREFIX, dst, 0, unformat_ip4_address, ip4)
      PREFIX ("src6", ACL_MITIGATION_SRC_PREFIX, src, 1, unformat_ip6_address, ip6)
      PREFIX ("dst6", ACL_MITIGATION_DST_PREFIX, dst, 1, unformat_ip6_address, ip6)
#undef PREFIX
#define RANGE(token, bit, field)                                                                   \
  else if (unformat (input, token " %u-%u", &x, &y))                                               \
  {                                                                                                \
    if (x > 65535 || y > 65535)                                                                    \
      return clib_error_return (0, "range overflow");                                              \
    m->field##_first = x;                                                                          \
    m->field##_last = y;                                                                           \
    m->flags |= bit;                                                                               \
  }                                                                                                \
  else if (unformat (input, token " %u", &x))                                                      \
  {                                                                                                \
    if (x > 65535)                                                                                 \
      return clib_error_return (0, "range overflow");                                              \
    m->field##_first = m->field##_last = x;                                                        \
    m->flags |= bit;                                                                               \
  }
      RANGE ("src-port", ACL_MITIGATION_SRC_PORT, src_port)
      RANGE ("dst-port", ACL_MITIGATION_DST_PORT, dst_port)
      RANGE ("either-port", ACL_MITIGATION_EITHER_PORT, either_port)
      RANGE ("packet-length", ACL_MITIGATION_PACKET_LENGTH, packet_length)
#undef RANGE
      else if (unformat (input, "proto %u", &x))
      {
	if (x > 255)
	  return clib_error_return (0, "protocol overflow");
	rule.proto = x;
	m->flags |= ACL_MITIGATION_PROTO;
      }
#define BYTE(token, bit, field)                                                                    \
  else if (unformat (input, token " %u", &x))                                                      \
  {                                                                                                \
    if (x > 255)                                                                                   \
      return clib_error_return (0, "value overflow");                                              \
    m->field = x;                                                                                  \
    m->flags |= bit;                                                                               \
  }
      BYTE ("dscp", ACL_MITIGATION_DSCP, dscp)
      BYTE ("icmp-type", ACL_MITIGATION_ICMP_TYPE, icmp_type)
      BYTE ("icmp-code", ACL_MITIGATION_ICMP_CODE, icmp_code)
#undef BYTE
      else if (unformat (input, "tcp-flags %x %x", &x, &y))
      {
	if (x > 255 || y > 255)
	  return clib_error_return (0, "flags overflow");
	m->tcp_flags_value = x;
	m->tcp_flags_mask = y;
	m->flags |= ACL_MITIGATION_TCP_FLAGS;
      }
      else if (unformat (input, "fragment %x %x", &x, &y))
      {
	if (x > 15 || y > 15)
	  return clib_error_return (0, "fragment overflow");
	m->fragment_value = x;
	m->fragment_mask = y;
	m->flags |= ACL_MITIGATION_FRAGMENT;
      }
      else return clib_error_return (0, "unknown input: %U", format_unformat_error, input);
    }
  if (action == ~0u)
    return clib_error_return (0, "action drop or permit is required");
  rule.is_permit = action;
  acl_rule_t *rules = 0;
  if (index != ~0u)
    {
      if (pool_is_free_index (acl_main.acls, index) || !acl_main.acls[index].is_mitigation)
	return clib_error_return (0, "not a mitigation ACL");
      rules = vec_dup (acl_mitigation_main.rules[index]);
      clib_memcpy_fast (tag, acl_main.acls[index].tag, sizeof (tag));
    }
  vec_add1 (rules, rule);
  int rv = mitigation_replace (rules, &index, tag);
  if (rv)
    return clib_error_return (0, "rule rejected: %d", rv);
  vlib_cli_output (vm, "mitigation ACL %u", index);
  return 0;
}
VLIB_CLI_COMMAND (mitigation_rule_command, static) = {
  .path = "acl mitigation rule add",
  .short_help = "acl mitigation rule add [acl <index>] [order N] [src4|dst4|src6|dst6 prefix] "
		"[proto N] [src-port|dst-port|either-port X[-Y]] [icmp-type N] [icmp-code N] "
		"[tcp-flags VALUE MASK] [packet-length X[-Y]] [dscp N] [fragment VALUE MASK] "
		"action drop|permit [sample N] [sample-group N]",
  .function = mitigation_rule_cli,
};

static clib_error_t *
mitigation_delete_cli (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u32 index, rule;
  if (!unformat (input, "acl %u rule %u", &index, &rule) ||
      unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "expected acl <index> rule <index>");
  int rv = mitigation_rule_change (&index, &rule, 0, 0);
  return rv ? clib_error_return (0, "delete failed: %d", rv) : 0;
}
VLIB_CLI_COMMAND (mitigation_delete_command, static) = {
  .path = "acl mitigation rule del",
  .short_help = "acl mitigation rule del acl <index> rule <index>",
  .function = mitigation_delete_cli,
};

static clib_error_t *
mitigation_show_cli (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  acl_mitigation_main_t *mm = &acl_mitigation_main;
  u32 selected = ~0u;
  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT && !unformat (input, "%u", &selected))
    return clib_error_return (0, "expected ACL index");
  vlib_cli_output (vm, "per-rule counters %s; psample %s",
		   mm->per_rule_counters ? "enabled" : "disabled",
		   mm->psample_enabled ? "enabled" : "disabled");
  acl_list_t *a;
  pool_foreach (a, acl_main.acls)
    {
      u32 index = a - acl_main.acls;
      if (!a->is_mitigation || (selected != ~0u && selected != index))
	continue;
      vlib_cli_output (vm, "ACL %u tag %s logical rules %u compiled ACEs %u", index, a->tag,
		       vec_len (mm->rules[index]), vec_len (a->rules));
      acl_rule_t *r;
      vec_foreach (r, mm->rules[index])
	{
	  vlib_counter_t c;
	  u64 sampled, failed;
	  mitigation_get_counts (index, r->logical_rule_index, &c, &sampled, &failed);
	  acl_mitigation_rate_t *rate = &mm->rates[index][r->logical_rule_index];
	  mitigation_update_rate (rate, &c);
	  vlib_cli_output (vm, "  pps %.2f L3 bps %.2f L1 bps %.2f", rate->pps, rate->l3_bps,
			   rate->l1_bps);
	  vlib_cli_output (vm,
			   "  rule %u order %u family %u flags 0x%x action %s sample %u packets "
			   "%llu bytes %llu sampled %llu failed %llu",
			   r->logical_rule_index, r->order, r->is_ipv6, r->mitigation.flags,
			   r->is_permit ? "permit" : "drop", r->sample_ratio, c.packets, c.bytes,
			   sampled, failed);
	}
    }
  for (u32 which = 0; which < 2; which++)
    {
      vlib_counter_t c;
      vlib_get_combined_counter (&mm->aggregate, which, &c);
      acl_mitigation_rate_t *rate = &mm->aggregate_rates[which];
      mitigation_update_rate (rate, &c);
      vlib_cli_output (vm, "%s packets %llu bytes %llu pps %.2f L3 bps %.2f L1 bps %.2f",
		       which ? "dropped" : "processed", c.packets, c.bytes, rate->pps, rate->l3_bps,
		       rate->l1_bps);
    }
  for (u32 i = 0; i < vec_len (mm->bindings); i++)
    if (mm->bindings[i] != ~0u)
      vlib_cli_output (vm, "interface %U ACL %u context %u", format_vnet_sw_if_index_name,
		       vnet_get_main (), i, mm->bindings[i], mm->contexts[i]);
  return 0;
}
VLIB_CLI_COMMAND (mitigation_show_command, static) = {
  .path = "show acl mitigation",
  .short_help = "show acl mitigation [acl-index]",
  .function = mitigation_show_cli,
};

static clib_error_t *
mitigation_config_cli (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u32 counters, sample;
  if (!unformat (input, "counters %u psample %u", &counters, &sample) || counters > 1 ||
      sample > 1 || unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "expected counters 0|1 psample 0|1");
  int rv = acl_mitigation_psample_enable (sample);
  if (rv)
    return clib_error_return (0, "psample unavailable: %d (load kernel psample module)", rv);
  acl_mitigation_main.per_rule_counters = counters;
  return 0;
}
VLIB_CLI_COMMAND (mitigation_config_command, static) = {
  .path = "acl mitigation config",
  .short_help = "acl mitigation config counters 0|1 psample 0|1",
  .function = mitigation_config_cli,
};

#include <acl/mitigation.api.c>
static clib_error_t *
mitigation_init (vlib_main_t *vm)
{
  acl_mitigation_main_t *mm = &acl_mitigation_main;
  clib_error_t *err = acl_plugin_exports_init (&mm->acl);
  if (err)
    return err;
  mm->user_id = mm->acl.register_user_module ("ACL mitigation", "sw_if_index", "unused");
  mm->aggregate.stat_segment_name = "/acl/mitigation/aggregate";
  vlib_validate_combined_counter (&mm->aggregate, 1);
  vlib_clear_combined_counters (&mm->aggregate);
  mm->aggregate_rates[0].time = mm->aggregate_rates[1].time = vlib_time_now (vm);
  mm->per_rule_counters = 1;
  vec_validate (mm->workers, vlib_get_thread_main ()->n_vlib_mains - 1);
  acl_mitigation_worker_t *w;
  vec_foreach (w, mm->workers)
    w->psample_fd = -1;
  mm->msg_id_base = setup_message_id_table ();
  return 0;
}
VLIB_INIT_FUNCTION (mitigation_init) = { .runs_after = VLIB_INITS ("acl_init") };
