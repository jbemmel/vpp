/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 *
 * Sync Linux SRv6 lwtunnel routes (SEG6_LOCAL / SEG6) into VPP SRv6 state.
 *
 * libnl has no SEG6 encap ops, so RTA_ENCAP is parsed from the raw nl_msg.
 * Phase 1: End.DT4 / End.DT6 localsids and H.Encaps headend steer.
 *
 * BSID pool: fd00:ffff:1::/96 (never use a remote service SID as BSID).
 */

#include <linux/rtnetlink.h>
#include <linux/lwtunnel.h>
#include <linux/seg6.h>
#include <linux/seg6_local.h>
#include <linux/seg6_iptunnel.h>

#include <netlink/attr.h>
#include <netlink/msg.h>
#include <netlink/errno.h>

#include <vnet/fib/fib_table.h>
#include <vnet/srv6/sr.h>

#include <linux-cp/lcp_srv6_sync.h>

#define LCP_SRV6_MAX_SIDS 16

static vlib_log_class_t lcp_srv6_logger;

#define LCP_SRV6_DBG(...)  vlib_log_debug (lcp_srv6_logger, __VA_ARGS__)
#define LCP_SRV6_INFO(...) vlib_log_notice (lcp_srv6_logger, __VA_ARGS__)
#define LCP_SRV6_ERR(...)  vlib_log_err (lcp_srv6_logger, __VA_ARGS__)

static inline u32
lcp_srv6_table_k2f (u32 k)
{
  /* Match lcp_router_table_k2f: kernel local/main → VPP table 0 */
  if (k == 255 || k == 254)
    return 0;
  return k;
}

typedef enum
{
  LCP_SRV6_ENCAP_NONE = 0,
  LCP_SRV6_ENCAP_SEG6_LOCAL,
  LCP_SRV6_ENCAP_SEG6,
} lcp_srv6_encap_kind_t;

typedef struct
{
  lcp_srv6_encap_kind_t kind;
  u32 action;	      /* SEG6_LOCAL_ACTION_* */
  u32 dest_table;     /* Linux table / vrftable before k2f */
  int mode;	      /* SEG6_IPTUN_MODE_* */
  u8 n_segs;
  ip6_address_t segs[LCP_SRV6_MAX_SIDS];
} lcp_srv6_encap_t;

typedef struct
{
  ip6_address_t sid;
  u16 plen;
  u8 behavior;
  u32 dest_table; /* VPP fib table id */
} lcp_srv6_localsid_t;

typedef struct
{
  u32 table_id;
  u8 is_ip6;
  u8 plen;
  u8 pad[2];
  ip46_address_t addr;
} lcp_srv6_steer_key_t;

typedef struct
{
  lcp_srv6_steer_key_t key;
  ip6_address_t bsid;
  ip6_address_t *segments;
} lcp_srv6_steer_t;

typedef struct
{
  uword *localsid_by_sid; /* ip6_address_t → pool index */
  lcp_srv6_localsid_t *localsids;

  uword *steer_by_key; /* lcp_srv6_steer_key_t → pool index */
  lcp_srv6_steer_t *steers;

  u32 bsid_counter;
} lcp_srv6_main_t;

static lcp_srv6_main_t lcp_srv6_main;

static void
lcp_srv6_alloc_bsid (ip6_address_t *bsid)
{
  lcp_srv6_main_t *sm = &lcp_srv6_main;

  clib_memset (bsid, 0, sizeof (*bsid));
  /* fd00:ffff:1::/96 */
  bsid->as_u16[0] = clib_host_to_net_u16 (0xfd00);
  bsid->as_u16[1] = clib_host_to_net_u16 (0xffff);
  bsid->as_u16[2] = clib_host_to_net_u16 (0x0001);
  if (sm->bsid_counter == 0)
    sm->bsid_counter = 1;
  bsid->as_u32[3] = clib_host_to_net_u32 (sm->bsid_counter++);
}

static int
lcp_srv6_parse_seg6local (struct nlattr *encap, lcp_srv6_encap_t *out)
{
  struct nlattr *tb[SEG6_LOCAL_MAX + 1];
  int err;

  clib_memset (tb, 0, sizeof (tb));
  err = nla_parse_nested (tb, SEG6_LOCAL_MAX, encap, NULL);
  if (err < 0)
    return err;

  out->kind = LCP_SRV6_ENCAP_SEG6_LOCAL;
  out->action = SEG6_LOCAL_ACTION_UNSPEC;
  out->dest_table = 254; /* main */

  if (tb[SEG6_LOCAL_ACTION])
    out->action = nla_get_u32 (tb[SEG6_LOCAL_ACTION]);

  if (tb[SEG6_LOCAL_TABLE])
    out->dest_table = nla_get_u32 (tb[SEG6_LOCAL_TABLE]);

  if (tb[SEG6_LOCAL_VRFTABLE])
    out->dest_table = nla_get_u32 (tb[SEG6_LOCAL_VRFTABLE]);

  return 0;
}

static int
lcp_srv6_parse_seg6 (struct nlattr *encap, lcp_srv6_encap_t *out)
{
  struct nlattr *tb[SEG6_IPTUNNEL_MAX + 1];
  struct seg6_iptunnel_encap *ipt;
  struct ipv6_sr_hdr *srh;
  int err, i, n;

  clib_memset (tb, 0, sizeof (tb));
  err = nla_parse_nested (tb, SEG6_IPTUNNEL_MAX, encap, NULL);
  if (err < 0)
    return err;

  if (!tb[SEG6_IPTUNNEL_SRH])
    return -1;

  ipt = (struct seg6_iptunnel_encap *) nla_data (tb[SEG6_IPTUNNEL_SRH]);
  if (nla_len (tb[SEG6_IPTUNNEL_SRH]) < (int) sizeof (*ipt))
    return -1;

  srh = ipt->srh;
  out->kind = LCP_SRV6_ENCAP_SEG6;
  out->mode = ipt->mode;
  out->n_segs = 0;

  n = srh->first_segment + 1;
  if (n <= 0 || n > LCP_SRV6_MAX_SIDS)
    return -1;

  /* SRH stores SIDs in reverse order; present as first-to-last for VPP */
  for (i = n - 1; i >= 0; i--)
    {
      clib_memcpy (&out->segs[out->n_segs], &srh->segments[i],
		   sizeof (ip6_address_t));
      out->n_segs++;
    }

  return 0;
}

static int
lcp_srv6_parse_encap_attrs (struct nlattr *encap, struct nlattr *encap_type,
			    lcp_srv6_encap_t *out)
{
  u16 etype;

  if (!encap || !encap_type)
    return -1;

  etype = nla_get_u16 (encap_type);
  clib_memset (out, 0, sizeof (*out));

  if (etype == LWTUNNEL_ENCAP_SEG6_LOCAL)
    return lcp_srv6_parse_seg6local (encap, out);
  if (etype == LWTUNNEL_ENCAP_SEG6)
    return lcp_srv6_parse_seg6 (encap, out);

  return -1;
}

static int
lcp_srv6_parse_multipath_encap (struct nlattr *mp, lcp_srv6_encap_t *out)
{
  int len = nla_len (mp);
  u8 *ptr = nla_data (mp);

  while (len >= (int) sizeof (struct rtnexthop))
    {
      struct rtnexthop *rtnh = (struct rtnexthop *) ptr;
      struct nlattr *tb[RTA_MAX + 1];
      int attrlen;

      if (rtnh->rtnh_len > len)
	break;

      attrlen = rtnh->rtnh_len - sizeof (*rtnh);
      if (attrlen > 0)
	{
	  clib_memset (tb, 0, sizeof (tb));
	  if (nla_parse (tb, RTA_MAX, (struct nlattr *) RTNH_DATA (rtnh),
			 attrlen, NULL) >= 0 &&
	      tb[RTA_ENCAP] && tb[RTA_ENCAP_TYPE] &&
	      lcp_srv6_parse_encap_attrs (tb[RTA_ENCAP], tb[RTA_ENCAP_TYPE],
					 out) == 0)
	    return 0;
	}

      len -= NLMSG_ALIGN (rtnh->rtnh_len);
      ptr += NLMSG_ALIGN (rtnh->rtnh_len);
    }

  return -1;
}

/**
 * Parse SRv6 encap from a raw RTM_NEWROUTE/DELROUTE message.
 * @return 0 on success (SRv6 encap found), -1 otherwise.
 */
static int
lcp_srv6_parse_encap_from_nlmsg (struct nl_msg *msg, lcp_srv6_encap_t *out)
{
  struct nlmsghdr *nlh;
  struct nlattr *tb[RTA_MAX + 1];
  int err;

  if (!msg || !out)
    return -1;

  nlh = nlmsg_hdr (msg);
  if (nlh->nlmsg_type != RTM_NEWROUTE && nlh->nlmsg_type != RTM_DELROUTE)
    return -1;

  clib_memset (tb, 0, sizeof (tb));
  err = nlmsg_parse (nlh, sizeof (struct rtmsg), tb, RTA_MAX, NULL);
  if (err < 0)
    return -1;

  if (tb[RTA_ENCAP] && tb[RTA_ENCAP_TYPE] &&
      lcp_srv6_parse_encap_attrs (tb[RTA_ENCAP], tb[RTA_ENCAP_TYPE], out) == 0)
    return 0;

  if (tb[RTA_MULTIPATH] &&
      lcp_srv6_parse_multipath_encap (tb[RTA_MULTIPATH], out) == 0)
    return 0;

  return -1;
}

static int
lcp_srv6_route_dst_from_nlmsg (struct nl_msg *msg, fib_prefix_t *pfx,
			       u32 *table_id)
{
  struct nlmsghdr *nlh;
  struct rtmsg *rtm;
  struct nlattr *tb[RTA_MAX + 1];
  int err;

  nlh = nlmsg_hdr (msg);
  rtm = nlmsg_data (nlh);

  clib_memset (tb, 0, sizeof (tb));
  err = nlmsg_parse (nlh, sizeof (struct rtmsg), tb, RTA_MAX, NULL);
  if (err < 0)
    return -1;

  clib_memset (pfx, 0, sizeof (*pfx));
  *table_id = rtm->rtm_table;
  if (tb[RTA_TABLE])
    *table_id = nla_get_u32 (tb[RTA_TABLE]);

  if (!tb[RTA_DST])
    return -1;

  pfx->fp_len = rtm->rtm_dst_len;
  if (rtm->rtm_family == AF_INET6)
    {
      pfx->fp_proto = FIB_PROTOCOL_IP6;
      if (nla_len (tb[RTA_DST]) < (int) sizeof (ip6_address_t))
	return -1;
      clib_memcpy (&pfx->fp_addr.ip6, nla_data (tb[RTA_DST]),
		   sizeof (ip6_address_t));
    }
  else if (rtm->rtm_family == AF_INET)
    {
      pfx->fp_proto = FIB_PROTOCOL_IP4;
      if (nla_len (tb[RTA_DST]) < (int) sizeof (ip4_address_t))
	return -1;
      clib_memcpy (&pfx->fp_addr.ip4, nla_data (tb[RTA_DST]),
		   sizeof (ip4_address_t));
    }
  else
    return -1;

  return 0;
}

static int
lcp_srv6_route_dst_from_rtnl (struct rtnl_route *rr, fib_prefix_t *pfx,
			      u32 *table_id)
{
  struct nl_addr *addr;

  if (!rr)
    return -1;

  addr = rtnl_route_get_dst (rr);
  if (!addr)
    return -1;

  *table_id = rtnl_route_get_table (rr);
  clib_memset (pfx, 0, sizeof (*pfx));
  pfx->fp_len = nl_addr_get_prefixlen (addr);

  switch (nl_addr_get_family (addr))
    {
    case AF_INET6:
      pfx->fp_proto = FIB_PROTOCOL_IP6;
      if (nl_addr_get_len (addr) < (int) sizeof (ip6_address_t))
	return -1;
      clib_memcpy (&pfx->fp_addr.ip6, nl_addr_get_binary_addr (addr),
		   sizeof (ip6_address_t));
      break;
    case AF_INET:
      pfx->fp_proto = FIB_PROTOCOL_IP4;
      if (nl_addr_get_len (addr) < (int) sizeof (ip4_address_t))
	return -1;
      clib_memcpy (&pfx->fp_addr.ip4, nl_addr_get_binary_addr (addr),
		   sizeof (ip4_address_t));
      break;
    default:
      return -1;
    }

  return 0;
}

static int
lcp_srv6_segs_equal (ip6_address_t *a, u8 na, ip6_address_t *b, u8 nb)
{
  u8 i;

  if (na != nb)
    return 0;
  for (i = 0; i < na; i++)
    if (!ip6_address_is_equal (&a[i], &b[i]))
      return 0;
  return 1;
}

static void
lcp_srv6_ensure_table (fib_protocol_t proto, u32 table_id)
{
  if (fib_table_find (proto, table_id) == ~0)
    fib_table_find_or_create_and_lock (proto, table_id, FIB_SOURCE_SR);
}

static int
lcp_srv6_localsid_add (ip6_address_t *sid, u16 plen, u8 behavior,
		       u32 dest_table)
{
  lcp_srv6_main_t *sm = &lcp_srv6_main;
  lcp_srv6_localsid_t *ls;
  ip46_address_t nh = {};
  uword *p;
  int rv;
  fib_protocol_t dproto =
    (behavior == SR_BEHAVIOR_DT4) ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;

  lcp_srv6_ensure_table (FIB_PROTOCOL_IP6, 0);
  lcp_srv6_ensure_table (dproto, dest_table);

  p = hash_get_mem (sm->localsid_by_sid, sid);
  if (p)
    {
      ls = pool_elt_at_index (sm->localsids, p[0]);
      if (ls->behavior == behavior && ls->dest_table == dest_table &&
	  ls->plen == plen)
	return 0;

      /* Replace: delete then re-add */
      rv = sr_cli_localsid (1 /* is_del */, &ls->sid, ls->plen, 0, ls->behavior,
			    ls->dest_table, 0, &nh, 0, NULL);
      if (rv)
	LCP_SRV6_DBG ("localsid del before replace rv=%d sid=%U", rv,
		      format_ip6_address, &ls->sid);
      hash_unset_mem (sm->localsid_by_sid, &ls->sid);
      pool_put (sm->localsids, ls);
    }

  rv = sr_cli_localsid (0 /* is_del */, sid, plen, 0, behavior, dest_table, 0,
			&nh, 0, NULL);
  if (rv)
    {
      LCP_SRV6_ERR ("sr_cli_localsid add rv=%d sid=%U/%u behavior=%u table=%u",
		    rv, format_ip6_address, sid, plen, behavior, dest_table);
      return rv;
    }

  pool_get (sm->localsids, ls);
  clib_memset (ls, 0, sizeof (*ls));
  ls->sid = *sid;
  ls->plen = plen;
  ls->behavior = behavior;
  ls->dest_table = dest_table;
  hash_set_mem (sm->localsid_by_sid, &ls->sid, ls - sm->localsids);

  LCP_SRV6_INFO ("localsid add %U/%u behavior %u dest-table %u",
		 format_ip6_address, sid, plen, behavior, dest_table);
  return 0;
}

static int
lcp_srv6_localsid_del (ip6_address_t *sid)
{
  lcp_srv6_main_t *sm = &lcp_srv6_main;
  lcp_srv6_localsid_t *ls;
  ip46_address_t nh = {};
  uword *p;
  int rv;

  p = hash_get_mem (sm->localsid_by_sid, sid);
  if (!p)
    return 0;

  ls = pool_elt_at_index (sm->localsids, p[0]);
  rv = sr_cli_localsid (1, &ls->sid, ls->plen, 0, ls->behavior, ls->dest_table,
			0, &nh, 0, NULL);
  if (rv)
    LCP_SRV6_DBG ("localsid del rv=%d sid=%U", rv, format_ip6_address,
		  &ls->sid);

  hash_unset_mem (sm->localsid_by_sid, &ls->sid);
  pool_put (sm->localsids, ls);

  LCP_SRV6_INFO ("localsid del %U", format_ip6_address, sid);
  return 0;
}

static void
lcp_srv6_steer_key_init (lcp_srv6_steer_key_t *key, u32 table_id,
			 const fib_prefix_t *pfx)
{
  clib_memset (key, 0, sizeof (*key));
  key->table_id = table_id;
  key->plen = pfx->fp_len;
  key->is_ip6 = (pfx->fp_proto == FIB_PROTOCOL_IP6);
  key->addr = pfx->fp_addr;
}

static int
lcp_srv6_steer_del_internal (lcp_srv6_steer_t *st)
{
  ip46_address_t prefix = st->key.addr;
  u8 ttype = st->key.is_ip6 ? SR_STEER_IPV6 : SR_STEER_IPV4;
  int rv;

  rv = sr_steering_policy (1 /* is_del */, &st->bsid, ~0, st->key.table_id,
			   &prefix, st->key.plen, ~0, ttype);
  if (rv)
    LCP_SRV6_DBG ("steer del rv=%d", rv);

  rv = sr_policy_del (&st->bsid, ~0);
  if (rv)
    LCP_SRV6_DBG ("policy del rv=%d bsid=%U", rv, format_ip6_address,
		  &st->bsid);

  vec_free (st->segments);
  return 0;
}

static int
lcp_srv6_headend_add (u32 table_id, const fib_prefix_t *pfx,
		      lcp_srv6_encap_t *encap)
{
  lcp_srv6_main_t *sm = &lcp_srv6_main;
  lcp_srv6_steer_key_t key;
  lcp_srv6_steer_t *st;
  ip6_address_t *segments = 0;
  ip6_address_t bsid;
  ip46_address_t prefix;
  uword *p;
  u8 ttype;
  u8 i;
  int rv;

  if (encap->n_segs == 0)
    return -1;

  lcp_srv6_steer_key_init (&key, table_id, pfx);
  ttype = (pfx->fp_proto == FIB_PROTOCOL_IP6) ? SR_STEER_IPV6 : SR_STEER_IPV4;
  prefix = pfx->fp_addr;

  for (i = 0; i < encap->n_segs; i++)
    vec_add1 (segments, encap->segs[i]);

  p = hash_get_mem (sm->steer_by_key, &key);
  if (p)
    {
      st = pool_elt_at_index (sm->steers, p[0]);
      if (lcp_srv6_segs_equal (st->segments, vec_len (st->segments), segments,
			       vec_len (segments)))
	{
	  vec_free (segments);
	  return 0; /* idempotent */
	}

      /* SID list changed: tear down and recreate */
      lcp_srv6_steer_del_internal (st);
      hash_unset_mem (sm->steer_by_key, &st->key);
      pool_put (sm->steers, st);
    }

  lcp_srv6_ensure_table (FIB_PROTOCOL_IP6, 0);
  lcp_srv6_ensure_table (pfx->fp_proto, table_id);

  lcp_srv6_alloc_bsid (&bsid);
  rv = sr_policy_add (&bsid, segments, NULL, 1 /* weight */,
		      SR_POLICY_TYPE_DEFAULT, 0 /* fib_table */, 1 /* encap */,
		      0, NULL);
  if (rv)
    {
      LCP_SRV6_ERR ("sr_policy_add rv=%d bsid=%U", rv, format_ip6_address,
		    &bsid);
      vec_free (segments);
      return rv;
    }

  rv = sr_steering_policy (0, &bsid, ~0, table_id, &prefix, pfx->fp_len, ~0,
			   ttype);
  if (rv)
    {
      LCP_SRV6_ERR ("sr_steering_policy add rv=%d prefix=%U", rv,
		    format_fib_prefix, pfx);
      sr_policy_del (&bsid, ~0);
      vec_free (segments);
      return rv;
    }

  pool_get (sm->steers, st);
  clib_memset (st, 0, sizeof (*st));
  st->key = key;
  st->bsid = bsid;
  st->segments = segments;
  hash_set_mem (sm->steer_by_key, &st->key, st - sm->steers);

  LCP_SRV6_INFO ("headend add %U table %u via bsid %U (%u segs)",
		 format_fib_prefix, pfx, table_id, format_ip6_address, &bsid,
		 encap->n_segs);
  return 0;
}

static int
lcp_srv6_headend_del (u32 table_id, const fib_prefix_t *pfx)
{
  lcp_srv6_main_t *sm = &lcp_srv6_main;
  lcp_srv6_steer_key_t key;
  lcp_srv6_steer_t *st;
  uword *p;

  lcp_srv6_steer_key_init (&key, table_id, pfx);
  p = hash_get_mem (sm->steer_by_key, &key);
  if (!p)
    return 0;

  st = pool_elt_at_index (sm->steers, p[0]);
  lcp_srv6_steer_del_internal (st);
  hash_unset_mem (sm->steer_by_key, &st->key);
  pool_put (sm->steers, st);

  LCP_SRV6_INFO ("headend del %U table %u", format_fib_prefix, pfx, table_id);
  return 0;
}

static int
lcp_srv6_apply (fib_prefix_t *pfx, u32 linux_table_id, lcp_srv6_encap_t *encap,
		int is_del)
{
  u32 table_id = lcp_srv6_table_k2f (linux_table_id);

  if (encap->kind == LCP_SRV6_ENCAP_SEG6_LOCAL)
    {
      u8 behavior;
      u32 dest_table;

      if (pfx->fp_proto != FIB_PROTOCOL_IP6)
	{
	  LCP_SRV6_DBG ("SEG6_LOCAL on non-IPv6 prefix, ignoring");
	  return 1; /* consumed */
	}

      if (encap->action == SEG6_LOCAL_ACTION_END_DT4)
	behavior = SR_BEHAVIOR_DT4;
      else if (encap->action == SEG6_LOCAL_ACTION_END_DT6)
	behavior = SR_BEHAVIOR_DT6;
      else
	{
	  LCP_SRV6_DBG ("SEG6_LOCAL action %u not supported in phase 1",
			encap->action);
	  return 1; /* consumed, skip FIB + skip programming */
	}

      dest_table = lcp_srv6_table_k2f (encap->dest_table);

      if (is_del)
	lcp_srv6_localsid_del (&pfx->fp_addr.ip6);
      else
	lcp_srv6_localsid_add (&pfx->fp_addr.ip6, pfx->fp_len, behavior,
			       dest_table);
      return 1;
    }

  if (encap->kind == LCP_SRV6_ENCAP_SEG6)
    {
      if (encap->mode != SEG6_IPTUN_MODE_ENCAP)
	{
	  LCP_SRV6_DBG ("SEG6 mode %d not supported in phase 1", encap->mode);
	  return 1;
	}

      if (pfx->fp_proto != FIB_PROTOCOL_IP4 &&
	  pfx->fp_proto != FIB_PROTOCOL_IP6)
	return 1;

      if (is_del)
	lcp_srv6_headend_del (table_id, pfx);
      else
	lcp_srv6_headend_add (table_id, pfx, encap);
      return 1;
    }

  return 0;
}

int
lcp_srv6_route_try_add (struct rtnl_route *rr, struct nl_msg *msg,
			int is_replace)
{
  lcp_srv6_encap_t encap;
  fib_prefix_t pfx;
  u32 table_id;

  if (!msg || lcp_srv6_parse_encap_from_nlmsg (msg, &encap) < 0)
    return 0;

  if (rr)
    {
      if (lcp_srv6_route_dst_from_rtnl (rr, &pfx, &table_id) < 0)
	return 0;
    }
  else if (lcp_srv6_route_dst_from_nlmsg (msg, &pfx, &table_id) < 0)
    return 0;

  (void) is_replace;
  return lcp_srv6_apply (&pfx, table_id, &encap, 0 /* is_del */);
}

static int
lcp_srv6_del_by_prefix (fib_prefix_t *pfx, u32 linux_table_id)
{
  lcp_srv6_main_t *sm = &lcp_srv6_main;
  u32 table_id = lcp_srv6_table_k2f (linux_table_id);
  lcp_srv6_steer_key_t key;
  uword *p;

  /* Prefer headend steer match (IPv4 or IPv6 overlay) */
  lcp_srv6_steer_key_init (&key, table_id, pfx);
  p = hash_get_mem (sm->steer_by_key, &key);
  if (p)
    {
      lcp_srv6_headend_del (table_id, pfx);
      return 1;
    }

  /* Localsid match (IPv6 SID prefix) */
  if (pfx->fp_proto == FIB_PROTOCOL_IP6)
    {
      p = hash_get_mem (sm->localsid_by_sid, &pfx->fp_addr.ip6);
      if (p)
	{
	  lcp_srv6_localsid_del (&pfx->fp_addr.ip6);
	  return 1;
	}
    }

  return 0;
}

int
lcp_srv6_route_try_del (struct rtnl_route *rr, struct nl_msg *msg)
{
  lcp_srv6_encap_t encap;
  fib_prefix_t pfx;
  u32 table_id;

  if (rr)
    {
      if (lcp_srv6_route_dst_from_rtnl (rr, &pfx, &table_id) < 0)
	return 0;
    }
  else if (!msg || lcp_srv6_route_dst_from_nlmsg (msg, &pfx, &table_id) < 0)
    return 0;

  /* Prefer encap on the message when present; else look up tracked state.
   * Linux DELROUTE sometimes omits RTA_ENCAP.
   */
  if (msg && lcp_srv6_parse_encap_from_nlmsg (msg, &encap) == 0)
    return lcp_srv6_apply (&pfx, table_id, &encap, 1 /* is_del */);

  return lcp_srv6_del_by_prefix (&pfx, table_id);
}

int
lcp_srv6_route_handle_parse_error (struct nl_msg *msg)
{
  struct nlmsghdr *nlh;
  lcp_srv6_encap_t encap;
  fib_prefix_t pfx;
  u32 table_id;
  int is_del;

  if (!msg)
    return 0;

  nlh = nlmsg_hdr (msg);
  if (nlh->nlmsg_type != RTM_NEWROUTE && nlh->nlmsg_type != RTM_DELROUTE)
    return 0;

  if (lcp_srv6_parse_encap_from_nlmsg (msg, &encap) < 0)
    return 0;

  if (lcp_srv6_route_dst_from_nlmsg (msg, &pfx, &table_id) < 0)
    return 0;

  is_del = (nlh->nlmsg_type == RTM_DELROUTE);
  LCP_SRV6_DBG ("raw fallback for SRv6 route (libnl encap unsupported)");
  return lcp_srv6_apply (&pfx, table_id, &encap, is_del);
}

/* ---- parser selftest (synthetic nested attrs) ---- */

static int
lcp_srv6_selftest_seg6local (void)
{
  struct nl_msg *msg;
  struct nlattr *encap;
  lcp_srv6_encap_t out;
  u32 action = SEG6_LOCAL_ACTION_END_DT4;
  u32 vrftable = 100;
  struct rtmsg rtm = { .rtm_family = AF_INET6,
		       .rtm_dst_len = 128,
		       .rtm_table = RT_TABLE_MAIN,
		       .rtm_protocol = RTPROT_BGP,
		       .rtm_scope = RT_SCOPE_UNIVERSE,
		       .rtm_type = RTN_UNICAST };
  ip6_address_t sid = {};
  int err;

  sid.as_u8[0] = 0xfc;
  sid.as_u8[15] = 0x01;

  msg = nlmsg_alloc_simple (RTM_NEWROUTE, 0);
  if (!msg)
    return -1;

  if (nlmsg_append (msg, &rtm, sizeof (rtm), NLMSG_ALIGNTO) < 0)
    goto fail;
  if (nla_put (msg, RTA_DST, sizeof (sid), &sid) < 0)
    goto fail;
  if (nla_put_u16 (msg, RTA_ENCAP_TYPE, LWTUNNEL_ENCAP_SEG6_LOCAL) < 0)
    goto fail;

  encap = nla_nest_start (msg, RTA_ENCAP);
  if (!encap)
    goto fail;
  if (nla_put_u32 (msg, SEG6_LOCAL_ACTION, action) < 0)
    goto fail;
  if (nla_put_u32 (msg, SEG6_LOCAL_VRFTABLE, vrftable) < 0)
    goto fail;
  nla_nest_end (msg, encap);

  err = lcp_srv6_parse_encap_from_nlmsg (msg, &out);
  nlmsg_free (msg);
  if (err < 0)
    return -1;
  if (out.kind != LCP_SRV6_ENCAP_SEG6_LOCAL ||
      out.action != SEG6_LOCAL_ACTION_END_DT4 || out.dest_table != 100)
    return -2;
  return 0;

fail:
  nlmsg_free (msg);
  return -1;
}

static int
lcp_srv6_selftest_seg6 (void)
{
  struct nl_msg *msg;
  struct nlattr *encap;
  lcp_srv6_encap_t out;
  struct rtmsg rtm = { .rtm_family = AF_INET,
		       .rtm_dst_len = 24,
		       .rtm_table = RT_TABLE_MAIN,
		       .rtm_protocol = RTPROT_BGP,
		       .rtm_scope = RT_SCOPE_UNIVERSE,
		       .rtm_type = RTN_UNICAST };
  ip4_address_t dst = { .as_u8 = { 10, 0, 0, 0 } };
  u8 buf[sizeof (struct seg6_iptunnel_encap) + sizeof (struct ipv6_sr_hdr) +
	 sizeof (ip6_address_t)];
  struct seg6_iptunnel_encap *ipt = (struct seg6_iptunnel_encap *) buf;
  struct ipv6_sr_hdr *srh;
  ip6_address_t remote = {};
  int err;

  remote.as_u8[0] = 0xfc;
  remote.as_u8[15] = 0x42;

  clib_memset (buf, 0, sizeof (buf));
  ipt->mode = SEG6_IPTUN_MODE_ENCAP;
  srh = ipt->srh;
  srh->hdrlen = ((sizeof (*srh) + sizeof (ip6_address_t)) >> 3) - 1;
  srh->type = 4;
  srh->segments_left = 0;
  srh->first_segment = 0;
  clib_memcpy (&srh->segments[0], &remote, sizeof (remote));

  msg = nlmsg_alloc_simple (RTM_NEWROUTE, 0);
  if (!msg)
    return -1;

  if (nlmsg_append (msg, &rtm, sizeof (rtm), NLMSG_ALIGNTO) < 0)
    goto fail;
  if (nla_put (msg, RTA_DST, sizeof (dst), &dst) < 0)
    goto fail;
  if (nla_put_u16 (msg, RTA_ENCAP_TYPE, LWTUNNEL_ENCAP_SEG6) < 0)
    goto fail;

  encap = nla_nest_start (msg, RTA_ENCAP);
  if (!encap)
    goto fail;
  if (nla_put (msg, SEG6_IPTUNNEL_SRH, sizeof (buf), buf) < 0)
    goto fail;
  nla_nest_end (msg, encap);

  err = lcp_srv6_parse_encap_from_nlmsg (msg, &out);
  nlmsg_free (msg);
  if (err < 0)
    return -1;
  if (out.kind != LCP_SRV6_ENCAP_SEG6 || out.mode != SEG6_IPTUN_MODE_ENCAP ||
      out.n_segs != 1 || !ip6_address_is_equal (&out.segs[0], &remote))
    return -2;
  return 0;

fail:
  nlmsg_free (msg);
  return -1;
}

int
lcp_srv6_parser_selftest (void)
{
  int rv;

  rv = lcp_srv6_selftest_seg6local ();
  if (rv)
    return rv;
  rv = lcp_srv6_selftest_seg6 ();
  if (rv)
    return rv;
  return 0;
}

static clib_error_t *
lcp_srv6_test_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "selftest"))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  rv = lcp_srv6_parser_selftest ();
  if (rv)
    return clib_error_return (0, "SRv6 parser selftest failed (%d)", rv);

  vlib_cli_output (vm, "SRv6 parser selftest OK");
  return 0;
}

VLIB_CLI_COMMAND (lcp_srv6_test_command, static) = {
  .path = "test lcp srv6",
  .short_help = "test lcp srv6 [selftest]",
  .function = lcp_srv6_test_command_fn,
};

static clib_error_t *
lcp_srv6_sync_init (vlib_main_t *vm)
{
  lcp_srv6_main_t *sm = &lcp_srv6_main;

  lcp_srv6_logger = vlib_log_register_class ("linux-cp", "srv6");
  sm->localsid_by_sid =
    hash_create_mem (0, sizeof (ip6_address_t), sizeof (uword));
  sm->steer_by_key =
    hash_create_mem (0, sizeof (lcp_srv6_steer_key_t), sizeof (uword));
  sm->bsid_counter = 1;

  return 0;
}

VLIB_INIT_FUNCTION (lcp_srv6_sync_init) = {
  .runs_after = VLIB_INITS ("sr_localsids_init", "sr_policy_rewrite_init"),
};
