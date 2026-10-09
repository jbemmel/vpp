/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef __LCP_SRV6_SYNC_H__
#define __LCP_SRV6_SYNC_H__

#include <vlib/vlib.h>
#include <netlink/msg.h>
#include <netlink/route/route.h>

/**
 * Try to consume a route as SRv6 (SEG6_LOCAL / SEG6).
 * @return 1 if the route was handled as SRv6 (caller must skip FIB sync),
 *         0 if the route is not SRv6 and normal sync should proceed.
 */
int lcp_srv6_route_try_add (struct rtnl_route *rr, struct nl_msg *msg,
			    int is_replace);
int lcp_srv6_route_try_del (struct rtnl_route *rr, struct nl_msg *msg);

/**
 * Fallback when libnl rejects the message (NLE_MSGTYPE_NOSUPPORT).
 * Parses the raw RTM_*ROUTE message and programs SRv6 if applicable.
 * @return 1 if handled as SRv6, 0 otherwise.
 */
int lcp_srv6_route_handle_parse_error (struct nl_msg *msg);

/** Parser self-check used by unit tests / CLI. Returns 0 on success. */
int lcp_srv6_parser_selftest (void);

#endif /* __LCP_SRV6_SYNC_H__ */
