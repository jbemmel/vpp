/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#ifndef included_acl_exports_h
#define included_acl_exports_h

/*
 * This file contains the declarations for external consumption,
 * along with the necessary dependent includes.
 */

#define ACL_PLUGIN_EXTERNAL_EXPORTS

#include <vlib/unix/plugin.h>

#include "acl.h"
#include "fa_node.h"
#include "public_inlines.h"

/* Optional non-inline entry point, discoverable with vlib_get_plugin_symbol.
 * Existing exports/vtable and 48-byte tuples retain their ABI.
 */
int acl_plugin_match_5tuple_extended (u32 lc_index, fa_5tuple_opaque_t *tuple, int is_ip6,
				      u8 *action, u32 *acl_position, u32 *acl_index,
				      u32 *rule_index, u32 *trace_bitmap,
				      const acl_mitigation_packet_t *metadata);

#endif /* included_acl_exports_h */
