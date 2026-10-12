/* SPDX-License-Identifier: Apache-2.0 */
#ifndef included_acl_mitigation_h
#define included_acl_mitigation_h
#include <acl/acl.h>
#include <acl/exports.h>

/* Per-worker credits are allocated on the main thread, never in the datapath. */
typedef struct
{
  u32 credit;
  u64 sampled, failed;
} acl_mitigation_sample_t;

typedef struct
{
  acl_mitigation_sample_t **samples;
  int psample_fd;
  u32 sequence;
} acl_mitigation_worker_t;

typedef struct
{
  u32 ace[2];
} acl_mitigation_mapping_t;

typedef struct
{
  f64 time, pps, l3_bps, l1_bps;
  vlib_counter_t previous;
} acl_mitigation_rate_t;

typedef struct
{
  u16 msg_id_base;
  acl_plugin_methods_t acl;
  u32 user_id;
  u32 *contexts;
  u32 *bindings;
  /* Original logical rules in native byte order, indexed by native ACL. */
  acl_rule_t **rules;
  acl_mitigation_mapping_t **mapping;
  acl_mitigation_rate_t **rates;
  acl_mitigation_rate_t aggregate_rates[2];
  acl_mitigation_worker_t *workers;
  vlib_combined_counter_main_t aggregate;
  u8 per_rule_counters;
  u8 psample_enabled;
  u16 psample_family;
  u32 psample_group;
} acl_mitigation_main_t;
extern acl_mitigation_main_t acl_mitigation_main;
void acl_mitigation_acl_deleted (u32 acl_index);
int acl_mitigation_bind (u32 sw_if_index, u32 acl_index);
int acl_mitigation_psample_enable (u8 enable);
int acl_mitigation_psample_send (acl_mitigation_worker_t *worker, vlib_buffer_t *b,
				 const acl_rule_t *rule, u32 sw_if_index, u32 bytes);
#endif
