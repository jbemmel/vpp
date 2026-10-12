/* SPDX-License-Identifier: Apache-2.0 */
#include <acl/mitigation.h>
#include <acl/mitigation_packet.h>
#include <acl/public_inlines.h>
#include <vnet/feature/feature.h>

typedef struct
{
  u32 acl_index, rule_index, next_index;
  u8 action;
} mitigation_trace_t;

static u8 *
format_mitigation_trace (u8 *s, va_list *args)
{
  va_arg (*args, vlib_main_t *);
  va_arg (*args, vlib_node_t *);
  mitigation_trace_t *t = va_arg (*args, mitigation_trace_t *);
  return format (s, "ACL mitigation acl %u rule %u action %u next %u", t->acl_index, t->rule_index,
		 t->action, t->next_index);
}

enum
{
  MITIGATION_PROCESSED,
  MITIGATION_MATCHED,
  MITIGATION_DROPPED,
  MITIGATION_MALFORMED,
  MITIGATION_SAMPLED,
  MITIGATION_SAMPLE_FAILED,
  MITIGATION_N_ERRORS
};
static char *mitigation_errors[] = { "packets processed", "packets matched",
				     "packets dropped",	  "malformed IP packets dropped",
				     "packets sampled",	  "sample exports failed" };

always_inline uword
mitigation_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, int is_l2)
{
  acl_mitigation_main_t *mm = &acl_mitigation_main;
  acl_mitigation_worker_t *worker = &mm->workers[vm->thread_index];
  u32 *from = vlib_frame_vector_args (frame);
  u16 nexts[VLIB_FRAME_SIZE];
  vlib_buffer_t *buffers[VLIB_FRAME_SIZE];
  u32 counts[MITIGATION_N_ERRORS] = { 0 };
  u64 bytes = 0, dropped_bytes = 0;
  vlib_get_buffers (vm, from, buffers, frame->n_vectors);
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *b = buffers[i];
      if (i + 2 < frame->n_vectors)
	{
	  vlib_prefetch_buffer_header (buffers[i + 2], LOAD);
	  CLIB_PREFETCH (vlib_buffer_get_current (buffers[i + 2]), CLIB_CACHE_LINE_BYTES, LOAD);
	}
      u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
      u16 next;
      vnet_feature_next_u16 (&next, b);
      fa_5tuple_t tuple;
      acl_mitigation_packet_t metadata;
      u32 acl_index = ~0u, ace_index = ~0u, position, trace_bitmap = 0;
      u8 action = 1;
      u32 offset = is_l2 ? vnet_buffer (b)->l2.l2_len : 0;
      counts[MITIGATION_PROCESSED]++;
      if (!acl_mitigation_fill_packet (vm, b, offset, &tuple, &metadata))
	{
	  next = 0;
	  counts[MITIGATION_MALFORMED]++;
	  b->error = node->errors[MITIGATION_MALFORMED];
	}
      else
	{
	  bytes += metadata.packet_length;
	  u32 lc = sw_if_index < vec_len (mm->contexts) ? mm->contexts[sw_if_index] : ~0u;
	  if (lc != ~0u && acl_plugin_match_5tuple_inline_extended (
			     &acl_main, lc, (fa_5tuple_opaque_t *) &tuple, tuple.pkt.is_ip6,
			     &action, &position, &acl_index, &ace_index, &trace_bitmap, &metadata))
	    {
	      counts[MITIGATION_MATCHED]++;
	      const acl_rule_t *rule = &acl_main.acls[acl_index].rules[ace_index];
	      if (mm->per_rule_counters)
		vlib_increment_combined_counter (&acl_main.combined_acl_counters[acl_index],
						 vm->thread_index, ace_index, 1,
						 metadata.packet_length);
	      if (mm->psample_enabled && rule->sample_ratio)
		{
		  acl_mitigation_sample_t *sample =
		    &worker->samples[acl_index][rule->logical_rule_index];
		  if (++sample->credit == rule->sample_ratio)
		    {
		      sample->credit = 0;
		      if (acl_mitigation_psample_send (worker, b, rule, sw_if_index,
						       vlib_buffer_length_in_chain (vm, b)))
			{
			  sample->failed++;
			  counts[MITIGATION_SAMPLE_FAILED]++;
			}
		      else
			{
			  sample->sampled++;
			  counts[MITIGATION_SAMPLED]++;
			}
		    }
		}
	      if (!action)
		{
		  next = 0;
		  counts[MITIGATION_DROPPED]++;
		  dropped_bytes += metadata.packet_length;
		  b->error = node->errors[MITIGATION_DROPPED];
		}
	      ace_index = rule->logical_rule_index;
	    }
	}
      nexts[i] = next;
      if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	{
	  mitigation_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
	  *t = (mitigation_trace_t) { acl_index, ace_index, next, action };
	}
    }
  for (u32 i = 0; i < MITIGATION_N_ERRORS; i++)
    vlib_node_increment_counter (vm, node->node_index, i, counts[i]);
  vlib_increment_combined_counter (&mm->aggregate, vm->thread_index, 0,
				   counts[MITIGATION_PROCESSED], bytes);
  vlib_increment_combined_counter (&mm->aggregate, vm->thread_index, 1,
				   counts[MITIGATION_DROPPED] + counts[MITIGATION_MALFORMED],
				   dropped_bytes);
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (acl_mitigation_ip_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return mitigation_node_inline (vm, node, frame, 0);
}
VLIB_NODE_FN (acl_mitigation_l2_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return mitigation_node_inline (vm, node, frame, 1);
}

VLIB_REGISTER_NODE (acl_mitigation_ip_node) = {
  .name = "acl-mitigation-ip",
  .vector_size = sizeof (u32),
  .format_trace = format_mitigation_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = MITIGATION_N_ERRORS,
  .error_strings = mitigation_errors,
  .n_next_nodes = 1,
  .next_nodes = { [0] = "error-drop" },
};
VLIB_REGISTER_NODE (acl_mitigation_l2_node) = {
  .name = "acl-mitigation-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_mitigation_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = MITIGATION_N_ERRORS,
  .error_strings = mitigation_errors,
  .n_next_nodes = 1,
  .next_nodes = { [0] = "error-drop" },
};
VNET_FEATURE_INIT (acl_mitigation_ip4, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "acl-mitigation-ip",
  .runs_before = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
};
VNET_FEATURE_INIT (acl_mitigation_ip6, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "acl-mitigation-ip",
  .runs_before = VNET_FEATURES ("acl-plugin-in-ip6-fa"),
};
VNET_FEATURE_INIT (acl_mitigation_l2_ip4, static) = {
  .arc_name = "l2-input-ip4",
  .node_name = "acl-mitigation-l2",
  .runs_before = VNET_FEATURES ("acl-plugin-in-ip4-l2"),
};
VNET_FEATURE_INIT (acl_mitigation_l2_ip6, static) = {
  .arc_name = "l2-input-ip6",
  .node_name = "acl-mitigation-l2",
  .runs_before = VNET_FEATURES ("acl-plugin-in-ip6-l2"),
};
