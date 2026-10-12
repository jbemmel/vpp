/* SPDX-License-Identifier: Apache-2.0 */
#include <acl/mitigation.h>
#include <vnet/api_errno.h>
#ifdef __linux__
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/psample.h>

#define MITIGATION_SAMPLE_BYTES 256
/* Fixed stack message; no allocation or blocking syscall on packet workers. */
typedef struct
{
  struct nlmsghdr header;
  struct genlmsghdr generic;
  u8 attributes[512];
} mitigation_nl_message_t;

static void
mitigation_nl_attr (mitigation_nl_message_t *msg, u16 type, const void *data, u16 bytes)
{
  struct nlattr *a = (void *) ((u8 *) msg + msg->header.nlmsg_len);
  a->nla_type = type;
  a->nla_len = NLA_HDRLEN + bytes;
  clib_memcpy_fast ((u8 *) a + NLA_HDRLEN, data, bytes);
  msg->header.nlmsg_len += NLA_ALIGN (a->nla_len);
}

static int
mitigation_attr_valid (struct nlattr *a, u32 remaining)
{
  return remaining >= NLA_HDRLEN && a->nla_len >= NLA_HDRLEN && a->nla_len <= remaining &&
	 NLA_ALIGN (a->nla_len) <= remaining;
}

static int
mitigation_resolve_family (u16 *family, u32 *group)
{
  int fd = socket (AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_GENERIC);
  if (fd < 0)
    return -1;
  struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
  mitigation_nl_message_t request = { .header = { .nlmsg_len = NLMSG_LENGTH (GENL_HDRLEN),
						  .nlmsg_type = GENL_ID_CTRL,
						  .nlmsg_flags = NLM_F_REQUEST,
						  .nlmsg_seq = 1 },
				      .generic = { .cmd = CTRL_CMD_GETFAMILY, .version = 1 } };
  const char name[] = PSAMPLE_GENL_NAME;
  mitigation_nl_attr (&request, CTRL_ATTR_FAMILY_NAME, name, sizeof (name));
  int rv = -1;
  if (sendto (fd, &request, request.header.nlmsg_len, MSG_DONTWAIT, (void *) &kernel,
	      sizeof (kernel)) < 0)
    goto done;
  struct pollfd ready = { .fd = fd, .events = POLLIN };
  if (poll (&ready, 1, 1000) <= 0)
    goto done;
  u8 reply[8192];
  int received = recv (fd, reply, sizeof (reply), MSG_DONTWAIT);
  if (received < (int) NLMSG_LENGTH (GENL_HDRLEN))
    goto done;
  struct nlmsghdr *h = (void *) reply;
  if (h->nlmsg_len < NLMSG_LENGTH (GENL_HDRLEN) || h->nlmsg_len > received ||
      h->nlmsg_type == NLMSG_ERROR || h->nlmsg_seq != 1)
    goto done;
  u32 remaining = h->nlmsg_len - NLMSG_LENGTH (GENL_HDRLEN);
  struct nlattr *a = (void *) (reply + NLMSG_LENGTH (GENL_HDRLEN));
  while (mitigation_attr_valid (a, remaining))
    {
      u16 type = a->nla_type & NLA_TYPE_MASK;
      u8 *payload = (u8 *) a + NLA_HDRLEN;
      u32 payload_len = a->nla_len - NLA_HDRLEN;
      if (type == CTRL_ATTR_FAMILY_ID && payload_len == sizeof (*family))
	clib_memcpy_fast (family, payload, sizeof (*family));
      if (type == CTRL_ATTR_MCAST_GROUPS)
	{
	  struct nlattr *nested = (void *) payload;
	  while (mitigation_attr_valid (nested, payload_len))
	    {
	      u32 left = nested->nla_len - NLA_HDRLEN, id = 0;
	      int found = 0;
	      struct nlattr *field = (void *) ((u8 *) nested + NLA_HDRLEN);
	      while (mitigation_attr_valid (field, left))
		{
		  u16 ft = field->nla_type & NLA_TYPE_MASK;
		  u8 *value = (u8 *) field + NLA_HDRLEN;
		  u32 size = field->nla_len - NLA_HDRLEN;
		  if (ft == CTRL_ATTR_MCAST_GRP_ID && size == sizeof (id))
		    clib_memcpy_fast (&id, value, sizeof (id));
		  if (ft == CTRL_ATTR_MCAST_GRP_NAME &&
		      size == sizeof (PSAMPLE_NL_MCGRP_SAMPLE_NAME) &&
		      !memcmp (value, PSAMPLE_NL_MCGRP_SAMPLE_NAME, size))
		    found = 1;
		  u32 step = NLA_ALIGN (field->nla_len);
		  left -= step;
		  field = (void *) ((u8 *) field + step);
		}
	      if (found)
		*group = id;
	      u32 step = NLA_ALIGN (nested->nla_len);
	      payload_len -= step;
	      nested = (void *) ((u8 *) nested + step);
	    }
	}
      u32 step = NLA_ALIGN (a->nla_len);
      remaining -= step;
      a = (void *) ((u8 *) a + step);
    }
  if (*family && *group && *group <= 32)
    rv = 0;
done:
  close (fd);
  return rv;
}

int
acl_mitigation_psample_enable (u8 enable)
{
  acl_mitigation_main_t *mm = &acl_mitigation_main;
  if (enable == mm->psample_enabled)
    return 0;
  if (enable)
    {
      u16 family = 0;
      u32 group = 0;
      if (mitigation_resolve_family (&family, &group))
	return VNET_API_ERROR_UNSUPPORTED;
      /* Allocate all sockets before publication; failures leave config intact. */
      int *fds = 0;
      vec_validate_init_empty (fds, vec_len (mm->workers) - 1, -1);
      for (u32 i = 0; i < vec_len (fds); i++)
	{
	  fds[i] = socket (AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_GENERIC);
	  if (fds[i] < 0)
	    {
	      for (u32 j = 0; j < i; j++)
		close (fds[j]);
	      vec_free (fds);
	      return VNET_API_ERROR_SYSCALL_ERROR_1;
	    }
	}
      vlib_worker_thread_barrier_sync (acl_main.vlib_main);
      mm->psample_family = family;
      mm->psample_group = group;
      for (u32 i = 0; i < vec_len (fds); i++)
	mm->workers[i].psample_fd = fds[i];
      mm->psample_enabled = 1;
      vlib_worker_thread_barrier_release (acl_main.vlib_main);
      vec_free (fds);
    }
  else
    {
      vlib_worker_thread_barrier_sync (acl_main.vlib_main);
      mm->psample_enabled = 0;
      acl_mitigation_worker_t *w;
      vec_foreach (w, mm->workers)
	{
	  close (w->psample_fd);
	  w->psample_fd = -1;
	}
      vlib_worker_thread_barrier_release (acl_main.vlib_main);
    }
  return 0;
}

int
acl_mitigation_psample_send (acl_mitigation_worker_t *worker, vlib_buffer_t *b,
			     const acl_rule_t *rule, u32 sw_if_index, u32 bytes)
{
  acl_mitigation_main_t *mm = &acl_mitigation_main;
  mitigation_nl_message_t msg = {
    .header = { .nlmsg_len = NLMSG_LENGTH (GENL_HDRLEN), .nlmsg_type = mm->psample_family },
    .generic = { .cmd = PSAMPLE_CMD_SAMPLE, .version = PSAMPLE_GENL_VERSION }
  };
  u32 sequence = worker->sequence++;
  mitigation_nl_attr (&msg, PSAMPLE_ATTR_ORIGSIZE, &bytes, sizeof (bytes));
  mitigation_nl_attr (&msg, PSAMPLE_ATTR_SAMPLE_GROUP, &rule->sample_group, sizeof (u32));
  mitigation_nl_attr (&msg, PSAMPLE_ATTR_SAMPLE_RATE, &rule->sample_ratio, sizeof (u32));
  mitigation_nl_attr (&msg, PSAMPLE_ATTR_GROUP_SEQ, &sequence, sizeof (sequence));
  /* VPP indices are not Linux ifindices; carry the index in a user cookie. */
  mitigation_nl_attr (&msg, PSAMPLE_ATTR_USER_COOKIE, &sw_if_index, sizeof (sw_if_index));
  u8 packet[MITIGATION_SAMPLE_BYTES];
  u32 copied = 0, capture = clib_min (bytes, MITIGATION_SAMPLE_BYTES);
  vlib_buffer_t *part = b;
  while (copied < capture)
    {
      u32 n = clib_min (capture - copied, part->current_length);
      clib_memcpy_fast (packet + copied, vlib_buffer_get_current (part), n);
      copied += n;
      if (!(part->flags & VLIB_BUFFER_NEXT_PRESENT))
	break;
      part = vlib_get_buffer (vlib_get_main (), part->next_buffer);
    }
  mitigation_nl_attr (&msg, PSAMPLE_ATTR_DATA, packet, copied);
  struct sockaddr_nl dst = { .nl_family = AF_NETLINK, .nl_groups = 1u << (mm->psample_group - 1) };
  return sendto (worker->psample_fd, &msg, msg.header.nlmsg_len, MSG_DONTWAIT, (void *) &dst,
		 sizeof (dst)) == msg.header.nlmsg_len ?
	   0 :
	   -1;
}
#else
int
acl_mitigation_psample_enable (u8 enable)
{
  return enable ? VNET_API_ERROR_UNSUPPORTED : 0;
}
int
acl_mitigation_psample_send (acl_mitigation_worker_t *w, vlib_buffer_t *b, const acl_rule_t *r,
			     u32 sw, u32 bytes)
{
  return -1;
}
#endif
