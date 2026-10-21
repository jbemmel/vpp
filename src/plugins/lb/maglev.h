/* SPDX-License-Identifier: Apache-2.0 */
#ifndef included_lb_maglev_h
#define included_lb_maglev_h

#include <lb/lbhash.h>

/* Identity words are decoded from network order; index zero means no backend. */
typedef struct
{
  u64 hi, lo;
  u32 as_index, weight;
  u32 quota, assigned, last, skip;
  u64 remainder;
  i64 credit;
} lb_maglev_backend_t;

static inline int
lb_maglev_compare (const void *a, const void *b)
{
  const lb_maglev_backend_t *x = a, *y = b;
  if (x->hi != y->hi)
    return x->hi < y->hi ? -1 : 1;
  return x->lo < y->lo ? -1 : x->lo != y->lo;
}

/* Exact largest-remainder quotas followed by smooth weighted placement.
 * One permutation per physical backend; no weight-expanded replicas. */
static inline void
lb_maglev_build (lb_maglev_backend_t *backends, u32 n, u32 *table, u32 size)
{
  if (n > 1)
    qsort (backends, n, sizeof (*backends), lb_maglev_compare);
  u64 total = 0;
  u32 allocated = 0;
  for (u32 i = 0; i < n; i++)
    total += backends[i].weight;
  clib_memset (table, 0, size * sizeof (*table));
  if (!total)
    return;
  for (u32 i = 0; i < n; i++)
    {
      lb_maglev_backend_t *b = &backends[i];
      u64 share = (u64) size * b->weight;
      b->quota = share / total;
      b->remainder = share % total;
      b->assigned = 0;
      b->credit = 0;
      allocated += b->quota;
      b->last = lb_hash_words (b->hi, b->lo, 0, 0, 1) & (size - 1);
      b->skip = (lb_hash_words (b->hi, b->lo, 0, 0, 2) | 1) & (size - 1);
    }
  while (allocated++ < size)
    {
      u32 best = 0;
      for (u32 i = 1; i < n; i++)
	if (backends[i].remainder > backends[best].remainder)
	  best = i;
      backends[best].quota++;
      backends[best].remainder = 0;
    }
  for (u32 slot = 0; slot < size; slot++)
    {
      u32 best = ~0;
      for (u32 i = 0; i < n; i++)
	{
	  lb_maglev_backend_t *b = &backends[i];
	  if (b->assigned == b->quota)
	    continue;
	  b->credit += b->quota;
	  if (best == ~0 || b->credit > backends[best].credit)
	    best = i;
	}
      lb_maglev_backend_t *b = &backends[best];
      b->credit -= size;
      while (table[b->last])
	b->last = (b->last + b->skip) & (size - 1);
      table[b->last] = b->as_index;
      b->last = (b->last + b->skip) & (size - 1);
      b->assigned++;
    }
}
#endif
