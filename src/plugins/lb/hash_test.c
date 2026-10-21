/* SPDX-License-Identifier: Apache-2.0 */
#include <lb/lb.h>
#include <lb/maglev.h>

#define CHECK(x)                                                                                   \
  do                                                                                               \
    {                                                                                              \
      if (!(x))                                                                                    \
	{                                                                                          \
	  error = clib_error_return (0, "failed: %s", #x);                                         \
	  goto done;                                                                               \
	}                                                                                          \
    }                                                                                              \
  while (0)

static clib_error_t *
lb_hash_test (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  clib_error_t *error = 0;
  lb_hash_t *h = lb_hash_alloc (1, 40);
  u32 available, found;
  u32 original[1024], table[1024], counts[4] = { 0 };
  lb_maglev_backend_t b[3] = {
    { .lo = 1, .as_index = 1, .weight = 100 },
    { .lo = 2, .as_index = 2, .weight = 50 },
    { .lo = 3, .as_index = 3, .weight = 0 },
  };
  CHECK (lb_hash_size (h) == 4);
  CHECK (sizeof (lb_hash_bucket_t) == CLIB_CACHE_LINE_BYTES);
  /* One bucket forces distinct 32-bit fingerprints into all four ways. */
  for (u32 i = 0; i < 4; i++)
    lb_hash_put (h, i + 7, i + 1, 10, i, 100);
  for (u32 i = 0; i < 4; i++)
    {
      lb_hash_get (h, i + 7, 10, 110, &available, &found);
      CHECK (found == i + 1 && available == ~0);
    }
  lb_hash_get (h, 7, 11, 110, &available, &found);
  CHECK (found == 0 && available == ~0);
  lb_hash_get (h, 7, 10, 150, &available, &found);
  CHECK (found == 0 && available == 0 && lb_hash_elts (h, 150) == 0);
  lb_hash_put (h, 7, 1, 10, 0, ~0U - 20);
  lb_hash_get (h, 7, 10, 5, &available, &found);
  CHECK (found == 1);
  lb_hash_get (h, 7, 10, 45, &available, &found);
  CHECK (found == 0);
  CHECK (lb_hash_words (1, 2, 0, 0, 0) != lb_hash_words (2, 1, 0, 0, 0));
  CHECK (lb_hash_words (0, 1, 0, 0, 1) != lb_hash_words (0, 0, 0, 0, 0));
  lb_maglev_build (b, 3, original, 1024);
  for (u32 i = 0; i < 1024; i++)
    {
      CHECK (original[i] == 1 || original[i] == 2);
      counts[original[i]]++;
    }
  CHECK (counts[1] == 683 && counts[2] == 341);
  /* Rebuilding must ignore transient builder state and absolute weight scale. */
  b[0].weight = 2;
  b[1].weight = 1;
  lb_maglev_build (b, 3, table, 1024);
  CHECK (!memcmp (table, original, sizeof (table)));
  b[1].weight = 0;
  lb_maglev_build (b, 3, table, 1024);
  u32 moved = 0, survivors = 0;
  for (u32 i = 0; i < 1024; i++)
    {
      CHECK (table[i] == 1);
      moved += table[i] != original[i];
      survivors += original[i] == 1 && table[i] != 1;
    }
  CHECK (moved == 341 && survivors == 0);
  vlib_cli_output (vm, "removal: moved %u/1024, surviving-backend movement %u", moved, survivors);
  b[0].weight = 0;
  lb_maglev_build (b, 3, table, 1024);
  for (u32 i = 0; i < 1024; i++)
    CHECK (table[i] == 0);
  b[0].weight = 1;
  b[1].weight = 1;
  lb_maglev_build (b, 3, table, 1);
  CHECK (table[0] == 1);
  /* More live backends than buckets: deterministic zero quotas. */
  b[2].weight = 1;
  lb_maglev_build (b, 3, table, 2);
  CHECK (table[0] && table[1] && table[0] != table[1]);
  lb_maglev_backend_t many[9];
  for (u32 i = 0; i < 8; i++)
    many[i] = (lb_maglev_backend_t) {
      .lo = 8 - i,
      .as_index = 8 - i,
      .weight = 100,
    };
  lb_maglev_build (many, 8, original, 1024);
  /* Builder sorted input by identity; reverse order and change pool indexes. */
  for (u32 i = 0; i < 4; i++)
    {
      lb_maglev_backend_t temp = many[i];
      many[i] = many[7 - i];
      many[7 - i] = temp;
    }
  for (u32 i = 0; i < 8; i++)
    many[i].as_index += 10;
  lb_maglev_build (many, 8, table, 1024);
  for (u32 i = 0; i < 1024; i++)
    CHECK (table[i] == original[i] + 10);
  for (u32 i = 0; i < 8; i++)
    many[i].as_index -= 10;
  many[7].weight = 0;
  lb_maglev_build (many, 8, table, 1024);
  moved = survivors = 0;
  for (u32 i = 0; i < 1024; i++)
    {
      CHECK (table[i] > 0 && table[i] < 8);
      moved += table[i] != original[i];
      survivors += original[i] != 8 && original[i] != table[i];
    }
  vlib_cli_output (vm, "8-to-7 removal: moved %u/1024, excess movement %u", moved, survivors);
  many[7].weight = 100;
  many[0].weight = 99;
  lb_maglev_build (many, 8, table, 1024);
  moved = 0;
  for (u32 i = 0; i < 1024; i++)
    moved += table[i] != original[i];
  vlib_cli_output (vm, "100-to-99 weight: moved %u/1024", moved);
  many[0].weight = 100;
  many[8] = (lb_maglev_backend_t) {
    .lo = 9,
    .as_index = 9,
    .weight = 100,
  };
  lb_maglev_build (many, 9, table, 1024);
  moved = survivors = 0;
  for (u32 i = 0; i < 1024; i++)
    {
      CHECK (table[i] > 0 && table[i] <= 9);
      moved += table[i] != original[i];
      survivors += table[i] != 9 && table[i] != original[i];
    }
  vlib_cli_output (vm, "8-to-9 addition: moved %u/1024, excess movement %u", moved, survivors);
  vlib_cli_output (vm, "LB hashing tests passed");
done:
  lb_hash_free (h);
  return error;
}

VLIB_CLI_COMMAND (lb_hash_test_command, static) = {
  .path = "test lb hashing",
  .short_help = "test lb hashing",
  .function = lb_hash_test,
};
