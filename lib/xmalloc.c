/*
 *	BIRD Library -- malloc() With Checking
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdlib.h>

#include "nest/bird.h"
#include "lib/locking.h"
#include "lib/resource.h"

#ifndef HAVE_LIBDMALLOC

DEFINE_DOMAIN(resource);
static DOMAIN(resource) malloc_domain;
static int malloc_domain_initialized = 0;

/**
 * xmalloc - malloc with checking
 * @size: block size
 *
 * This function is equivalent to malloc() except that in case of
 * failure it calls die() to quit the program instead of returning
 * a %NULL pointer.
 *
 * Also it locks a mutex to prevent arena bloating.
 *
 * Wherever possible, please use the memory resources instead.
 */
void *
xmalloc(uint size)
{
  switch (malloc_domain_initialized)
  {
    case 0:
      malloc_domain_initialized++;
      malloc_domain = DOMAIN_NEW(resource, "Malloc workaround");
      malloc_domain_initialized++;
      break;
    case 1:
      {
	void *p = malloc(size);
	if (p) return p;
	die("Unable to allocate anything");
      }
    case 2:
      break;
    default:
      bug("Impossible value of malloc_domain_initialized");
  }

  LOCK_DOMAIN(resource, malloc_domain);
  void *p = malloc(size);
  UNLOCK_DOMAIN(resource, malloc_domain);
  if (p)
    return p;
  die("Unable to allocate %d bytes of memory", size);
}

/**
 * xrealloc - realloc with locking and checking
 * @ptr: original memory block
 * @size: block size
 *
 * This function is equivalent to realloc() except that in case of
 * failure it calls die() to quit the program instead of returning
 * a %NULL pointer.
 *
 * Also it locks a mutex to prevent arena bloating.
 *
 * Wherever possible, please use the memory resources instead.
 */
void *
xrealloc(void *ptr, uint size)
{
  LOCK_DOMAIN(resource, malloc_domain);
  void *p = realloc(ptr, size);
  UNLOCK_DOMAIN(resource, malloc_domain);
  if (p)
    return p;
  die("Unable to allocate %d bytes of memory", size);
}

/**
 * xfree - free with locking
 * @ptr: memory block to free
 *
 * This function is equivalent to free() but it locks a mutex to prevent arena bloating.
 */
void
xfree(void *ptr)
{
  LOCK_DOMAIN(resource, malloc_domain);
  free(ptr);
  UNLOCK_DOMAIN(resource, malloc_domain);
}

#endif
