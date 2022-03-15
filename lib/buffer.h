/*
 *	BIRD Library -- Generic Buffer Structure
 *
 *	(c) 2013 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2013 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_BUFFER_H_
#define _BIRD_BUFFER_H_

#include "lib/resource.h"
#include "sysdep/config.h"

#define BUFFER_(type)		struct { pool *pool; type *data; uint used, size; }
#define BUFFER_TYPE(v)		typeof(* (v).data)
#define BUFFER_SIZE(v)		((v).size * sizeof(* (v).data))

#ifndef PARSER
#define BUFFER(type) BUFFER_(type)
#endif

#define BUFFER_INIT(v,_pool,_size)					\
  ({									\
    (v).used = 0;							\
    (v).size = (_size);							\
    (v).data = mb_alloc(_pool, BUFFER_SIZE(v));				\
    (v).pool = _pool;							\
  })

#define BUFFER_SET(v,nsize)						\
  ({									\
    (v).used = (nsize);							\
    if ((v).used > (v).size)						\
      buffer_realloc((v).pool, (void **) &((v).data), &((v).size), (v).used, sizeof(* (v).data)); \
  })

#define BUFFER_INC(v,step)						\
  ({									\
    uint _o = (v).used;							\
    BUFFER_SET(v, (v).used + (step));					\
    (v).data + _o;							\
  })

#define BUFFER_DEC(v,step)	({ (v).used -= (step); })

#define BUFFER_PUSH(v)		(*BUFFER_INC(v,1))

#define BUFFER_POP(v)		BUFFER_DEC(v,1)

#define BUFFER_FLUSH(v)		({ (v).used = 0; })

#define BUFFER_EMPTY(v)		({ (v).used == 0; })

#define BUFFER_WALK(v,n)						\
  for (BUFFER_TYPE(v) *_n = (v).data, n; _n < ((v).data + (v).used) && (n = *_n, 1); _n++)

#endif /* _BIRD_BUFFER_H_ */
