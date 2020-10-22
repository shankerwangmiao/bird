/*
 *	BIRD -- Timers
 *
 *	(c) 2013--2017 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2013--2020 CZ.NIC z.s.p.o.
 *	(c) 2020 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_TIMELOOP_H_
#define _BIRD_TIMELOOP_H_ 

#include "lib/timer.h"

struct timeloop
{
  DOMAIN(timer) domain;

  btime last_time;
  btime real_time;

  int fds[2];				/* sysdep specific data */

  LOCKED_STRUCT(timer,
      BUFFER_(timer *) timers;
      );
};

#define TL_TIMERS(tl)		UNLOCKED_STRUCT(timer, tl)->timers

#define TM_EXPIRES_U(t)		UNLOCKED_STRUCT(timer, (t))->expires
#define TM_REMAINS_U(t)		({ \
    btime now_ = current_time(); \
    btime exp_ = TM_EXPIRES_U(t); \
    exp_ > now_ ? exp_ - now_ : 0; \
    })

static inline uint timers_count(LOCKED(timer), struct timeloop *loop)
{ return UNLOCKED_STRUCT(timer, loop)->timers.used - 1; }

static inline timer *timers_first(LOCKED(timer), struct timeloop *loop)
{
  AUTO_TYPE timers = &TL_TIMERS(loop);
  return (timers->used > 1) ? timers->data[1] : NULL;
}

#endif
