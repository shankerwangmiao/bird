/*
 *	BIRD -- Timers
 *
 *	(c) 2013--2017 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2013--2017 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_TIMER_H_
#define _BIRD_TIMER_H_

#include "nest/bird.h"
#include "lib/buffer.h"
#include "lib/resource.h"
#include "lib/locking.h"

DEFINE_DOMAIN(timer);

typedef struct timer
{
  resource r;
  void (*hook)(struct timer *);
  void *data;

  uint randomize;			/* Amount of randomization */
  uint recurrent;			/* Timer recurrence */

  LOCKED_STRUCT(timer,
      btime expires;			/* 0=inactive */
      int index;
      );
} timer;

struct timeloop;
extern struct timeloop main_timeloop;
extern _Thread_local struct timeloop *timeloop_current;

/*
#define TIMELOOP_DO(loop) \
  for (struct timeloop *tmp = timeloop_current, *_loop = loop; \
      _loop && (timeloop_current = _loop); \
      timeloop_current = tmp, _loop = NULL)
      */

/* Wait for next timer. */
void timers_wait(struct timeloop *loop);

btime current_time(void);
btime current_real_time(void);

extern btime boot_time;

timer *tm_new(pool *p);
void tm_set(timer *t, btime when);
void tm_set_max(timer *t, btime when);
void tm_start(timer *t, btime after);
void tm_start_max(timer *t, btime after);
void tm_stop(timer *t);

_Bool tm_active(timer *t);
btime tm_remains(timer *t);

static inline timer *
tm_new_init(pool *p, void (*hook)(struct timer *), void *data, uint rec, uint rand)
{
  timer *t = tm_new(p);
  t->hook = hook;
  t->data = data;
  t->recurrent = rec;
  t->randomize = rand;
  return t;
}

/* In sysdep code */
void times_init(struct timeloop *loop);
void times_update(LOCKED(timer), struct timeloop *loop);
void times_update_real_time(LOCKED(timer), struct timeloop *loop);

/* For I/O loop */
void timers_init(struct timeloop *loop, pool *p, const char *name);
void timers_fire(struct timeloop *loop);

void timer_init(void);


struct timeformat {
  const char *fmt1, *fmt2;
  btime limit;
};

#define TM_ISO_SHORT_S	(struct timeformat){"%T",     "%F", (s64) (20*3600) S_}
#define TM_ISO_SHORT_MS	(struct timeformat){"%T.%3f", "%F", (s64) (20*3600) S_}
#define TM_ISO_SHORT_US	(struct timeformat){"%T.%6f", "%F", (s64) (20*3600) S_}

#define TM_ISO_LONG_S	(struct timeformat){"%F %T",     NULL, 0}
#define TM_ISO_LONG_MS	(struct timeformat){"%F %T.%3f", NULL, 0}
#define TM_ISO_LONG_US	(struct timeformat){"%F %T.%6f", NULL, 0}

#define TM_DATETIME_BUFFER_SIZE 32	/* Buffer size required by tm_format_time() */

btime tm_parse_time(const char *x);
void tm_format_time(char *x, struct timeformat *fmt, btime t);
int tm_format_real_time(char *x, size_t max, const char *fmt, btime t);

#endif
