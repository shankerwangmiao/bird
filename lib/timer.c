/*
 *	BIRD -- Timers
 *
 *	(c) 2013--2017 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2013--2017 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Timers
 *
 * Timers are resources which represent a wish of a module to call a function at
 * the specified time. The timer code does not guarantee exact timing, only that
 * a timer function will not be called before the requested time.
 *
 * In BIRD, time is represented by values of the &btime type which is signed
 * 64-bit integer interpreted as a relative number of microseconds since some
 * fixed time point in past. The current time can be obtained by current_time()
 * function with reasonable accuracy and is monotonic. There is also a current
 * 'wall-clock' real time obtainable by current_real_time() reported by OS.
 *
 * Each timer is described by a &timer structure containing a pointer to the
 * handler function (@hook), data private to this function (@data), time the
 * function should be called at (@expires, 0 for inactive timers), for the other
 * fields see |timer.h|.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "nest/bird.h"

#include "lib/heap.h"
#include "lib/resource.h"
#include "lib/timer.h"

struct timeloop main_timeloop;
_Thread_local struct timeloop *timeloop_current;

btime
current_time(void)
{
  return atomic_load_explicit(&timeloop_current->last_time__atomic, memory_order_relaxed);
}

btime
current_real_time(void)
{
  struct timeloop *loop = timeloop_current;
  btime real_time = atomic_load_explicit(&loop->real_time__atomic, memory_order_relaxed);

  if (real_time)
    return real_time;

  atomic_compare_exchange_strong_explicit(
      &loop->real_time__atomic,
      &real_time,
      times_fetch_real_time(),
      memory_order_relaxed,
      memory_order_relaxed
      );

  return current_real_time();
}


#define TM_INDEX_U(t)		UNLOCKED_STRUCT(timer, (t))->index
#define TIMER_LESS(a,b)		(TM_EXPIRES_U((a)) < TM_EXPIRES_U((b)))
#define TIMER_SWAP(heap,a,b,t)	(t = heap[a], heap[a] = heap[b], heap[b] = t, \
				   TM_INDEX_U((heap[a])) = (a), TM_INDEX_U((heap[b])) = (b))


static void
tm_free(resource *r)
{
  timer *t = (void *) r;

  tm_stop(t);
}

static void
tm_dump_locked(LOCKED(timer), timer *t)
{
  debug("(code %p, data %p, ", t->hook, t->data);
  if (t->randomize)
    debug("rand %d, ", t->randomize);
  if (t->recurrent)
    debug("recur %d, ", t->recurrent);
  if (TM_EXPIRES_U(t))
    debug("expires in %d ms)\n", (TM_EXPIRES_U(t) - current_time()) TO_MS);
  else
    debug("inactive)\n");
}

static void
tm_dump(resource *r)
{
  timer *t = (void *) r;

  LOCKED_DO_NOFAIL(timer, timeloop_current->domain)
    tm_dump_locked(CURRENT_LOCK, t);
}


static struct resclass tm_class = {
  "Timer",
  sizeof(timer),
  tm_free,
  tm_dump,
  NULL,
  NULL
};

timer *
tm_new(pool *p)
{
  timer *t = ralloc(p, &tm_class);
  LOCKED_STRUCT_INIT(timer, t, timeloop_current->domain,
      .index = -1
      );
  return t;
}

static void
tm_set_unlocked(LOCKED(timer), timer *t, btime when)
{
  struct timeloop *loop = timeloop_current;
  uint tc = timers_count(CURRENT_LOCK, loop);

  _Bool kick = (timers_first(CURRENT_LOCK, loop) == t);

  AUTO_TYPE timers = &TL_TIMERS(loop);
  AUTO_TYPE tu = UNLOCKED_STRUCT(timer, t);

  if (!tu->expires)
  {
    tu->index = ++tc;
    tu->expires = when;
    BUFFER_PUSH(*timers) = t;
    HEAP_INSERT(timers->data, tc, timer *, TIMER_LESS, TIMER_SWAP);
  }
  else if (tu->expires < when)
  {
    tu->expires = when;
    HEAP_INCREASE(timers->data, tc, timer *, TIMER_LESS, TIMER_SWAP, tu->index);
  }
  else if (tu->expires > when)
  {
    tu->expires = when;
    HEAP_DECREASE(timers->data, tc, timer *, TIMER_LESS, TIMER_SWAP, tu->index);
  }

  if (kick || (timers_first(CURRENT_LOCK, loop) == t))
    timers_ping(loop);
}

void
tm_set(timer *t, btime when)
{
  LOCKED_DO_NOFAIL(timer, timeloop_current->domain)
    tm_set_unlocked(CURRENT_LOCK, t, when);
}

void
tm_start(timer *t, btime after)
{
  LOCKED_DO_NOFAIL(timer, timeloop_current->domain)
    tm_set_unlocked(CURRENT_LOCK, t, current_time() + MAX(after, 0));
}

void
tm_set_max(timer *t, btime when)
{
  LOCKED_DO_NOFAIL(timer, timeloop_current->domain)
    if (when > UNLOCKED_STRUCT(timer, t)->expires)
      tm_set_unlocked(CURRENT_LOCK, t, when);
}

void
tm_start_max(timer *t, btime after)
{
  btime now_ = current_time();
  btime when = after + now_;

  LOCKED_DO_NOFAIL(timer, timeloop_current->domain)
    if (when > UNLOCKED_STRUCT(timer, t)->expires)
      tm_set_unlocked(CURRENT_LOCK, t, when);
}

static void
tm_stop_unlocked(LOCKED(timer), timer *t)
{
  struct timeloop *loop = timeloop_current;

  if (TM_EXPIRES_U(t))
  {
    AUTO_TYPE timers = &TL_TIMERS(loop);
    AUTO_TYPE tu = UNLOCKED_STRUCT(timer, t);

    uint tc = timers_count(CURRENT_LOCK, loop);

    _Bool kick = (timers_first(CURRENT_LOCK, loop) == t);

    HEAP_DELETE(timers->data, tc, timer *, TIMER_LESS, TIMER_SWAP, tu->index);
    BUFFER_POP(*timers);

    tu->index = -1;
    tu->expires = 0;

    if (kick)
      timers_ping(loop);
  }
}

void
tm_stop(timer *t)
{
  LOCKED_DO_NOFAIL(timer, timeloop_current->domain)
    tm_stop_unlocked(CURRENT_LOCK, t);
}

_Bool
tm_active(timer *t)
{
  _Bool out;
  LOCKED_DO_NOFAIL(timer, timeloop_current->domain) out = TM_EXPIRES_U(t) != 0;
  return out;
}

btime
tm_remains(timer *t)
{
  btime rem;
  LOCKED_DO_NOFAIL(timer, timeloop_current->domain) rem = TM_REMAINS_U(t);
  return rem;
}

void
timers_init(struct timeloop *loop, pool *p, const char *name)
{
  times_init(loop);

  loop->domain = DOMAIN_NEW(timer, name);
  LOCKED_STRUCT_INIT_LOCK(timer, loop, loop->domain);

  LOCKED_DO_NOFAIL(timer, loop->domain)
  {
    AUTO_TYPE lu = UNLOCKED_STRUCT(timer, loop);

    BUFFER_INIT(lu->timers, p, 4);
    BUFFER_PUSH(lu->timers) = NULL;
  }
}

void io_log_event(void *hook, void *data);

void
timers_fire(struct timeloop *loop)
{
  while (1)
  {
    timer *t = NULL;

    LOCKED_DO_NOFAIL(timer, loop->domain)
    {
      atomic_store_explicit(&loop->real_time__atomic, 0, memory_order_relaxed);

      btime old_time = atomic_load_explicit(&loop->last_time__atomic, memory_order_relaxed);
      btime base_time = times_update(old_time);

      ASSERT_DIE(atomic_compare_exchange_strong_explicit(
	    &loop->last_time__atomic,
	    &old_time,
	    base_time,
	    memory_order_relaxed,
	    memory_order_relaxed));

      if ((t = timers_first(CURRENT_LOCK, loop)) && TM_EXPIRES_U(t) <= base_time)
      {
	AUTO_TYPE tu = UNLOCKED_STRUCT(timer, t);

	if (t->recurrent)
	{
	  btime when = tu->expires + t->recurrent;

	  if (when <= base_time)
	    when = base_time + t->recurrent;

	  if (t->randomize)
	    when += random() % (t->randomize + 1);

	  tm_set_unlocked(CURRENT_LOCK, t, when);
	}
	else
	  tm_stop_unlocked(CURRENT_LOCK, t);
      }
      else
	t = NULL;
    }

    if (t)
      t->hook(t);
    else
      return;
  }
}

void
timer_init(void)
{
  timers_init(&main_timeloop, &root_pool, "Main timer");
  timeloop_current = &main_timeloop;
}


/**
 * tm_parse_time - parse a date and time
 * @x: time string
 *
 * tm_parse_time() takes a textual representation of a date and time
 * (yyyy-mm-dd[ hh:mm:ss[.sss]]) and converts it to the corresponding value of
 * type &btime.
 */
btime
tm_parse_time(const char *x)
{
  struct tm tm = {};
  int usec, n1, n2, n3, r;

  r = sscanf(x, "%d-%d-%d%n %d:%d:%d%n.%d%n",
	     &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &n1,
	     &tm.tm_hour, &tm.tm_min, &tm.tm_sec, &n2,
	     &usec, &n3);

  if ((r == 3) && !x[n1])
    tm.tm_hour = tm.tm_min = tm.tm_sec = usec = 0;
  else if ((r == 6) && !x[n2])
    usec = 0;
  else if ((r == 7) && !x[n3])
  {
    /* Convert subsecond digits to proper precision */
    int digits = n3 - n2 - 1;
    if ((usec < 0) || (usec > 999999) || (digits < 1) || (digits > 6))
      return 0;

    while (digits++ < 6)
      usec *= 10;
  }
  else
    return 0;

  tm.tm_mon--;
  tm.tm_year -= 1900;
  s64 ts = mktime(&tm);
  if ((ts == (s64) (time_t) -1) || (ts < 0) || (ts > ((s64) 1 << 40)))
    return 0;

  return ts S + usec;
}

/**
 * tm_format_time - convert date and time to textual representation
 * @x: destination buffer of size %TM_DATETIME_BUFFER_SIZE
 * @fmt: specification of resulting textual representation of the time
 * @t: time
 *
 * This function formats the given relative time value @t to a textual
 * date/time representation (dd-mm-yyyy hh:mm:ss) in real time.
 */
void
tm_format_time(char *x, struct timeformat *fmt, btime t)
{
  btime dt = current_time() - t;
  btime rt = current_real_time() - dt;
  int v1 = !fmt->limit || (dt < fmt->limit);

  if (!tm_format_real_time(x, TM_DATETIME_BUFFER_SIZE, v1 ? fmt->fmt1 : fmt->fmt2, rt))
    strcpy(x, "<error>");
}

/* Replace %f in format string with usec scaled to requested precision */
static int
strfusec(char *buf, int size, const char *fmt, uint usec)
{
  char *str = buf;
  int parity = 0;

  while (*fmt)
  {
    if (!size)
      return 0;

    if ((fmt[0] == '%') && (!parity) &&
	((fmt[1] == 'f') || (fmt[1] >= '1') && (fmt[1] <= '6') && (fmt[2] == 'f')))
    {
      int digits = (fmt[1] == 'f') ? 6 : (fmt[1] - '0');
      uint d = digits, u = usec;

      /* Convert microseconds to requested precision */
      while (d++ < 6)
	u /= 10;

      int num = bsnprintf(str, size, "%0*u", digits, u);
      if (num < 0)
	return 0;

      fmt += (fmt[1] == 'f') ? 2 : 3;
      ADVANCE(str, size, num);
    }
    else
    {
      /* Handle '%%' expression */
      parity = (*fmt == '%') ? !parity : 0;
      *str++ = *fmt++;
      size--;
    }
  }

  if (!size)
    return 0;

  *str = 0;
  return str - buf;
}

int
tm_format_real_time(char *x, size_t max, const char *fmt, btime t)
{
  s64 t1 = t TO_S;
  s64 t2 = t - t1 S;

  time_t ts = t1;
  struct tm tm;
  if (!localtime_r(&ts, &tm))
    return 0;

  byte tbuf[TM_DATETIME_BUFFER_SIZE];
  if (!strfusec(tbuf, max, fmt, t2))
    return 0;

  if (!strftime(x, max, tbuf, &tm))
    return 0;

  return 1;
}
