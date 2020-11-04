/*
 *	BIRD Coroutines
 *
 *	(c) 2017 Martin Mares <mj@ucw.cz>
 *	(c) 2020 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#undef LOCAL_DEBUG
#define LOCAL_DEBUG

#undef DEBUG_LOCKING

#include "lib/birdlib.h"
#include "lib/ip.h"
#include "lib/event.h"
#include "lib/timer.h"
#include "lib/socket.h"

#include "nest/cli.h"
#include "nest/protocol.h"

/* Using a rather big stack for coroutines to allow for stack-local allocations. */
#define CORO_STACK_SIZE	1048576

//#define CORO_STACK_SIZE 65536
//#define CORO_STACK_SIZE 32768

/*
 *	Implementation of coroutines based on POSIX threads
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 *	Locking subsystem
 */

#define DOMAIN(type) struct domain__##type
#define ASSERT_NO_LOCK	ASSERT_DIE(last_locked == NULL)

struct domain_generic {
  pthread_mutex_t mutex;
  struct domain_generic **prev;
  struct lock_order *locked_by;
};

#define DOMAIN_INIT { .mutex = PTHREAD_MUTEX_INITIALIZER }

static struct domain_generic event_state_domain_gen = DOMAIN_INIT,
			     the_bird_domain_gen = DOMAIN_INIT;

DOMAIN(event_state) event_state_domain = { .event_state = &event_state_domain_gen };
DOMAIN(the_bird) the_bird_domain = { .the_bird = &the_bird_domain_gen };

#define EVENT_UNLOCKED for ( \
  _Bool _bird_aux = (do_unlock(event_state_domain.event_state, &locking_stack.event_state), 1); \
  _bird_aux ? ((_bird_aux = 0), 1) : 0; \
  do_lock(event_state_domain.event_state, &locking_stack.event_state))

_Thread_local struct lock_order locking_stack = {};
_Thread_local struct domain_generic **last_locked = NULL;

void do_lock(struct domain_generic *dg, struct domain_generic **lsp)
{
  if (lsp <= last_locked)
    bug("Trying to lock in a bad order");
  if (*lsp)
    bug("Inconsistent locking stack state on lock");
  pthread_mutex_lock(&dg->mutex);
  if (dg->prev || dg->locked_by)
    bug("Previous unlock not finished correctly");
  dg->prev = last_locked;
  *lsp = dg;
  last_locked = lsp;
  dg->locked_by = &locking_stack;
}

void do_unlock(struct domain_generic *dg, struct domain_generic **lsp)
{
  if (dg->locked_by != &locking_stack)
    bug("Inconsistent domain state on unlock");
  if ((last_locked != lsp) || (*lsp != dg))
    bug("Inconsistent locking stack state on unlock");
  dg->locked_by = NULL;
  last_locked = dg->prev;
  *lsp = NULL;
  dg->prev = NULL;
  pthread_mutex_unlock(&dg->mutex);
}

static _Thread_local event *ev_local = NULL;
static _Thread_local struct birdsock *sk_local = NULL;

list coro_list;

struct coroutine {
  LOCKED_STRUCT(event_state,
      node n;
      );

  pthread_t id;				/* The appropriate pthread */
  pthread_attr_t attr;			/* Attributes (stack size, detachable, etc.) */

  enum coro_flags {
    CORO_REPEAT = 0x2,			/* Run once more */
    CORO_STOP = 0x4,			/* Canceled by self */
    CORO_KIND_EVENT = 0x10,		/* Event coroutine */
    CORO_KIND_SOCKET = 0x20,		/* Socket coroutine */
    CORO_KIND_MASK = 0xf0,
  } flags;
};

static const char coro_dump_flagset[] = "0RS3es";

struct coro_event {
  struct coroutine c;
  event *ev;				/* The event this coroutine is assigned to */
  sem_t cancel_sem;			/* Semaphore to post on coroutine cancellation */
};

struct coro_sock {
  struct coroutine c;
  struct birdsock *socket;		/* Socket to work at */
  int cancel_pipe[2];			/* Pipe to ping on coroutine cancellation */
};

static _Thread_local union coro_union {
  struct coroutine coro;
  struct coro_event event;
  struct coro_sock sock;
} *coro_local = NULL;

static const char *coro_dump(struct coroutine *c)
{
  if (!c)
    return "";

  static _Thread_local char buf[sizeof(coro_dump_flagset)];

  uint pos = 0, i = 0;
  for (uint flags = c->flags; flags; i++, flags >>= 1)
    if (i >= sizeof(coro_dump_flagset))
      bug("Unknown coroutine flagset: 0x%x", c->flags);
    else if (flags & 1)
      buf[pos++] = coro_dump_flagset[i];

  buf[pos] = 0;
  return buf;
}

#define EV_DEBUG_FMT "(ev %p, code %p (%s), data %p, init %s:%u, %s)\n"
#define EV_DEBUG_ARGS(e, eu) e, eu->hook, e->name, eu->data, e->file, e->line, \
  coro_dump(&eu->coro->c)

#define EV_DEBUG(e, s, a...) DBG("%.6T: " s " " EV_DEBUG_FMT, ##a, \
    EV_DEBUG_ARGS(e, UNLOCKED_STRUCT(event_state, e)))

#define EV_DEBUG_FMT_UNLOCKED "(ev %p, code (%s), init %s:%u)\n"
#define EV_DEBUG_ARGS_UNLOCKED(e) e, e->name, e->file, e->line

#define EV_DEBUG_UNLOCKED(e, s, a...) DBG("%.6T: " s " " EV_DEBUG_FMT_UNLOCKED, ##a, \
    EV_DEBUG_ARGS_UNLOCKED(e))

static _Thread_local char sk_debug_buf[256];
extern char *sk_type_names[];

#define SK_INFO(sk) ({ \
    ASSERT_DIE(UNLOCKED_STRUCT(event_state, sk)->cli_info); \
    UNLOCKED_STRUCT(event_state, sk)->cli_info(CURRENT_LOCK, sk, sk_debug_buf, sizeof(sk_debug_buf)-1); \
    sk_debug_buf; \
    })
#define SK_DEBUG_FMT "(sk %s %p from coro %p %s)\n"
#define SK_DEBUG_ARGS(sk) sk_type_names[sk->type], sk, coro_local, SK_INFO(sk)

#define SK_DEBUG(sk, s, a...) DBG("%.6T: socket " s " " SK_DEBUG_FMT, ##a, SK_DEBUG_ARGS(sk))

#define SK_DEBUG_FMT_UNLOCKED "(sk %s %p from coro %p)\n"
#define SK_DEBUG_ARGS_UNLOCKED(sk) sk_type_names[sk->type], sk, coro_local

#define SK_DEBUG_UNLOCKED(sk, s, a...) DBG("%.6T: socket " s " " SK_DEBUG_FMT_UNLOCKED, ##a, \
    SK_DEBUG_ARGS_UNLOCKED(sk))

void
ev_dump(event *e)
{
  EVENT_LOCKED
  {
    AUTO_TYPE eu = UNLOCKED_STRUCT(event_state, e);
    debug(EV_DEBUG_FMT, EV_DEBUG_ARGS(e, eu));
  }
}

static void coro_free(void)
{
  EVENT_LOCKED rem_node(&UNLOCKED_STRUCT(event_state, &coro_local->coro)->n);

  switch (coro_local->coro.flags & CORO_KIND_MASK) 
  {
    case CORO_KIND_EVENT:
      sem_destroy(&coro_local->event.cancel_sem);
      break;
    case CORO_KIND_SOCKET:
      close(coro_local->sock.cancel_pipe[0]);
      close(coro_local->sock.cancel_pipe[1]);
      break;
    default:
      bug("Coroutine of unknown kind: 0x%x", coro_local->coro.flags);
  }

  pthread_attr_destroy(&coro_local->coro.attr);
  xfree(coro_local);
  coro_local = NULL;
}

/* From sysdep/unix/io.c */
void io_update_time(void);
void io_log_event(void *hook, void *data);
void io_close_event(void);

static _Bool ev_get_cancelled_(LOCKED(event_state))
{
  ASSERT_DIE((coro_local->coro.flags & CORO_KIND_MASK) == CORO_KIND_EVENT);

  struct coro_event *cev = &(coro_local->event);
  if (cev->c.flags & CORO_STOP)
    return 1;

  int e = sem_trywait(&cev->cancel_sem);
  if ((e < 0) && (errno == EAGAIN))
    return 0;

  if ((e < 0) && (errno == EINTR))
    return ev_get_cancelled_(CURRENT_LOCK);

  if (e < 0)
    die("sem_trywait() failed in ev_get_cancelled: %M");

  ASSERT_DIE(e == 0);
  /* Store the cancellation info locally */
  cev->c.flags |= CORO_STOP;
  return 1;
}

_Bool ev_get_cancelled(void)
{
  _Bool out;
  EVENT_LOCKED out = ev_get_cancelled_(CURRENT_LOCK);
  return out;
}

static NORET void ev_exit_(LOCKED(event_state))
{
  ASSERT_DIE((coro_local->coro.flags & CORO_KIND_MASK) == CORO_KIND_EVENT);

  /* Here the ev_local pointer is not a valid pointer, maybe */
  DBG("stopping cancelled event: %p\n", coro_local->event.ev);

  if (!(coro_local->coro.flags & CORO_STOP))
    UNLOCKED_STRUCT(event_state, ev_local)->coro = NULL;

  ev_local = NULL;

  EVENT_UNLOCKED
  {
    ASSERT_NO_LOCK;
    coro_free();
    pthread_exit(NULL);
  }

  bug("There shall happen nothing after pthread_exit()");
}

NORET void ev_exit(void)
{
  EVENT_LOCKED ev_exit_(CURRENT_LOCK);
  bug("There shall happen nothing after pthread_exit()");
}

static void ev_check_cancelled(LOCKED(event_state))
{
  if (ev_get_cancelled_(CURRENT_LOCK))
    ev_exit_(CURRENT_LOCK);
}

void ev_suspend(void)
{
  struct suspend_lock {
    struct domain_generic *lock, **slot;
  } stored[LOCK_ORDER_DEPTH];

  uint N = 0;
  while (last_locked)
  {
    stored[N++] = (struct suspend_lock) {
      .lock = *last_locked,
      .slot = last_locked,
    };

    do_unlock(*last_locked, last_locked);
  }

  while (N--)
  {
    do_lock(stored[N].lock, stored[N].slot);
    _Bool cancelled;
    cancelled = ev_get_cancelled();
    if (!cancelled)
      continue;

    while (last_locked)
      do_unlock(*last_locked, last_locked);
    ev_exit();
  }
}

_Bool ev_cancel(event *e)
{
  _Bool out = 0;
  EVENT_LOCKED
  {
    if (e == ev_local)
      EV_DEBUG(e, "cancel from self");
    else if (ev_local)
      EV_DEBUG(e, "cancel from %p", ev_local);
    else if (sk_local)
      EV_DEBUG(e, "cancel from %p", sk_local);
    else
      EV_DEBUG(e, "cancel from main");

    AUTO_TYPE eu = UNLOCKED_STRUCT(event_state, e);
    if (eu->coro)
    {
      eu->coro->c.flags &= ~CORO_REPEAT;

      if (e == ev_local)
	eu->coro->c.flags |= CORO_STOP;
      else
	sem_post(&(eu->coro->cancel_sem));
      
      out = 1;
      eu->coro = NULL;
    }
  }
  return out;
}

extern _Thread_local struct timeloop *timeloop_current;

static void *ev_entry(void *data)
{
  timeloop_current = &main_timeloop; /* TODO: use local timers if appropriate */

  EVENT_LOCKED
  {
    DBG("ev_entry(%p)\n", data);
    coro_local = data;

    ev_check_cancelled(CURRENT_LOCK);

    ev_local = coro_local->event.ev;
    AUTO_TYPE evlu = UNLOCKED_STRUCT(event_state, ev_local);

    do {
      coro_local->coro.flags &= ~CORO_REPEAT;

      void (*hook)(void *) = evlu->hook;
      void *data = evlu->data;

      io_log_event(hook, data);

      EV_DEBUG(ev_local, "event entry");

      if (ev_local->default_lock)
	EVENT_UNLOCKED
	{
	  ASSERT_NO_LOCK;
	  the_bird_lock();
	  EV_DEBUG_UNLOCKED(ev_local, "event locked");

	  _Bool cancelled;
	  cancelled = ev_get_cancelled();
	  if (cancelled)
	  {
	    the_bird_unlock();
	    ev_exit();
	  }

	  hook(data);

	  EV_DEBUG_UNLOCKED(ev_local, "event unlocked");
	  the_bird_unlock();
	  ASSERT_NO_LOCK;
	}
      else
	EVENT_UNLOCKED
	{
	  ASSERT_NO_LOCK;
	  hook(data);
	  ASSERT_NO_LOCK;
	}

      DBG("event %p exit\n", ev_local);
      io_update_time();
    } while (coro_local->coro.flags & CORO_REPEAT);

    ev_check_cancelled(CURRENT_LOCK);

    DBG("coro_free(%p)\n", data);
    evlu->coro = NULL;
  }

  coro_free();
  return NULL;
}

void coro_start(LOCKED(event_state), struct coroutine *coro, void *(*entry)(void *))
{
  EVENT_LOCKED_INIT_LOCK(coro);

  int e = 0;
  if (e = pthread_attr_init(&coro->attr))
    die("pthread_attr_init() failed: %M", e);

  if (e = pthread_attr_setstacksize(&coro->attr, CORO_STACK_SIZE))
    die("pthread_attr_setstacksize(%u) failed: %M", CORO_STACK_SIZE, e);

  if (e = pthread_attr_setdetachstate(&coro->attr, PTHREAD_CREATE_DETACHED))
    die("pthread_attr_setdetachstate(PTHREAD_CREATE_DETACHED) failed: %M", e);

  if (e = pthread_create(&coro->id, &coro->attr, entry, coro))
    die("pthread_create() failed: %M", e);

  add_tail(&coro_list, &(UNLOCKED_STRUCT(event_state, coro)->n));
}

#ifdef DEBUGGING
void ev_schedule_locked_(LOCKED(event_state), event *ev, const char *name, const char *file, uint line)
#else
void ev_schedule_locked(LOCKED(event_state), event *ev)
#endif
{
#ifdef DEBUGGING
  if (ev_local)
    EV_DEBUG(ev, "scheduling from %p event %s in %s:%u", ev_local, name, file, line);
  else if (sk_local)
    EV_DEBUG(ev, "scheduling from socket %s %s in %s:%u", SK_INFO(sk_local), name, file, line);
  else
    EV_DEBUG(ev, "scheduling from main event %s in %s:%u", name, file, line);
#else
  if (ev_local)
    EV_DEBUG(ev, "scheduling from %p", ev_local);
  else if (sk_local)
    EV_DEBUG(ev, "scheduling from socket %s", SK_INFO(sk_local));
  else
    EV_DEBUG(ev, "scheduling from main");
#endif

  AUTO_TYPE evu = UNLOCKED_STRUCT(event_state, ev);
  if (evu->coro)
  {
    evu->coro->c.flags |= CORO_REPEAT;
    EV_DEBUG(ev, "repeat");
    return;
  }

  struct coro_event *coro = evu->coro = xmalloc(sizeof(struct coro_event));
  memset(coro, 0, sizeof(struct coro_event));
  coro->ev = ev;
  coro->c.flags |= CORO_KIND_EVENT;
  sem_init(&coro->cancel_sem, 0, 0);
  coro_start(CURRENT_LOCK, &(coro->c), ev_entry);
  EV_DEBUG(ev, "spawned");
}

#ifdef DEBUGGING
void ev_schedule_(event *ev, const char *name, const char *file, uint line)
{
  EVENT_LOCKED ev_schedule_locked_(CURRENT_LOCK, ev, name, file, line);
}

#define ev_schedule_locked(l, e) ev_schedule_locked_(l, e, #e, __FILE__, __LINE__)

#else
void ev_schedule(event *ev)
{
  EVENT_LOCKED ev_schedule_locked(CURRENT_LOCK, ev);
}
#endif

static const char SKC_CANCEL = 0;
static const char SKC_RELOAD = 1;

#define sk_write_pipe(su, dir, c) write(su->dir##_coro->cancel_pipe[1], c, 1)

#define sk_do_cancel(s, su, dir) ({ \
      ASSERT_DIE(!(su->dir##_coro->c.flags & CORO_REPEAT)); \
      if (su->dir##_coro == &coro_local->sock) \
	su->dir##_coro->c.flags |= CORO_STOP; \
      else \
	sk_write_pipe(su, dir, &SKC_CANCEL); \
      })
   
#define sk_do_reload(su, dir) sk_write_pipe(su, dir, &SKC_RELOAD)

static void
sk_close_debug(LOCKED(event_state), struct birdsock *s)
{
  if (s == sk_local)
    SK_DEBUG(s, "close from self");
  else if (ev_local)
    SK_DEBUG(s, "close from %p", ev_local);
  else if (sk_local)
    SK_DEBUG(s, "close from %p", sk_local);
  else
    SK_DEBUG(s, "close from main");
}

void sk_close_fd(sock *s);

void sk_close(struct birdsock *s)
{
  sk_close_fd(s);

  _Bool free_now = 1;
  EVENT_LOCKED
  {
    sk_close_debug(CURRENT_LOCK, s);

    AUTO_TYPE su = UNLOCKED_STRUCT(event_state, s);
    su->closing = 1;

    if (su->rx_coro)
    {
      SK_DEBUG(s, "cancel rx");
      free_now = 0;
      sk_do_cancel(s, su, rx);
    }

    if (su->tx_coro)
    {
      SK_DEBUG(s, "cancel tx");
      free_now = 0;
      sk_do_cancel(s, su, tx);
    }
  }

  if (free_now)
  {
    SK_DEBUG_UNLOCKED(s, "sk_close() free now");
    rfree(s);
  }
}

void sk_set_rbsize(sock *s, uint rbsize)
{
  EVENT_LOCKED
  {
    AUTO_TYPE su = UNLOCKED_STRUCT(event_state, s);

    if (rbsize > su->rbsize)
    {
      su->rbsize = rbsize;
      sk_do_reload(su, rx);
    }
  }
}


int sk_read(sock *s, struct sock_rx_buf *buf, int revents);
int sk_write(sock *s);
void sk_err(sock *s, int revents, _Bool rx);

#define SKL_RX (su->rx_coro == &(coro_local->sock))
#define SKL_TX (su->tx_coro == &(coro_local->sock))

_Bool sk_write_from_tx_hook(LOCKED(event_state), sock *s)
{
  return UNLOCKED_STRUCT(event_state, s)->tx_coro == &(coro_local->sock);
}

static void *sk_entry(void *data)
{
  _Bool cancelled = 0;
  DBG("sk_entry(%p)\n", data);
  coro_local = data;

  sk_local = coro_local->sock.socket;
  timeloop_current = &main_timeloop; /* TODO: use local timers if appropriate */

  struct sock_rx_buf *buf = NULL;
  _Bool rx, tx;

#define SK_DBG_DIR	(rx ? "rx" : (tx ? "tx" : "??"))

  EVENT_LOCKED {
    AUTO_TYPE su = UNLOCKED_STRUCT(event_state, sk_local);
    rx = SKL_RX;
    tx = SKL_TX;

    ASSERT_DIE(!tx || !rx);

    if (rx)
    {
      buf = xmalloc(sizeof(struct sock_rx_buf) + su->rbsize);
      *buf = (struct sock_rx_buf) { .end = su->rbsize };
    }

    SK_DEBUG(sk_local, "entry %s", SK_DBG_DIR);
  }

  uint sk_err_revents = 0;

  while (!cancelled && !(coro_local->coro.flags & CORO_STOP))
  {
    uint (*rx_hook)(struct birdsock *, byte *buf, uint size);
    _Bool (*tx_hook)(struct birdsock *);

    EVENT_LOCKED {
      AUTO_TYPE su = UNLOCKED_STRUCT(event_state, sk_local);
      rx = SKL_RX;
      tx = SKL_TX;
      rx_hook = su->rx_hook;
      tx_hook = su->tx_hook;
    }

    if (!tx && !rx)
      break;

    ASSERT_DIE(!tx || !rx);

    struct pollfd pfd[2] = {
      {
	.fd = coro_local->sock.cancel_pipe[0],
	.events = POLLIN,
      },
      {
	.fd = sk_local->fd,
	.events = rx * POLLIN + tx * POLLOUT,
      },
    };

    int pout = poll(pfd, 2, -1);
    SK_DEBUG_UNLOCKED(sk_local, "poll %s returned %d", SK_DBG_DIR, pout);

    if (pout < 0)
    {
      if (errno == EINTR || errno == EAGAIN)
	continue;
      die("poll: %m");
    }

    if (pfd[0].revents & POLLIN)
    {
      DBG("got a byte on cancel pipe for %s socket: %p\n", SK_DBG_DIR, coro_local->sock.socket);
      _Bool reload = 0;
      for (char c; read(coro_local->sock.cancel_pipe[0], &c, 1) == 1; )
	if (c == SKC_CANCEL)
	{
	  cancelled = 1;
	  break;
	}
	else if (c == SKC_RELOAD)
	  reload = 1;
	else
	  die("cancel pipe (%s) got byte %d", SK_DBG_DIR, c);

      if (cancelled)
      {
	SK_DEBUG_UNLOCKED(sk_local, "cancelled");
	break;
      }

      if (!reload)
	continue;

      if (buf)
      {
	SK_DEBUG_UNLOCKED(sk_local, "reload");
	uint rbsize = EVENT_LOCKED_GET(sk_local, rbsize);
	if (rbsize <= buf->end)
	  continue;

	SK_DEBUG_UNLOCKED(sk_local, "rx buf realloc from %u to %u", buf->end, rbsize);
	struct sock_rx_buf *nb = xmalloc(sizeof(struct sock_rx_buf) + rbsize);
	*nb = (struct sock_rx_buf) { .end = rbsize, .pos = buf->pos };
	if (nb->pos)
	  memcpy(nb->buf, buf->buf, nb->pos);

	xfree(buf);
	buf = nb;
	continue;
      }
    }

    if (pfd[1].revents & (POLLHUP | POLLERR))
    {
      sk_err_revents = pfd[1].revents;
      break;
    }

    if (tx && (pfd[1].revents & POLLOUT))
    {
      SK_DEBUG_UNLOCKED(sk_local, "write");
      io_log_event(tx_hook, sk_local->data);
      cancelled = !sk_write(sk_local);
      io_close_event();
    }

    else if (rx && (pfd[1].revents & POLLIN))
    {
      SK_DEBUG_UNLOCKED(sk_local, "read");
      io_log_event(rx_hook, sk_local->data);
      sk_read(sk_local, buf, pfd[1].revents);
      io_close_event();
    }
  }

  _Bool free_sock = 0;
  EVENT_LOCKED
  {
    SK_DEBUG(sk_local, "%s done", SK_DBG_DIR);

    AUTO_TYPE su = UNLOCKED_STRUCT(event_state, sk_local);
    if (su->rx_coro == &(coro_local->sock))
      su->rx_coro = NULL;

    if (su->tx_coro == &(coro_local->sock))
      su->tx_coro = NULL;

    if (sk_local->owner)
    {
      uint as;
      if (as = --UNLOCKED_STRUCT(event_state, sk_local->owner)->active_sockets)
	DBG("Still %u active sockets remaining in %s\n", as, sk_local->owner->name);
      else
      {
	DBG("Last active socket, scheduling owner event for %s\n", sk_local->owner->name);
	ev_schedule_locked(CURRENT_LOCK, sk_local->owner->event);
      }
    }

    if (su->closing && !su->tx_coro && !su->rx_coro)
      free_sock = 1;
  }

  if (free_sock)
    rfree(sk_local);
  else if (sk_err_revents)
    sk_err(sk_local, sk_err_revents, rx);

  coro_free();
  return NULL;
}

static void
sk_coro_start(LOCKED(event_state), struct birdsock *s, struct coro_sock **coro_ptr)
{
  ASSERT(!*coro_ptr);
  struct coro_sock *coro = *coro_ptr = xmalloc(sizeof(struct coro_sock));
  memset(coro, 0, sizeof(struct coro_sock));
  coro->socket = s;
  coro->c.flags |= CORO_KIND_SOCKET;
  if (pipe2(coro->cancel_pipe, O_NONBLOCK) < 0)
    die("pipe: %m");
  coro_start(CURRENT_LOCK, &(coro->c), sk_entry);
  if (s->owner)
  {
    uint as = ++UNLOCKED_STRUCT(event_state, s->owner)->active_sockets;
    DBG("Updated active sockets of %s to %u\n", s->owner->name, as);
  } 
}

void
sk_schedule_rx(struct birdsock *s)
{
  EVENT_LOCKED {
    AUTO_TYPE su = UNLOCKED_STRUCT(event_state, s);
    if (!su->rx_coro)
      sk_coro_start(CURRENT_LOCK, s, &su->rx_coro);
  }
}

void
sk_schedule_tx_locked(LOCKED(event_state), struct birdsock *s)
{
  AUTO_TYPE su = UNLOCKED_STRUCT(event_state, s);
  sk_coro_start(CURRENT_LOCK, s, &su->tx_coro);
}

void
sk_schedule_tx(struct birdsock *s)
{
  EVENT_LOCKED
  {
    AUTO_TYPE su = UNLOCKED_STRUCT(event_state, s);
    if (!su->tx_coro)
      sk_schedule_tx_locked(CURRENT_LOCK, s);
  }
}

void
coro_init(void)
{
  init_list(&coro_list);
}

static uint
do_show_threads(uint cnt)
{
#define SHOW_THREAD_BUFSIZE 1024
#define show_thread(...)  bsnprintf(tbuf + SHOW_THREAD_BUFSIZE * seen++, SHOW_THREAD_BUFSIZE, __VA_ARGS__)

  uint seen = 0;
  char *tbuf = xmalloc(SHOW_THREAD_BUFSIZE * cnt);

  show_thread("Main thread");

  union coro_union *c;
  EVENT_LOCKED WALK_LIST(c, coro_list)
  {
    if (seen >= cnt)
    {
      seen++;
      continue;
    }

    switch (c->coro.flags & CORO_KIND_MASK)
    {
      case CORO_KIND_EVENT:
      {
	event *ev = c->event.ev;
	show_thread("Event %s(%p) inited at %s:%u",
	    ev->name, UNLOCKED_STRUCT(event_state, ev)->data, ev->file, ev->line);
	break;
      }
      case CORO_KIND_SOCKET:
      {
	struct birdsock *s = c->sock.socket;
	AUTO_TYPE su = UNLOCKED_STRUCT(event_state, s);
	_Bool rx = (su->rx_coro == &c->sock);
	_Bool tx = (su->tx_coro == &c->sock);
	char buf[256];
	if (su->cli_info)
	  su->cli_info(CURRENT_LOCK, s, buf, sizeof(buf)-1);

	if (rx)
	  if (su->cli_info)
	    show_thread("RX %s socket %s", sk_type_names[s->type], buf);
	  else
	    show_thread("RX %s socket rx %p data %p", sk_type_names[s->type], su->rx_hook, s->data);  
	else if (tx)
	  if (su->cli_info)
	    show_thread("TX %s socket %s", sk_type_names[s->type], buf);
	  else
	    show_thread("TX %s socket tx %p data %p", sk_type_names[s->type], su->tx_hook, s->data);
	else
	  if (su->cli_info)
	    show_thread("?? %s socket %s", sk_type_names[s->type], buf);
	  else
	    show_thread("?? %s socket data %p", sk_type_names[s->type], s->data);
	break;
      }
      default: bug("Unknown type of coroutine");
    }
  }

  if (seen <= cnt)
  {
    for (uint i=0; i<seen; i++)
      cli_msg(-1026, "%s", tbuf + SHOW_THREAD_BUFSIZE * i);
    cli_msg(1026, "Total: %u threads", seen);
  }

  xfree(tbuf);
  return seen;
}

void
cmd_show_threads(void)
{
  for (uint cnt = 32, seen = 0; (seen = do_show_threads(cnt)) > cnt; cnt = seen * 2)
    ;
}

