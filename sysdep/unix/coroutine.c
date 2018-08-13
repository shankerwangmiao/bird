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
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 *	Coroutine private structures 
 */

static _Thread_local event *ev_local = NULL;
static _Thread_local struct birdsock *sk_local = NULL;
_Thread_local struct linpool *lp_local = NULL;	/* Local linpool for temporary allocations */

list coro_list;

struct coroutine {
  LOCKED_STRUCT(event_state,
      node n;
      );

  pthread_t id;				/* The appropriate pthread */
  pthread_attr_t attr;			/* Attributes (stack size, detachable, etc.) */
  struct domain_generic * _Atomic wfl;	/* Waiting for this lock */
  _Atomic _Bool cancelled;		/* Synchronous cancel has been requested */

  struct linpool *lp_local;		/* Local linpool for temporary allocations */

  enum coro_flags {
    CORO_REPEAT = 0x2,			/* Run once more */
    CORO_STOP = 0x4,			/* Cancelled, finishing */
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
} *coro_local = NULL, main_thread_coro;

/*
 *	Locking subsystem
 */

#define DOMAIN(type) struct domain__##type
#define ASSERT_NO_LOCK	ASSERT_DIE(last_locked == NULL)

struct domain_generic {
  pthread_mutex_t mutex;
  struct domain_generic **prev;
  struct lock_order *locked_by;
  const char *name;
  _Bool free_after_unlock;
  _Bool unlock_to_cancel;
};

#define DOMAIN_INIT(_name) { .mutex = PTHREAD_MUTEX_INITIALIZER, .name = _name }

static struct domain_generic event_state_domain_gen = DOMAIN_INIT("Event state"),
			     the_bird_domain_gen = DOMAIN_INIT("The BIRD");

DOMAIN(event_state) event_state_domain = { .event_state = &event_state_domain_gen };
DOMAIN(the_bird) the_bird_domain = { .the_bird = &the_bird_domain_gen };

struct domain_generic *
domain_new(const char *name)
{
  struct domain_generic *dg = xmalloc(sizeof(struct domain_generic));
  *dg = (struct domain_generic) DOMAIN_INIT(name);
  return dg;
}

void
domain_free_after_unlock(struct domain_generic *dg)
{
  dg->free_after_unlock = 1;
}

_Thread_local struct lock_order locking_stack = {};
_Thread_local struct domain_generic **last_locked = NULL;

#define WFL(d) atomic_store_explicit(&coro_local->coro.wfl, (d), memory_order_release);

_Bool do_lock(struct domain_generic *dg, struct domain_generic **lsp)
{
  if (lsp <= last_locked)
    bug("Trying to lock in a bad order");
  if (*lsp)
    bug("Inconsistent locking stack state on lock");

  /* Declare that we're waiting for this lock */
  WFL(dg);

  /* We shall fail if cancellation is requested */
  if (atomic_load_explicit(&coro_local->coro.cancelled, memory_order_acquire))
  {
    WFL(NULL);
    return 0;
  }

  /* Is this unlocking speculative? */
  while (
      pthread_mutex_lock(&dg->mutex),
      dg->unlock_to_cancel) {
    if (atomic_load_explicit(&coro_local->coro.cancelled, memory_order_acquire))
    {
      /* Yes and this thread is being cancelled */
      WFL(NULL);
      pthread_mutex_unlock(&dg->mutex);
      return 0;
    }
    else
      /* Yes and this thread will wait for a regular unlock */
      pthread_mutex_unlock(&dg->mutex);
  }

  /* Finally a regular unlock, not waiting for the lock anymore */
  WFL(NULL);
    
  if (dg->prev || dg->locked_by)
    bug("Previous unlock not finished correctly");
  dg->prev = last_locked;
  *lsp = dg;
  last_locked = lsp;
  dg->locked_by = &locking_stack;

  return 1;
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
  if (dg->free_after_unlock)
  {
    pthread_mutex_destroy(&dg->mutex);
    xfree(dg);
  }
}

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
    sk->class->cli_info(sk, sk_debug_buf, sizeof(sk_debug_buf)-1); \
    sk_debug_buf; \
    })
#define SK_DEBUG_FMT "(sk %s %p from coro %p %s)\n"
#define SK_DEBUG_ARGS(sk) sk_type_names[sk->type], sk, coro_local, SK_INFO(sk)

#define SK_DEBUG(sk, s, a...) DBG("%.6T: socket " s " " SK_DEBUG_FMT, ##a, SK_DEBUG_ARGS(sk))

void
ev_dump(event *e)
{
  EVENT_LOCKED_NOFAIL
  {
    AUTO_TYPE eu = UNLOCKED_STRUCT(event_state, e);
    debug(EV_DEBUG_FMT, EV_DEBUG_ARGS(e, eu));
  }
}

static void coro_free(LOCKED(event_state), struct coroutine *c)
{
  rem_node(&UNLOCKED_STRUCT(event_state, c)->n);
  rfree(c->lp_local);

  switch (c->flags & CORO_KIND_MASK) 
  {
    case CORO_KIND_EVENT:
      sem_destroy(&((struct coro_event *) c)->cancel_sem);
      break;
    case CORO_KIND_SOCKET:
      close(((struct coro_sock *) c)->cancel_pipe[0]);
      close(((struct coro_sock *) c)->cancel_pipe[1]);
      break;
    default:
      bug("Coroutine of unknown kind: 0x%x", c->flags);
  }

  pthread_attr_destroy(&c->attr);
  xfree(c);
}

static void
coro_sync_stop(LOCKED(event_state), struct coroutine *coro)
{
  atomic_store_explicit(&coro->cancelled, 1, memory_order_release);

  switch (coro->flags & CORO_KIND_MASK) 
  {
    case CORO_KIND_EVENT:
      sem_post(&((struct coro_event *) coro)->cancel_sem);
      break;

    case CORO_KIND_SOCKET:
      write(((struct coro_sock *) coro)->cancel_pipe[1], "", 1);
      break;
      
    default:
      bug("Coroutine of unknown kind: 0x%x", coro_local->coro.flags);
  }

  /* The cancelled coroutine may be waiting for the lock we're currently waiting for */
  while (1) {
    struct domain_generic *wfl = atomic_load_explicit(&coro->wfl, memory_order_acquire);
    if (!wfl || wfl->locked_by != &locking_stack)
      break;

    /* Speculatively unlock to release the cancelled coroutine and let it finish */
    wfl->unlock_to_cancel = 1;
    pthread_mutex_unlock(&wfl->mutex);
    pthread_mutex_lock(&wfl->mutex);
    wfl->unlock_to_cancel = 0;
  }

  /* Now the cancelled coroutine shall be released and we just wait for it */
  void *data;
  int e = pthread_join(coro->id, &data);
  if (e < 0)
    bug("pthread_join: %m");

  ASSERT_DIE(data == coro);

  coro_free(CURRENT_LOCK, coro);
}

static void coro_finish(LOCKED(event_state))
{
  ASSERT_DIE(pthread_equal(coro_local->coro.id, pthread_self()));

  pthread_detach(coro_local->coro.id);
  coro_free(CURRENT_LOCK, &coro_local->coro);
}

enum ev_cancel_result
ev_cancel(event *e, _Bool allow_self)
{
  _Bool out = EV_CANCEL_NONE;
  EVENT_LOCKED_NOFAIL
  {
    if (e == ev_local)
    {
      ASSERT_DIE(allow_self);
      EV_DEBUG(e, "cancel from self");
    }
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
      {
	eu->coro->c.flags |= CORO_STOP;
	out = EV_CANCEL_SELF;
      }
      else
      {
	coro_sync_stop(CURRENT_LOCK, &eu->coro->c);
	out = EV_CANCEL_STOPPED;
      }
      
      eu->coro = NULL;
    }
  }
  return out;
}

static void *ev_entry(void *_coro)
{
  timeloop_current = &main_timeloop; /* TODO: use local timers if appropriate */

  void (*hook)(void *);
  void *data;

  DBG("ev_entry(%p)\n", _coro);
  coro_local = _coro;
  lp_local = coro_local->coro.lp_local;

  EVENT_LOCKED ({ return coro_local; })
  {
    ev_local = coro_local->event.ev;
    AUTO_TYPE evlu = UNLOCKED_STRUCT(event_state, ev_local);

    coro_local->coro.flags &= ~CORO_REPEAT;

    hook = evlu->hook;
    data = evlu->data;

    EV_DEBUG(ev_local, "event entry");
  }

  ASSERT_NO_LOCK;

  if (ev_local->default_lock)
  {
    if (!the_bird_lock())
      return coro_local;

    EV_DEBUG_UNLOCKED(ev_local, "event locked");
    hook(data);
    EV_DEBUG_UNLOCKED(ev_local, "event unlocked");

    the_bird_unlock();
  }
  else
    hook(data);

  ASSERT_NO_LOCK;

  DBG("event %p exit\n", ev_local);

  _Bool repeat;

  EVENT_LOCKED ({ return coro_local; })
  {
    repeat = !!(coro_local->coro.flags & CORO_REPEAT);
    if (repeat)
      DBG("coro_repeat(%p)\n", _coro);
    else
    {
      AUTO_TYPE evlu = UNLOCKED_STRUCT(event_state, ev_local);
      DBG("coro_finish(%p)\n", _coro);
      evlu->coro = NULL;
      coro_finish(CURRENT_LOCK);
    }
  }

  if (repeat)
    return ev_entry(_coro);
  else
    return NULL;
}

static pool *thread_local_lp_pool = NULL;

void coro_start(LOCKED(event_state), struct coroutine *coro, void *(*entry)(void *))
{
  EVENT_LOCKED_INIT_LOCK(coro);

  coro->lp_local = lp_new_default(thread_local_lp_pool);

  int e = 0;
  if (e = pthread_attr_init(&coro->attr))
    die("pthread_attr_init() failed: %M", e);

  if (e = pthread_attr_setstacksize(&coro->attr, CORO_STACK_SIZE))
    die("pthread_attr_setstacksize(%u) failed: %M", CORO_STACK_SIZE, e);

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
  EVENT_LOCKED_NOFAIL ev_schedule_locked_(CURRENT_LOCK, ev, name, file, line);
}

#define ev_schedule_locked(l, e) ev_schedule_locked_(l, e, #e, __FILE__, __LINE__)

#else
void ev_schedule(event *ev)
{
  EVENT_LOCKED_NOFAIL ev_schedule_locked(CURRENT_LOCK, ev);
}
#endif

#define sk_do_cancel(s, su, dir) ({ \
      SK_DEBUG(s, "cancel " #dir); \
      ASSERT_DIE(!(su->dir##_coro->c.flags & CORO_REPEAT)); \
      if (su->dir##_coro == &coro_local->sock) { \
	self = 1; \
	su->dir##_coro->c.flags |= CORO_STOP; \
      } else \
	coro_sync_stop(CURRENT_LOCK, &su->dir##_coro->c); \
	su->dir##_coro = NULL; \
      })
   
static void
sk_close_debug(struct birdsock *s)
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

_Bool
sk_close(struct birdsock *s, _Bool allow_self)
{
  sk_close_debug(s);
  sk_close_fd(s);

  _Bool self = 0;

  EVENT_LOCKED_NOFAIL
  {
    AUTO_TYPE su = UNLOCKED_STRUCT(event_state, s);

    if (su->rx_coro)
      sk_do_cancel(s, su, rx);

    if (su->tx_coro)
      sk_do_cancel(s, su, tx);
  }

  ASSERT_DIE(allow_self || !self);

  rfree(s);

  return self;
}

void sk_set_rbsize(sock *s, uint rbsize)
{
  EVENT_LOCKED_NOFAIL
  {
    AUTO_TYPE su = UNLOCKED_STRUCT(event_state, s);

    if (rbsize > su->rbsize)
    {
      su->rbsize = rbsize;

      if (su->rx_coro)
	write(su->rx_coro->cancel_pipe[1], "", 1);
    }
  }
}


void sk_read(sock *s, struct sock_rx_buf *buf, int revents);
_Bool sk_write(sock *s);
void sk_err(sock *s, int revents, _Bool rx);

#define SKL_RX (su->rx_coro == &(coro_local->sock))
#define SKL_TX (su->tx_coro == &(coro_local->sock))

_Bool sk_write_from_tx_hook(LOCKED(event_state), sock *s)
{
  return UNLOCKED_STRUCT(event_state, s)->tx_coro == &(coro_local->sock);
}

static void *sk_entry(void *data)
{
  DBG("sk_entry(%p)\n", data);
  coro_local = data;

  lp_local = coro_local->coro.lp_local;
  sk_local = coro_local->sock.socket;
  timeloop_current = &main_timeloop; /* TODO: use local timers if appropriate */

  struct sock_rx_buf *buf = NULL;
  _Bool rx, tx;

#define SK_DBG_DIR	(rx ? "rx" : (tx ? "tx" : "??"))

  EVENT_LOCKED ({ return data; }) {
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

  while (1)
  {
    EVENT_LOCKED ({
	if (buf)
	  xfree(buf);
	return data;
	})
    {
      AUTO_TYPE su = UNLOCKED_STRUCT(event_state, sk_local);
      rx = SKL_RX;
      tx = SKL_TX;

      if (buf)
      {
	SK_DEBUG(sk_local, "reload");
	if (su->rbsize > buf->end)
	{
	  SK_DEBUG(sk_local, "rx buf realloc from %u to %u", buf->end, su->rbsize);
	  struct sock_rx_buf *nb = xmalloc(sizeof(struct sock_rx_buf) + su->rbsize);
	  *nb = (struct sock_rx_buf) { .end = su->rbsize, .pos = buf->pos };
	  if (nb->pos)
	    memcpy(nb->buf, buf->buf, nb->pos);

	  xfree(buf);
	  buf = nb;
	}
      }
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
    SK_DEBUG(sk_local, "poll %s returned %d", SK_DBG_DIR, pout);

    if (pout < 0)
    {
      if (errno == EINTR || errno == EAGAIN)
	continue;
      die("poll: %m");
    }

    /* A ping received, do a reload */
    if (pfd[0].revents & POLLIN)
    {
      SK_DEBUG(sk_local, "got something on cancel pipe");
      char cbuf[64];
      read(coro_local->sock.cancel_pipe[0], cbuf, sizeof(cbuf));
      continue;
    }

    /* An error received, finishing */
    if (pfd[1].revents & (POLLHUP | POLLERR))
    {
      SK_DEBUG(sk_local, "got error revents: %x", pfd[1].revents);
      sk_err_revents = pfd[1].revents;
      break;
    }

    if (tx && (pfd[1].revents & POLLOUT))
    {
      SK_DEBUG(sk_local, "write");
      if (!sk_write(sk_local))
	break;
    }

    else if (rx && (pfd[1].revents & POLLIN))
    {
      SK_DEBUG(sk_local, "read");
      sk_read(sk_local, buf, pfd[1].revents);
    }

    /* End of the socket loop */
  }

  if (buf)
    xfree(buf);

  EVENT_LOCKED ({ return coro_local; })
  {
    AUTO_TYPE su = UNLOCKED_STRUCT(event_state, sk_local);

    if (SKL_RX)
      su->rx_coro = NULL;
    else if (SKL_TX)
      su->tx_coro = NULL;

    coro_finish(CURRENT_LOCK);
  }

  if (sk_err_revents)
    sk_err(sk_local, sk_err_revents, rx);

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
}

void
sk_schedule_rx(struct birdsock *s)
{
  EVENT_LOCKED_NOFAIL {
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
  EVENT_LOCKED_NOFAIL
  {
    AUTO_TYPE su = UNLOCKED_STRUCT(event_state, s);
    if (!su->tx_coro)
      sk_schedule_tx_locked(CURRENT_LOCK, s);
  }
}

void
coro_init(void)
{
  main_thread_coro.coro.id = pthread_self();
  coro_local = &main_thread_coro;
  init_list(&coro_list);
}

void
coro_resource_init(void)
{
  thread_local_lp_pool = rp_new(&root_pool, "Thread local linpools");
  lp_local = main_thread_coro.coro.lp_local = lp_new_default(thread_local_lp_pool);
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
  EVENT_LOCKED_NOFAIL WALK_LIST(c, coro_list)
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

	show_thread("%s %s socket %s",
	    (rx ? "RX" : (tx ? "TX" : "??")), sk_type_names[s->type], buf);
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

