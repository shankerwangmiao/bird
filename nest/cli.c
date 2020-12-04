/*
 *	BIRD Internet Routing Daemon -- Command-Line Interface
 *
 *	(c) 1999--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Command line interface
 *
 * This module takes care of the BIRD's command-line interface (CLI).
 * The CLI exists to provide a way to control BIRD remotely and to inspect
 * its status. It uses a very simple textual protocol over a stream
 * connection provided by the platform dependent code (on UNIX systems,
 * it's a UNIX domain socket).
 *
 * Each session of the CLI consists of a sequence of request and replies,
 * slightly resembling the FTP and SMTP protocols.
 * Requests are commands encoded as a single line of text, replies are
 * sequences of lines starting with a four-digit code followed by either
 * a space (if it's the last line of the reply) or a minus sign (when the
 * reply is going to continue with the next line), the rest of the line
 * contains a textual message semantics of which depends on the numeric
 * code. If a reply line has the same code as the previous one and it's
 * a continuation line, the whole prefix can be replaced by a single
 * white space character.
 *
 * Reply codes starting with 0 stand for `action successfully completed' messages,
 * 1 means `table entry', 8 `runtime error' and 9 `syntax error'.
 *
 * Each CLI session is internally represented by a &cli structure and a
 * resource pool containing all resources associated with the connection,
 * so that it can be easily freed whenever the connection gets closed, not depending
 * on the current state of command processing.
 *
 * The CLI commands are declared as a part of the configuration grammar
 * by using the |CF_CLI| macro. When a command is received, it is processed
 * by the same lexical analyzer and parser as used for the configuration, but
 * it's switched to a special mode by prepending a fake token to the text,
 * so that it uses only the CLI command rules. Then the parser invokes
 * an execution routine corresponding to the command, which either constructs
 * the whole reply and returns it back or (in case it expects the reply will be long)
 * it prints a partial reply and asks the CLI module (using the @cont hook)
 * to call it again when the output is transferred to the user.
 *
 * The @this_cli variable points to a &cli structure of the session being
 * currently parsed, but it's of course available only in command handlers
 * not entered using the @cont hook.
 *
 */

#include "nest/bird.h"
#include "nest/cli.h"
#include "conf/conf.h"
#include "lib/string.h"

#undef CLI_LOG_HOOKS

pool *cli_pool;

/**
 * cli_printf - send reply to a CLI connection
 * @c: CLI connection
 * @code: numeric code of the reply, negative for continuation lines
 * @msg: a printf()-like formatting string.
 *
 * This function send a single line of reply to a given CLI connection.
 * In works in all aspects like bsprintf() except that it automatically
 * prepends the reply line prefix.
 *
 * Please note that if the connection can be already busy sending some
 * data in which case cli_printf() stores the output to a temporary buffer,
 * so please avoid sending a large batch of replies without waiting
 * for the buffers to be flushed.
 *
 * If you want to write to the current CLI output, you can use the cli_msg()
 * macro instead.
 */
void
cli_printf(cli *c, int code, char *msg, ...)
{
  va_list args;
  byte buf[CLI_LINE_SIZE];
  int cd = code;
  int errcode;
  int size, cnt;

  if (cd < 0)
    {
      cd = -cd;
      if (cd == c->last_reply)
	size = bsprintf(buf, " ");
      else
	size = bsprintf(buf, "%04d-", cd);
      errcode = -8000;
    }
  else if (cd == CLI_ASYNC_CODE)
    {
      size = 1; buf[0] = '+';
      errcode = cd;
    }
  else
    {
      size = bsprintf(buf, "%04d ", cd);
      errcode = 8000;
      cd = 0;	/* Final message - no more continuation lines */
    }

  c->last_reply = cd;
  va_start(args, msg);
  cnt = bvsnprintf(buf+size, sizeof(buf)-size-1, msg, args);
  va_end(args);
  if (cnt < 0)
    {
      cli_printf(c, errcode, "<line overflow>");
      return;
    }
  size += cnt;
  buf[size++] = '\n';
  if (sk_send(c->sock, buf, size) < 0)
    longjmp(c->errbuf, 1);
}

#if CLI_LOG_HOOKS
static void
cli_copy_message(cli *c)
{
  byte *p, *q, *qq;
  uint cnt = 2;

  if (c->ring_overflow)
    {
      byte buf[64];
      int n = bsprintf(buf, "<%d messages lost>\n", c->ring_overflow);
      c->ring_overflow = 0;
      sk_send(c->sock, buf, n);
    }
  p = c->ring_read;
  while (*p)
    {
      cnt++;
      p++;
      if (p == c->ring_end)
	p = c->ring_buf;
      ASSERT(p != c->ring_write);
    }
  c->async_msg_size += cnt;
  q = qq = alloca(cnt);
  *q++ = '+';
  p = c->ring_read;
  do
    {
      *q = *p++;
      if (p == c->ring_end)
	p = c->ring_buf;
    }
  while (*q++);
  c->ring_read = p;
  q[-1] = '\n';
  sk_send(c->sock, q, (qq-q));
}
#endif

static void
cli_hello(cli *c)
{
  cli_printf(c, 1, "BIRD " BIRD_VERSION " ready.");
}

_Thread_local static byte *cli_rh_pos;
_Thread_local static uint cli_rh_len;
_Thread_local static int cli_rh_trick_flag;
_Thread_local struct cli *this_cli;

/* Hack for scheduled undo notification */
extern cli *cmd_reconfig_stored_cli;

void
cli_free(cli *c)
{
#if 0
  cli_set_log_echo(c, 0, 0);
#endif
  if (c == cmd_reconfig_stored_cli)
    cmd_reconfig_stored_cli = NULL;
  rfree(c->pool);
}

static int
cli_cmd_read_hook(byte *buf, uint max, UNUSED int fd)
{
  if (!cli_rh_trick_flag)
    {
      cli_rh_trick_flag = 1;
      buf[0] = '!';
      return 1;
    }
  if (max > cli_rh_len)
    max = cli_rh_len;
  memcpy(buf, cli_rh_pos, max);
  cli_rh_pos += max;
  cli_rh_len -= max;
  return max;
}

static void
cli_command(struct cli *c, byte *buf, uint len)
{
  struct config f;
  int res;

  if (config->cli_debug > 1)
    log(L_TRACE "CLI: %s", buf);
  bzero(&f, sizeof(f));
  f.mem = c->parser_pool;
  f.pool = rp_new(c->pool, "Config");
  init_list(&f.symbols);
  cf_read_hook = cli_cmd_read_hook;
  cli_rh_pos = buf;
  cli_rh_len = len;
  cli_rh_trick_flag = 0;
  this_cli = c;
  lp_flush(c->parser_pool);
  res = cli_parse(&f);
  if (!res)
    cli_printf(c, 9001, f.err_msg);

  config_free(&f);
}

static uint
cli_rx(sock *s, byte *buf, uint size)
{
  cli *c = s->data;

#if CLI_LOG_HOOKS
  while (c->ring_read != c->ring_write &&
      c->async_msg_size < CLI_MAX_ASYNC_QUEUE)
    cli_copy_message(c);
#endif

  byte *eol = buf;
  byte *end = buf + size;
  byte *nxt = NULL;
  for (; eol < end; eol++)
    if (eol[0] == '\n')
    {
      nxt = eol+1;
      break;
    }
    else if (eol[0] == '\r' && eol+1 < end && eol[1] == '\n')
    {
      nxt = eol+2;
      break;
    }

  this_cli = c;

  if (!nxt)
  {
    cli_printf(c, 9000, "Command too long");
    return size;
  }
  else
  {
    eol[0] = 0;
    cli_command(c, buf, eol-buf);
    return nxt - buf;
  }
}

static void
cli_err(sock *s, int err)
{
  if (config->cli_debug)
    {
      if (err)
	log(L_INFO "CLI connection dropped: %s", strerror(err));
      else
	log(L_INFO "CLI connection closed");
    }
  cli_free(s->data);
}

void
cli_sock_info(sock *s, char *buf, uint len)
{
  if (s->class->rx_hook == cli_connect)
    bsnprintf(buf, len, "listening for incoming CLI connections");
  else if (s->class->rx_hook == cli_rx)
    bsnprintf(buf, len, "for active CLI");
  else
    bsnprintf(buf, len, "for CLI in some strange state");
}

static cli *
cli_new(sock *s)
{
  pool *p = rp_new(cli_pool, "CLI");
  cli *c = mb_alloc(p, sizeof(cli));

  bzero(c, sizeof(cli));
  c->pool = p;
  c->sock = s;
  c->parser_pool = lp_new_default(c->pool);
  c->show_pool = lp_new_default(c->pool);
  return c;
}

static const struct sock_class cli_sock_class = {
  .rx_hook = cli_rx,
  .rx_err = cli_err,
  .cli_info = cli_sock_info,
};

uint
cli_connect(sock *s, byte *buf UNUSED, uint size UNUSED)
{
  cli *c;

  if (config->cli_debug)
    log(L_INFO "CLI connect");
 
  s->class = &cli_sock_class;

  s->data = c = cli_new(s);
  s->pool = c->pool;		/* We need to have all the socket buffers allocated in the cli pool */

  rmove(s, c->pool);
  sk_set_rbsize(s, 1024);

  cli_hello(c);

  sk_schedule_rx(s);

  return 0;
}

#if CLI_LOG_HOOKS
/* TODO: Implement a thread-safe cli-log mechanism */
static list cli_log_hooks;
static int cli_log_inited;

void
cli_set_log_echo(cli *c, uint mask, uint size)
{
  if (c->ring_buf)
    {
      mb_free(c->ring_buf);
      c->ring_buf = c->ring_end = c->ring_read = c->ring_write = NULL;
      rem_node(&c->n);
    }
  c->log_mask = mask;
  if (mask && size)
    {
      c->ring_buf = mb_alloc(c->pool, size);
      c->ring_end = c->ring_buf + size;
      c->ring_read = c->ring_write = c->ring_buf;
      add_tail(&cli_log_hooks, &c->n);
      c->log_threshold = size / 8;
    }
  c->ring_overflow = 0;
}

void
cli_echo(uint class, byte *msg)
{
  unsigned len, free, i, l;
  cli *c;
  byte *m;

  if (!cli_log_inited || EMPTY_LIST(cli_log_hooks))
    return;
  len = strlen(msg) + 1;
  WALK_LIST(c, cli_log_hooks)
    {
      if (!(c->log_mask & (1 << class)))
	continue;
      if (c->ring_read <= c->ring_write)
	free = (c->ring_end - c->ring_buf) - (c->ring_write - c->ring_read + 1);
      else
	free = c->ring_read - c->ring_write - 1;
      if ((len > free) ||
	  (free < c->log_threshold && class < (unsigned) L_INFO[0]))
	{
	  c->ring_overflow++;
	  continue;
	}
      if (c->ring_read == c->ring_write)
	ev_schedule(c->event);
      m = msg;
      l = len;
      while (l)
	{
	  if (c->ring_read <= c->ring_write)
	    i = c->ring_end - c->ring_write;
	  else
	    i = c->ring_read - c->ring_write;
	  if (i > l)
	    i = l;
	  memcpy(c->ring_write, m, i);
	  m += i;
	  l -= i;
	  c->ring_write += i;
	  if (c->ring_write == c->ring_end)
	    c->ring_write = c->ring_buf;
	}
    }
}
#endif

/**
 * cli_init - initialize the CLI module
 *
 * This function is called during BIRD startup to initialize
 * the internal data structures of the CLI module.
 */
void
cli_init(void)
{
  cli_pool = rp_new(&root_pool, "CLI");
#if CLI_LOG_HOOKS
  init_list(&cli_log_hooks);
  cli_log_inited = 1;
#endif
}
