/*
 *	BIRD Internet Routing Daemon -- Command-Line Interface
 *
 *	(c) 1999--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_CLI_H_
#define _BIRD_CLI_H_

#include "lib/resource.h"
#include "lib/socket.h"
#include "lib/event.h"

#include <setjmp.h>

#define CLI_RX_BUF_SIZE 4096
#define CLI_TX_BUF_SIZE 4096
#define CLI_MAX_ASYNC_QUEUE 4096

#define CLI_MSG_SIZE 500
#define CLI_LINE_SIZE 512

typedef struct cli {
  node n;				/* Node in list of all log hooks */
  pool *pool;
  sock *sock;				/* Socket */
  int last_reply;
  int restricted;			/* CLI is restricted to read-only commands */
  struct linpool *parser_pool;		/* Pool used during parsing */
  struct linpool *show_pool;		/* Pool used during route show */
  jmp_buf errbuf;			/* Longjmp buffer for CLI write errors */
#if 0
  byte *ring_buf;			/* Ring buffer for asynchronous messages */
  byte *ring_end, *ring_read, *ring_write;	/* Pointers to the ring buffer */
  uint ring_overflow;			/* Counter of ring overflows */
  uint log_mask;			/* Mask of allowed message levels */
  uint log_threshold;			/* When free < log_threshold, store only important messages */
#endif
} cli;

#define CLI_TRY(c) if (!setjmp((c)->errbuf)) {
#define CLI_EXCEPT(c) memset(&(c)->errbuf, 0, sizeof(jmp_buf)); } else

extern pool *cli_pool;
extern _Thread_local struct cli *this_cli;		/* Used during parsing */

#define CLI_ASYNC_CODE 10000

/* Functions to be called by command handlers */

void cli_printf(cli *, int, const char *, ...);
#define cli_msg(x...) cli_printf(this_cli, x)
#if 0
void cli_set_log_echo(cli *, uint mask, uint size);
#endif

static inline void cli_separator(cli *c)
{ if (c->last_reply) cli_printf(c, -c->last_reply, ""); };

/* Functions provided to sysdep layer */

void cli_init(void);
uint cli_connect(sock *s, byte *buf UNUSED, uint size UNUSED);
#if 0
void cli_echo(uint class, byte *msg);
#endif

static inline int cli_access_restricted(void)
{
  if (this_cli && this_cli->restricted)
    return (cli_printf(this_cli, 8007, "Access denied"), 1);
  else
    return 0;
}

/* Functions provided by sysdep layer */

int cli_get_command(cli *);

#endif
