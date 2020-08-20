/*
 *	BIRD Socket Interface
 *
 *	(c) 1998--2004 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_SOCKET_H_
#define _BIRD_SOCKET_H_

#include <errno.h>
#include <stdatomic.h>

#include "lib/resource.h"
#include "lib/locking.h"

#ifdef HAVE_LIBSSH
#define LIBSSH_LEGACY_0_4
#include <libssh/libssh.h>
#endif

#ifdef HAVE_LIBSSH
struct ssh_sock {
    const char *username;		/* (Required) SSH user name */
    const char *server_hostkey_path;	/* (Optional) Filepath to the SSH public key of remote side, can be knownhost file */
    const char *client_privkey_path;	/* (Optional) Filepath to the SSH private key of BIRD */
    const char *subsystem;		/* (Optional) Name of SSH subsytem */
    ssh_session session;		/* Internal */
    ssh_channel channel;		/* Internal */
    int state;				/* Internal */
#define SK_SSH_CONNECT		0	/* Start state */
#define SK_SSH_SERVER_KNOWN	1	/* Internal */
#define SK_SSH_USERAUTH		2	/* Internal */
#define SK_SSH_CHANNEL		3	/* Internal */
#define SK_SSH_SESSION		4	/* Internal */
#define SK_SSH_SUBSYSTEM 	5	/* Internal */
#define SK_SSH_ESTABLISHED	6	/* Final state */
};
#endif

struct sock_rx_buf {
  uint pos;
  uint end;
  char buf[0];
};

typedef struct birdsock {
  resource r;
  pool *pool;				/* Pool where incoming connections should be allocated (for SK_xxx_PASSIVE) */
  struct proto *owner;			/* Protocol which this socket belongs to; NULL for BIRD-wide sockets */
  int type;				/* Socket type */
  int subtype;				/* Socket subtype */
  void *data;				/* User data */
  ip_addr saddr, daddr;			/* IPA_NONE = unspecified */
  const char *host;			/* Alternative to daddr, NULL = unspecified */
  uint sport, dport;			/* 0 = unspecified (for IP: protocol type) */
  int tos;				/* TOS / traffic class, -1 = default */
  int priority;				/* Local socket priority, -1 = default */
  int ttl;				/* Time To Live, -1 = default */
  u32 flags;
  struct iface *iface;			/* Interface; specify this for broad/multicast sockets */
  struct iface *vrf;			/* Related VRF instance, NULL if global */

  /* To be locked by the real owner instead */
  LOCKED_STRUCT(event_state, 
      /* rx_hook: On stream sockets (TCP, UNIX) returns number of processed bytes. Otherwise ignored. */
      uint (*rx_hook)(struct birdsock *, byte *buf, uint size);
      void (*rx_err)(struct birdsock *, int); /* errno or zero if EOF */

      _Bool (*tx_hook)(struct birdsock *);    /* returns 1 to call again */
      void (*tx_err)(struct birdsock *, int); /* errno or zero if EOF */

      void (*cli_info)(LOCKED(event_state), struct birdsock *, char *buf, uint len);	/* Write CLI info to the buf */

      list tx_chain;
      struct coro_sock *rx_coro, *tx_coro;
      uint rbsize;			/* May be changed ONLY with RX stopped or from RX hook inside */
      _Bool tx_active;			/* Set when somebody is trying to TX directly */
      _Bool closing;			/* Set when the socket is closing */
      );

  /* Information about received datagrams (UDP, RAW), valid in rx_hook */
  ip_addr faddr, laddr;			/* src (From) and dst (Local) address of the datagram */
  uint fport;				/* src port of the datagram */
  uint lifindex;			/* local interface that received the datagram */
  /* laddr and lifindex are valid only if SKF_LADDR_RX flag is set to request it */

  int af;				/* System-dependend adress family (e.g. AF_INET) */
  int fd;				/* System-dependent data */
  int rcv_ttl;				/* TTL of last received datagram */
  void *rbuf_alloc, *tbuf_alloc;
  const char *password;			/* Password for MD5 authentication */
  const char *err;			/* Error message */
  struct ssh_sock *ssh;			/* Used in SK_SSH */
} sock;

sock *sock_new(pool *);			/* Allocate new socket */
#define sk_new(X) sock_new(X)		/* Wrapper to avoid name collision with OpenSSL */

int sk_open(sock *, struct proto *);	/* Open socket */
int sk_rx_ready(sock *s);
int USE_RESULT sk_send(sock *, void *buf, uint len);		/* Send data, <0=err, >0=ok, 0=sleep */
int USE_RESULT sk_send_to(sock *, void *buf, uint len, ip_addr to, uint port); /* sk_send to given destination */
void sk_dump_all(void);

/* Schedule/Cancel rx/tx on the given socket */
void sk_schedule_rx(sock *);
void sk_cancel_rx(sock *);
void sk_schedule_tx(sock *);
void sk_cancel_tx(sock *);

/* Close and free the socket (asynchronous) */
void sk_close(sock *);

/* Resize read buffer */
void sk_set_rbsize(sock *, uint);

int sk_is_ipv4(sock *s);		/* True if socket is IPv4 */
int sk_is_ipv6(sock *s);		/* True if socket is IPv6 */

#if 0
static inline _Bool sk_tx_buffer_empty(sock *sk)
{
  return !EVENT_LOCKED_GET(sk, tx_active);
}
#endif

int sk_setup_multicast(sock *s);	/* Prepare UDP or IP socket for multicasting */
int sk_join_group(sock *s, ip_addr maddr);	/* Join multicast group on sk iface */
int sk_leave_group(sock *s, ip_addr maddr);	/* Leave multicast group on sk iface */
int sk_setup_broadcast(sock *s);
int sk_set_ttl(sock *s, int ttl);	/* Set transmit TTL for given socket */
int sk_set_min_ttl(sock *s, int ttl);	/* Set minimal accepted TTL for given socket */
int sk_set_md5_auth(sock *s, ip_addr local, ip_addr remote, int pxlen, struct iface *ifa, const char *passwd, int setkey);
int sk_set_ipv6_checksum(sock *s, int offset);
int sk_set_icmp6_filter(sock *s, int p1, int p2);
void sk_log_error(sock *s, const char *p);

extern int sk_priority_control;		/* Suggested priority for control traffic, should be sysdep define */


/* Socket flags */

#define SKF_V6ONLY	0x02	/* Use IPV6_V6ONLY socket option */
#define SKF_LADDR_RX	0x04	/* Report local address for RX packets */
#define SKF_TTL_RX	0x08	/* Report TTL / Hop Limit for RX packets */
#define SKF_BIND	0x10	/* Bind datagram socket to given source address */
#define SKF_HIGH_PORT	0x20	/* Choose port from high range if possible */

#define SKF_TRUNCATED	0x200	/* Received packet was truncated, set by IO layer */
#define SKF_HDRINCL	0x400	/* Used internally */
#define SKF_PKTINFO	0x800	/* Used internally */

/*
 *	Socket types		     SA SP DA DP IF  TTL SendTo	(?=may, -=must not, *=must)
 */

#define SK_TCP_PASSIVE	0	   /* ?  *  -  -  -  ?   -	*/
#define SK_TCP_ACTIVE	1          /* ?  ?  *  *  -  ?   -	*/
#define SK_TCP		2
#define SK_UDP		3          /* ?  ?  ?  ?  ?  ?   *	*/
#define SK_IP		5          /* ?  -  ?  *  ?  ?   *	*/
#define SK_MAGIC	7	   /* Internal use by sysdep code */
#define SK_UNIX_PASSIVE	8
#define SK_UNIX		9
#define SK_SSH_ACTIVE	10         /* -  -  *  *  -  ?   -	DA = host */
#define SK_SSH		11

/*
 *	Socket subtypes
 */

#define SK_IPV4		1
#define SK_IPV6		2

/*
 * For TCP/IP sockets, Address family (IPv4 or IPv6) can be specified either
 * explicitly (SK_IPV4 or SK_IPV6) or implicitly (based on saddr, daddr). But
 * these specifications must be consistent.
 *
 * For SK_UDP or SK_IP sockets setting DA/DP allows to use sk_send(), otherwise
 * sk_send_to() must be used.
 *
 * For SK_IP sockets setting DP specifies protocol number, which is used for
 * both receiving and sending.
 *
 * For multicast on SK_UDP or SK_IP sockets set IF and TTL, call
 * sk_setup_multicast() to enable multicast on that socket, and then use
 * sk_join_group() and sk_leave_group() to manage a set of received multicast
 * groups.
 *
 * For datagram (SK_UDP, SK_IP) sockets, there are two ways to handle source
 * address. The socket could be bound to it using bind() syscall, but that also
 * forbids the reception of multicast packets, or the address could be set on
 * per-packet basis using platform dependent options (but these are not
 * available in some corner cases). The first way is used when SKF_BIND is
 * specified, the second way is used otherwise.
 */

#endif
