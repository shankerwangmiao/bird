/*
 *	BIRD Internet Routing Daemon -- Unix I/O
 *
 *	(c) 1998--2004 Martin Mares <mj@ucw.cz>
 *      (c) 2004       Ondrej Filip <feela@network.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/* Unfortunately, some glibc versions hide parts of RFC 3542 API
   if _GNU_SOURCE is not defined. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#undef LOCAL_DEBUG

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>

#include "nest/bird.h"
#include "lib/lists.h"
#include "lib/resource.h"
#include "lib/socket.h"
#include "lib/event.h"
#include "lib/timer.h"
#include "lib/string.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "conf/conf.h"

#include "sysdep/unix/unix.h"
#include CONFIG_INCLUDE_SYSIO_H

/* Maximum number of calls of tx handler for one socket in one
 * poll iteration. Should be small enough to not monopolize CPU by
 * one protocol instance.
 */
#define MAX_STEPS 4

/* Maximum number of calls of rx handler for all sockets in one poll
   iteration. RX callbacks are often much more costly so we limit
   this to gen small latencies */
#define MAX_RX_STEPS 4


/*
 *	Tracked Files
 */

struct rfile {
  resource r;
  FILE *f;
};

static void
rf_free(resource *r)
{
  struct rfile *a = (struct rfile *) r;

  fclose(a->f);
}

static void
rf_dump(resource *r)
{
  struct rfile *a = (struct rfile *) r;

  debug("(FILE *%p)\n", a->f);
}

static struct resclass rf_class = {
  "FILE",
  sizeof(struct rfile),
  rf_free,
  rf_dump,
  NULL,
  NULL
};

struct rfile *
rf_open(pool *p, const char *name, const char *mode)
{
  FILE *f = fopen(name, mode);

  if (!f)
    return NULL;

  struct rfile *r = ralloc(p, &rf_class);
  r->f = f;
  return r;
}

void *
rf_file(struct rfile *f)
{
  return f->f;
}

int
rf_fileno(struct rfile *f)
{
  return fileno(f->f);
}


/*
 *	Time clock
 */

btime boot_time;

void
times_init(struct timeloop *loop)
{
  struct timespec ts;
  int rv;

  rv = clock_gettime(CLOCK_MONOTONIC, &ts);
  if (rv < 0)
    die("Monotonic clock is missing");

  if ((ts.tv_sec < 0) || (((u64) ts.tv_sec) > ((u64) 1 << 40)))
    log(L_WARN "Monotonic clock is crazy");

  atomic_store_explicit(&loop->last_time__atomic, ts.tv_sec S + ts.tv_nsec NS, memory_order_relaxed);
  atomic_store_explicit(&loop->real_time__atomic, 0, memory_order_relaxed);

  if (pipe2(loop->fds, O_NONBLOCK) < 0)
    die("Couldn't open timer pipe");
}

btime
times_update(btime current)
{
  struct timespec ts;
  int rv;

  rv = clock_gettime(CLOCK_MONOTONIC, &ts);
  if (rv < 0)
    die("clock_gettime: %m");

  btime new_time = ts.tv_sec S + ts.tv_nsec NS;

  if (new_time < current)
    log(L_ERR "Monotonic clock is broken");

  return new_time;
  /*
  loop->last_time = new_time;
  loop->real_time = 0;
  */
}

btime
times_fetch_real_time(void)
{
  struct timespec ts;
  int rv;

  rv = clock_gettime(CLOCK_REALTIME, &ts);
  if (rv < 0)
    die("clock_gettime: %m");

  return ts.tv_sec S + ts.tv_nsec NS;
}


/**
 * DOC: Sockets
 *
 * Socket resources represent network connections. Their data structure (&socket)
 * contains a lot of fields defining the exact type of the socket, the local and
 * remote addresses and ports, pointers to socket buffers and finally pointers to
 * hook functions to be called when new data have arrived to the receive buffer
 * (@rx_hook), when the contents of the transmit buffer have been transmitted
 * (@tx_hook) and when an error or connection close occurs (@err_hook).
 *
 * Freeing of sockets from inside socket hooks is perfectly safe.
 */

#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif

#ifndef SOL_IPV6
#define SOL_IPV6 IPPROTO_IPV6
#endif

#ifndef SOL_ICMPV6
#define SOL_ICMPV6 IPPROTO_ICMPV6
#endif


/*
 *	Sockaddr helper functions
 */

static inline int UNUSED sockaddr_length(int af)
{ return (af == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6); }

static inline void
sockaddr_fill4(struct sockaddr_in *sa, ip_addr a, uint port)
{
  memset(sa, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
  sa->sin_len = sizeof(struct sockaddr_in);
#endif
  sa->sin_family = AF_INET;
  sa->sin_port = htons(port);
  sa->sin_addr = ipa_to_in4(a);
}

static inline void
sockaddr_fill6(struct sockaddr_in6 *sa, ip_addr a, struct iface *ifa, uint port)
{
  memset(sa, 0, sizeof(struct sockaddr_in6));
#ifdef SIN6_LEN
  sa->sin6_len = sizeof(struct sockaddr_in6);
#endif
  sa->sin6_family = AF_INET6;
  sa->sin6_port = htons(port);
  sa->sin6_flowinfo = 0;
  sa->sin6_addr = ipa_to_in6(a);

  if (ifa && ipa_is_link_local(a))
    sa->sin6_scope_id = ifa->index;
}

void
sockaddr_fill(sockaddr *sa, int af, ip_addr a, struct iface *ifa, uint port)
{
  if (af == AF_INET)
    sockaddr_fill4((struct sockaddr_in *) sa, a, port);
  else if (af == AF_INET6)
    sockaddr_fill6((struct sockaddr_in6 *) sa, a, ifa, port);
  else
    bug("Unknown AF");
}

static inline void
sockaddr_read4(struct sockaddr_in *sa, ip_addr *a, uint *port)
{
  *port = ntohs(sa->sin_port);
  *a = ipa_from_in4(sa->sin_addr);
}

static inline void
sockaddr_read6(struct sockaddr_in6 *sa, ip_addr *a, struct iface **ifa, uint *port)
{
  *port = ntohs(sa->sin6_port);
  *a = ipa_from_in6(sa->sin6_addr);

  if (ifa && ipa_is_link_local(*a))
    *ifa = if_find_by_index(sa->sin6_scope_id);
}

int
sockaddr_read(sockaddr *sa, int af, ip_addr *a, struct iface **ifa, uint *port)
{
  if (sa->sa.sa_family != af)
    goto fail;

  if (af == AF_INET)
    sockaddr_read4((struct sockaddr_in *) sa, a, port);
  else if (af == AF_INET6)
    sockaddr_read6((struct sockaddr_in6 *) sa, a, ifa, port);
  else
    goto fail;

  return 0;

 fail:
  *a = IPA_NONE;
  *port = 0;
  return -1;
}


/*
 *	IPv6 multicast syscalls
 */

/* Fortunately standardized in RFC 3493 */

#define INIT_MREQ6(maddr,ifa) \
  { .ipv6mr_multiaddr = ipa_to_in6(maddr), .ipv6mr_interface = ifa->index }

static inline int
sk_setup_multicast6(sock *s)
{
  int index = s->iface->index;
  int ttl = s->ttl;
  int n = 0;

  if (setsockopt(s->fd, SOL_IPV6, IPV6_MULTICAST_IF, &index, sizeof(index)) < 0)
    ERR("IPV6_MULTICAST_IF");

  if (setsockopt(s->fd, SOL_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl)) < 0)
    ERR("IPV6_MULTICAST_HOPS");

  if (setsockopt(s->fd, SOL_IPV6, IPV6_MULTICAST_LOOP, &n, sizeof(n)) < 0)
    ERR("IPV6_MULTICAST_LOOP");

  return 0;
}

static inline int
sk_join_group6(sock *s, ip_addr maddr)
{
  struct ipv6_mreq mr = INIT_MREQ6(maddr, s->iface);

  if (setsockopt(s->fd, SOL_IPV6, IPV6_JOIN_GROUP, &mr, sizeof(mr)) < 0)
    ERR("IPV6_JOIN_GROUP");

  return 0;
}

static inline int
sk_leave_group6(sock *s, ip_addr maddr)
{
  struct ipv6_mreq mr = INIT_MREQ6(maddr, s->iface);

  if (setsockopt(s->fd, SOL_IPV6, IPV6_LEAVE_GROUP, &mr, sizeof(mr)) < 0)
    ERR("IPV6_LEAVE_GROUP");

  return 0;
}


/*
 *	IPv6 packet control messages
 */

/* Also standardized, in RFC 3542 */

/*
 * RFC 2292 uses IPV6_PKTINFO for both the socket option and the cmsg
 * type, RFC 3542 changed the socket option to IPV6_RECVPKTINFO. If we
 * don't have IPV6_RECVPKTINFO we suppose the OS implements the older
 * RFC and we use IPV6_PKTINFO.
 */
#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif
/*
 * Same goes for IPV6_HOPLIMIT -> IPV6_RECVHOPLIMIT.
 */
#ifndef IPV6_RECVHOPLIMIT
#define IPV6_RECVHOPLIMIT IPV6_HOPLIMIT
#endif


#define CMSG6_SPACE_PKTINFO CMSG_SPACE(sizeof(struct in6_pktinfo))
#define CMSG6_SPACE_TTL CMSG_SPACE(sizeof(int))

static inline int
sk_request_cmsg6_pktinfo(sock *s)
{
  int y = 1;

  if (setsockopt(s->fd, SOL_IPV6, IPV6_RECVPKTINFO, &y, sizeof(y)) < 0)
    ERR("IPV6_RECVPKTINFO");

  return 0;
}

static inline int
sk_request_cmsg6_ttl(sock *s)
{
  int y = 1;

  if (setsockopt(s->fd, SOL_IPV6, IPV6_RECVHOPLIMIT, &y, sizeof(y)) < 0)
    ERR("IPV6_RECVHOPLIMIT");

  return 0;
}

static inline void
sk_process_cmsg6_pktinfo(sock *s, struct cmsghdr *cm)
{
  if (cm->cmsg_type == IPV6_PKTINFO)
  {
    struct in6_pktinfo *pi = (struct in6_pktinfo *) CMSG_DATA(cm);
    s->laddr = ipa_from_in6(pi->ipi6_addr);
    s->lifindex = pi->ipi6_ifindex;
  }
}

static inline void
sk_process_cmsg6_ttl(sock *s, struct cmsghdr *cm)
{
  if (cm->cmsg_type == IPV6_HOPLIMIT)
    s->rcv_ttl = * (int *) CMSG_DATA(cm);
}

static inline void
sk_prepare_cmsgs6(sock *s, struct msghdr *msg, void *cbuf, size_t cbuflen)
{
  struct cmsghdr *cm;
  struct in6_pktinfo *pi;
  int controllen = 0;

  msg->msg_control = cbuf;
  msg->msg_controllen = cbuflen;

  cm = CMSG_FIRSTHDR(msg);
  cm->cmsg_level = SOL_IPV6;
  cm->cmsg_type = IPV6_PKTINFO;
  cm->cmsg_len = CMSG_LEN(sizeof(*pi));
  controllen += CMSG_SPACE(sizeof(*pi));

  pi = (struct in6_pktinfo *) CMSG_DATA(cm);
  pi->ipi6_ifindex = s->iface ? s->iface->index : 0;
  pi->ipi6_addr = ipa_to_in6(s->saddr);

  msg->msg_controllen = controllen;
}


/*
 *	Miscellaneous socket syscalls
 */

static inline int
sk_set_ttl4(sock *s, int ttl)
{
  if (setsockopt(s->fd, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
    ERR("IP_TTL");

  return 0;
}

static inline int
sk_set_ttl6(sock *s, int ttl)
{
  if (setsockopt(s->fd, SOL_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)) < 0)
    ERR("IPV6_UNICAST_HOPS");

  return 0;
}

static inline int
sk_set_tos4(sock *s, int tos)
{
  if (setsockopt(s->fd, SOL_IP, IP_TOS, &tos, sizeof(tos)) < 0)
    ERR("IP_TOS");

  return 0;
}

static inline int
sk_set_tos6(sock *s, int tos)
{
  if (setsockopt(s->fd, SOL_IPV6, IPV6_TCLASS, &tos, sizeof(tos)) < 0)
    ERR("IPV6_TCLASS");

  return 0;
}

static inline int
sk_set_high_port(sock *s UNUSED)
{
  /* Port range setting is optional, ignore it if not supported */

#ifdef IP_PORTRANGE
  if (sk_is_ipv4(s))
  {
    int range = IP_PORTRANGE_HIGH;
    if (setsockopt(s->fd, SOL_IP, IP_PORTRANGE, &range, sizeof(range)) < 0)
      ERR("IP_PORTRANGE");
  }
#endif

#ifdef IPV6_PORTRANGE
  if (sk_is_ipv6(s))
  {
    int range = IPV6_PORTRANGE_HIGH;
    if (setsockopt(s->fd, SOL_IPV6, IPV6_PORTRANGE, &range, sizeof(range)) < 0)
      ERR("IPV6_PORTRANGE");
  }
#endif

  return 0;
}


/*
 *	Public socket functions
 */

/**
 * sk_setup_multicast - enable multicast for given socket
 * @s: socket
 *
 * Prepare transmission of multicast packets for given datagram socket.
 * The socket must have defined @iface.
 *
 * Result: 0 for success, -1 for an error.
 */

int
sk_setup_multicast(sock *s)
{
  ASSERT(s->iface);

  if (sk_is_ipv4(s))
    return sk_setup_multicast4(s);
  else
    return sk_setup_multicast6(s);
}

/**
 * sk_join_group - join multicast group for given socket
 * @s: socket
 * @maddr: multicast address
 *
 * Join multicast group for given datagram socket and associated interface.
 * The socket must have defined @iface.
 *
 * Result: 0 for success, -1 for an error.
 */

int
sk_join_group(sock *s, ip_addr maddr)
{
  if (sk_is_ipv4(s))
    return sk_join_group4(s, maddr);
  else
    return sk_join_group6(s, maddr);
}

/**
 * sk_leave_group - leave multicast group for given socket
 * @s: socket
 * @maddr: multicast address
 *
 * Leave multicast group for given datagram socket and associated interface.
 * The socket must have defined @iface.
 *
 * Result: 0 for success, -1 for an error.
 */

int
sk_leave_group(sock *s, ip_addr maddr)
{
  if (sk_is_ipv4(s))
    return sk_leave_group4(s, maddr);
  else
    return sk_leave_group6(s, maddr);
}

/**
 * sk_setup_broadcast - enable broadcast for given socket
 * @s: socket
 *
 * Allow reception and transmission of broadcast packets for given datagram
 * socket. The socket must have defined @iface. For transmission, packets should
 * be send to @brd address of @iface.
 *
 * Result: 0 for success, -1 for an error.
 */

int
sk_setup_broadcast(sock *s)
{
  int y = 1;

  if (setsockopt(s->fd, SOL_SOCKET, SO_BROADCAST, &y, sizeof(y)) < 0)
    ERR("SO_BROADCAST");

  return 0;
}

/**
 * sk_set_ttl - set transmit TTL for given socket
 * @s: socket
 * @ttl: TTL value
 *
 * Set TTL for already opened connections when TTL was not set before. Useful
 * for accepted connections when different ones should have different TTL.
 *
 * Result: 0 for success, -1 for an error.
 */

int
sk_set_ttl(sock *s, int ttl)
{
  s->ttl = ttl;

  if (sk_is_ipv4(s))
    return sk_set_ttl4(s, ttl);
  else
    return sk_set_ttl6(s, ttl);
}

/**
 * sk_set_min_ttl - set minimal accepted TTL for given socket
 * @s: socket
 * @ttl: TTL value
 *
 * Set minimal accepted TTL for given socket. Can be used for TTL security.
 * implementations.
 *
 * Result: 0 for success, -1 for an error.
 */

int
sk_set_min_ttl(sock *s, int ttl)
{
  if (sk_is_ipv4(s))
    return sk_set_min_ttl4(s, ttl);
  else
    return sk_set_min_ttl6(s, ttl);
}

#if 0
/**
 * sk_set_md5_auth - add / remove MD5 security association for given socket
 * @s: socket
 * @local: IP address of local side
 * @remote: IP address of remote side
 * @ifa: Interface for link-local IP address
 * @passwd: Password used for MD5 authentication
 * @setkey: Update also system SA/SP database
 *
 * In TCP MD5 handling code in kernel, there is a set of security associations
 * used for choosing password and other authentication parameters according to
 * the local and remote address. This function is useful for listening socket,
 * for active sockets it may be enough to set s->password field.
 *
 * When called with passwd != NULL, the new pair is added,
 * When called with passwd == NULL, the existing pair is removed.
 *
 * Note that while in Linux, the MD5 SAs are specific to socket, in BSD they are
 * stored in global SA/SP database (but the behavior also must be enabled on
 * per-socket basis). In case of multiple sockets to the same neighbor, the
 * socket-specific state must be configured for each socket while global state
 * just once per src-dst pair. The @setkey argument controls whether the global
 * state (SA/SP database) is also updated.
 *
 * Result: 0 for success, -1 for an error.
 */

int
sk_set_md5_auth(sock *s, ip_addr local, ip_addr remote, struct iface *ifa, char *passwd, int setkey)
{ DUMMY; }
#endif

/**
 * sk_set_ipv6_checksum - specify IPv6 checksum offset for given socket
 * @s: socket
 * @offset: offset
 *
 * Specify IPv6 checksum field offset for given raw IPv6 socket. After that, the
 * kernel will automatically fill it for outgoing packets and check it for
 * incoming packets. Should not be used on ICMPv6 sockets, where the position is
 * known to the kernel.
 *
 * Result: 0 for success, -1 for an error.
 */

int
sk_set_ipv6_checksum(sock *s, int offset)
{
  if (setsockopt(s->fd, SOL_IPV6, IPV6_CHECKSUM, &offset, sizeof(offset)) < 0)
    ERR("IPV6_CHECKSUM");

  return 0;
}

int
sk_set_icmp6_filter(sock *s, int p1, int p2)
{
  /* a bit of lame interface, but it is here only for Radv */
  struct icmp6_filter f;

  ICMP6_FILTER_SETBLOCKALL(&f);
  ICMP6_FILTER_SETPASS(p1, &f);
  ICMP6_FILTER_SETPASS(p2, &f);

  if (setsockopt(s->fd, SOL_ICMPV6, ICMP6_FILTER, &f, sizeof(f)) < 0)
    ERR("ICMP6_FILTER");

  return 0;
}

void
sk_log_error(sock *s, const char *p)
{
  log(L_ERR "%s: Socket error: %s%#m", p, s->err);
}


/*
 *	Actual struct birdsock code
 */

#ifdef HAVE_LIBSSH
static void
sk_ssh_free(sock *s)
{
  struct ssh_sock *ssh = s->ssh;

  if (s->ssh == NULL)
    return;

  s->ssh = NULL;

  if (ssh->channel)
  {
    if (ssh_channel_is_open(ssh->channel))
      ssh_channel_close(ssh->channel);
    ssh_channel_free(ssh->channel);
    ssh->channel = NULL;
  }

  if (ssh->session)
  {
    ssh_disconnect(ssh->session);
    ssh_free(ssh->session);
    ssh->session = NULL;
  }
}
#endif

void
sk_close_fd(sock *s)
{
  if (s->fd < 0)
    return;

  if (s->type != SK_SSH && s->type != SK_SSH_ACTIVE)
    close(s->fd);

  s->fd = -1;
}

static void
sk_free(resource *r)
{
  sock *s = (sock *) r;

#ifdef HAVE_LIBSSH
  if (s->type == SK_SSH || s->type == SK_SSH_ACTIVE)
    sk_ssh_free(s);
#endif

  EVENT_LOCKED_NOFAIL {
    AUTO_TYPE su = UNLOCKED_STRUCT(event_state, s);
    ASSERT_DIE(su->tx_coro == NULL);
    ASSERT_DIE(su->rx_coro == NULL);
  }

  sk_close_fd(s);
}

struct coroutine *coro_get_current(void);

char *sk_type_names[] = { "TCP<", "TCP>", "TCP", "UDP", NULL, "IP", NULL, "MAGIC", "UNIX<", "UNIX", "SSH>", "SSH", "DEL!" };

static void
sk_dump(resource *r)
{
  sock *s = (sock *) r;

  debug("(%s, ud=%p, sa=%I, sp=%d, da=%I, dp=%d, tos=%d, ttl=%d, if=%s)\n",
	sk_type_names[s->type],
	s->data,
	s->saddr,
	s->sport,
	s->daddr,
	s->dport,
	s->tos,
	s->ttl,
	s->iface ? s->iface->name : "none");
}

static struct resclass sk_class = {
  "Socket",
  sizeof(sock),
  sk_free,
  sk_dump,
  NULL,
  NULL
};

/**
 * sk_new - create a socket
 * @p: pool
 *
 * This function creates a new socket resource. If you want to use it,
 * you need to fill in all the required fields of the structure and
 * call sk_open() to do the actual opening of the socket.
 *
 * The real function name is sock_new(), sk_new() is a macro wrapper
 * to avoid collision with OpenSSL.
 */
sock *
sock_new(pool *p)
{
  sock *s = ralloc(p, &sk_class);
  s->pool = p;
  // s->saddr = s->daddr = IPA_NONE;
  s->tos = s->priority = s->ttl = -1;
  s->fd = -1;
  return s;
}

static int
sk_setup(sock *s)
{
  int y = 1;
  int fd = s->fd;

  if (s->type == SK_SSH_ACTIVE)
    return 0;

  if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
    ERR("O_NONBLOCK");

  if (!s->af)
    return 0;

  if (ipa_nonzero(s->saddr) && !(s->flags & SKF_BIND))
    s->flags |= SKF_PKTINFO;

#ifdef CONFIG_USE_HDRINCL
  if (sk_is_ipv4(s) && (s->type == SK_IP) && (s->flags & SKF_PKTINFO))
  {
    s->flags &= ~SKF_PKTINFO;
    s->flags |= SKF_HDRINCL;
    if (setsockopt(fd, SOL_IP, IP_HDRINCL, &y, sizeof(y)) < 0)
      ERR("IP_HDRINCL");
  }
#endif

  if (s->vrf && !s->iface)
  {
    /* Bind socket to associated VRF interface.
       This is Linux-specific, but so is SO_BINDTODEVICE. */
#ifdef SO_BINDTODEVICE
    struct ifreq ifr = {};
    strcpy(ifr.ifr_name, s->vrf->name);
    if (setsockopt(s->fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0)
      ERR("SO_BINDTODEVICE");
#endif
  }

  if (s->iface)
  {
#ifdef SO_BINDTODEVICE
    struct ifreq ifr = {};
    strcpy(ifr.ifr_name, s->iface->name);
    if (setsockopt(s->fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0)
      ERR("SO_BINDTODEVICE");
#endif

#ifdef CONFIG_UNIX_DONTROUTE
    if (setsockopt(s->fd, SOL_SOCKET, SO_DONTROUTE, &y, sizeof(y)) < 0)
      ERR("SO_DONTROUTE");
#endif
  }

  if (sk_is_ipv4(s))
  {
    if (s->flags & SKF_LADDR_RX)
      if (sk_request_cmsg4_pktinfo(s) < 0)
	return -1;

    if (s->flags & SKF_TTL_RX)
      if (sk_request_cmsg4_ttl(s) < 0)
	return -1;

    if ((s->type == SK_UDP) || (s->type == SK_IP))
      if (sk_disable_mtu_disc4(s) < 0)
	return -1;

    if (s->ttl >= 0)
      if (sk_set_ttl4(s, s->ttl) < 0)
	return -1;

    if (s->tos >= 0)
      if (sk_set_tos4(s, s->tos) < 0)
	return -1;
  }

  if (sk_is_ipv6(s))
  {
    if ((s->type == SK_TCP_PASSIVE) || (s->type == SK_TCP_ACTIVE) || (s->type == SK_UDP))
      if (setsockopt(fd, SOL_IPV6, IPV6_V6ONLY, &y, sizeof(y)) < 0)
	ERR("IPV6_V6ONLY");

    if (s->flags & SKF_LADDR_RX)
      if (sk_request_cmsg6_pktinfo(s) < 0)
	return -1;

    if (s->flags & SKF_TTL_RX)
      if (sk_request_cmsg6_ttl(s) < 0)
	return -1;

    if ((s->type == SK_UDP) || (s->type == SK_IP))
      if (sk_disable_mtu_disc6(s) < 0)
	return -1;

    if (s->ttl >= 0)
      if (sk_set_ttl6(s, s->ttl) < 0)
	return -1;

    if (s->tos >= 0)
      if (sk_set_tos6(s, s->tos) < 0)
	return -1;
  }

  /* Must be after sk_set_tos4() as setting ToS on Linux also mangles priority */
  if (s->priority >= 0)
    if (sk_set_priority(s, s->priority) < 0)
      return -1;

  return 0;
}

#define CALL_NOLOCK(s)	((s)->flags & SKF_NOLOCK)

#define THE_BIRD_LOCKED_CALL(s, what) ({ \
    if (CALL_NOLOCK(s)) what; \
    else THE_BIRD_LOCKED({CANCEL_ACTION;}) what; \
    })

#define CALL_ERR_TBL(s, hook, e) ({ \
    if ((s)->class->hook##_err) (s)->class->hook##_err((s), e); })
    
#define CALL_ERR(s, hook, e, tbl) ({ \
    if (tbl || CALL_NOLOCK(s)) CALL_ERR_TBL(s, hook, e); \
    else THE_BIRD_LOCKED({CANCEL_ACTION;}) CALL_ERR_TBL(s, hook, e); })

#define CALL_RX_ERR(s, arg, tbl) CALL_ERR(s, rx, arg, tbl)
#define CALL_TX_ERR(s, arg, tbl) CALL_ERR(s, tx, arg, tbl)

#define CALL_RX_HOOK(s, buf_) ((s)->class->rx_hook((s), buf_->buf, buf_->pos))

#define CALL_TX_HOOK(s) ((s)->class->tx_hook((s)))

#define CALL_TX_HOOK_IF_EXISTS(s) (((s)->class->tx_hook) ? CALL_TX_HOOK((s)) : 0 )

static void
sk_tcp_connected(sock *s)
{
  sockaddr sa;
  int sa_len = sizeof(sa);

  if ((getsockname(s->fd, &sa.sa, &sa_len) < 0) ||
      (sockaddr_read(&sa, s->af, &s->saddr, &s->iface, &s->sport) < 0))
    log(L_WARN "SOCK: Cannot get local IP address for TCP>");

  s->type = SK_TCP;
}

#define CANCEL_ACTION return 0

static int
sk_passive_connected(sock *s, int type)
{
  sockaddr loc_sa, rem_sa;
  int loc_sa_len = sizeof(loc_sa);
  int rem_sa_len = sizeof(rem_sa);

  int fd = accept(s->fd, ((type == SK_TCP) ? &rem_sa.sa : NULL), &rem_sa_len);
  if (fd < 0)
  {
    if ((errno != EINTR) && (errno != EAGAIN))
      CALL_RX_ERR(s, errno, 0);
    return 0;
  }

  sock *t = sk_new(s->pool);
  t->type = type;
  t->data = s->data;
  t->af = s->af;
  t->fd = fd;
  t->ttl = s->ttl;
  t->tos = s->tos;
  t->vrf = s->vrf;

  EVENT_LOCKED_INIT_LOCK(t);
  init_list(&t->LOCKED_STRUCT_NAME(event_state).tx_chain);
  init_list(&t->LOCKED_STRUCT_NAME(event_state).used_tx_bufs);

  if (type == SK_TCP)
  {
    if ((getsockname(fd, &loc_sa.sa, &loc_sa_len) < 0) ||
	(sockaddr_read(&loc_sa, s->af, &t->saddr, &t->iface, &t->sport) < 0))
      log(L_WARN "SOCK: Cannot get local IP address for TCP<");

    if (sockaddr_read(&rem_sa, s->af, &t->daddr, &t->iface, &t->dport) < 0)
      log(L_WARN "SOCK: Cannot get remote IP address for TCP<");
  }

  if (sk_setup(t) < 0)
  {
    /* FIXME: Call err_hook instead ? */
    log(L_ERR "SOCK: Incoming connection: %s%#m", t->err);

    /* FIXME: handle it better in rfree() */
    close(t->fd);
    t->fd = -1;
    rfree(t);
    return 1;
  }

  s->class->rx_hook(t, NULL, 0);
  return 1;
}

#undef CANCEL_ACTION

#ifdef HAVE_LIBSSH
/*
 * Return SSH_OK or SSH_AGAIN or SSH_ERROR
 */
static int
sk_ssh_connect(sock *s)
{
  s->fd = ssh_get_fd(s->ssh->session);

  /* Big fall thru automata */
  switch (s->ssh->state)
  {
  case SK_SSH_CONNECT:
  {
    switch (ssh_connect(s->ssh->session))
    {
    case SSH_AGAIN:
      /* A quick look into libSSH shows that ssh_get_fd() should return non-(-1)
       * after SSH_AGAIN is returned by ssh_connect(). This is however nowhere
       * documented but our code relies on that.
       */
      return SSH_AGAIN;

    case SSH_OK:
      break;

    default:
      return SSH_ERROR;
    }
  } /* fallthrough */

  case SK_SSH_SERVER_KNOWN:
  {
    s->ssh->state = SK_SSH_SERVER_KNOWN;

    if (s->ssh->server_hostkey_path)
    {
      int server_identity_is_ok = 1;

      /* Check server identity */
      switch (ssh_is_server_known(s->ssh->session))
      {
#define LOG_WARN_ABOUT_SSH_SERVER_VALIDATION(s,msg,args...) log(L_WARN "SSH Identity %s@%s:%u: " msg, (s)->ssh->username, (s)->host, (s)->dport, ## args);
      case SSH_SERVER_KNOWN_OK:
	/* The server is known and has not changed. */
	break;

      case SSH_SERVER_NOT_KNOWN:
	LOG_WARN_ABOUT_SSH_SERVER_VALIDATION(s, "The server is unknown, its public key was not found in the known host file %s", s->ssh->server_hostkey_path);
	break;

      case SSH_SERVER_KNOWN_CHANGED:
	LOG_WARN_ABOUT_SSH_SERVER_VALIDATION(s, "The server key has changed. Either you are under attack or the administrator changed the key.");
	server_identity_is_ok = 0;
	break;

      case SSH_SERVER_FILE_NOT_FOUND:
	LOG_WARN_ABOUT_SSH_SERVER_VALIDATION(s, "The known host file %s does not exist", s->ssh->server_hostkey_path);
	server_identity_is_ok = 0;
	break;

      case SSH_SERVER_ERROR:
	LOG_WARN_ABOUT_SSH_SERVER_VALIDATION(s, "Some error happened");
	server_identity_is_ok = 0;
	break;

      case SSH_SERVER_FOUND_OTHER:
	LOG_WARN_ABOUT_SSH_SERVER_VALIDATION(s, "The server gave use a key of a type while we had an other type recorded. " \
					     "It is a possible attack.");
	server_identity_is_ok = 0;
	break;
      }

      if (!server_identity_is_ok)
	return SSH_ERROR;
    }
  } /* fallthrough */

  case SK_SSH_USERAUTH:
  {
    s->ssh->state = SK_SSH_USERAUTH;
    switch (ssh_userauth_publickey_auto(s->ssh->session, NULL, NULL))
    {
    case SSH_AUTH_AGAIN:
      return SSH_AGAIN;

    case SSH_AUTH_SUCCESS:
      break;

    default:
      return SSH_ERROR;
    }
  } /* fallthrough */

  case SK_SSH_CHANNEL:
  {
    s->ssh->state = SK_SSH_CHANNEL;
    s->ssh->channel = ssh_channel_new(s->ssh->session);
    if (s->ssh->channel == NULL)
      return SSH_ERROR;
  } /* fallthrough */

  case SK_SSH_SESSION:
  {
    s->ssh->state = SK_SSH_SESSION;
    switch (ssh_channel_open_session(s->ssh->channel))
    {
    case SSH_AGAIN:
      return SSH_AGAIN;

    case SSH_OK:
      break;

    default:
      return SSH_ERROR;
    }
  } /* fallthrough */

  case SK_SSH_SUBSYSTEM:
  {
    s->ssh->state = SK_SSH_SUBSYSTEM;
    if (s->ssh->subsystem)
    {
      switch (ssh_channel_request_subsystem(s->ssh->channel, s->ssh->subsystem))
      {
      case SSH_AGAIN:
	return SSH_AGAIN;

      case SSH_OK:
	break;

      default:
	return SSH_ERROR;
      }
    }
  } /* fallthrough */

  case SK_SSH_ESTABLISHED:
    s->ssh->state = SK_SSH_ESTABLISHED;
  }

  return SSH_OK;
}

/*
 * Return file descriptor number if success
 * Return -1 if failed
 */
static int
sk_open_ssh(sock *s)
{
  if (!s->ssh)
    bug("sk_open() sock->ssh is not allocated");

  ssh_session sess = ssh_new();
  if (sess == NULL)
    ERR2("Cannot create a ssh session");
  s->ssh->session = sess;

  const int verbosity = SSH_LOG_NOLOG;
  ssh_options_set(sess, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
  ssh_options_set(sess, SSH_OPTIONS_HOST, s->host);
  ssh_options_set(sess, SSH_OPTIONS_PORT, &(s->dport));
  /* TODO: Add SSH_OPTIONS_BINDADDR */
  ssh_options_set(sess, SSH_OPTIONS_USER, s->ssh->username);

  if (s->ssh->server_hostkey_path)
    ssh_options_set(sess, SSH_OPTIONS_KNOWNHOSTS, s->ssh->server_hostkey_path);

  if (s->ssh->client_privkey_path)
    ssh_options_set(sess, SSH_OPTIONS_IDENTITY, s->ssh->client_privkey_path);

  ssh_set_blocking(sess, 0);

  switch (sk_ssh_connect(s))
  {
  case SSH_AGAIN:
    break;

  case SSH_OK:
    s->type = SK_SSH;
    CALL_TX_HOOK(s);
    break;

  case SSH_ERROR:
    ERR2(ssh_get_error(sess));
    break;
  }

  return ssh_get_fd(sess);

 err:
  return -1;
}
#endif

/**
 * sk_open - open a socket
 * @s: socket
 *
 * This function takes a socket resource created by sk_new() and
 * initialized by the user and binds a corresponding network connection
 * to it.
 *
 * Result: 0 for success, -1 for an error.
 */
int
sk_open(sock *s, struct proto *p)
{
  int af = AF_UNSPEC;
  int fd = -1;
  int do_bind = 0;
  int bind_port = 0;
  ip_addr bind_addr = IPA_NONE;
  sockaddr sa;

  if (s->type <= SK_IP)
  {
    /*
     * For TCP/IP sockets, Address family (IPv4 or IPv6) can be specified either
     * explicitly (SK_IPV4 or SK_IPV6) or implicitly (based on saddr, daddr).
     * But the specifications have to be consistent.
     */

    switch (s->subtype)
    {
    case 0:
      ASSERT(ipa_zero(s->saddr) || ipa_zero(s->daddr) ||
	     (ipa_is_ip4(s->saddr) == ipa_is_ip4(s->daddr)));
      af = (ipa_is_ip4(s->saddr) || ipa_is_ip4(s->daddr)) ? AF_INET : AF_INET6;
      break;

    case SK_IPV4:
      ASSERT(ipa_zero(s->saddr) || ipa_is_ip4(s->saddr));
      ASSERT(ipa_zero(s->daddr) || ipa_is_ip4(s->daddr));
      af = AF_INET;
      break;

    case SK_IPV6:
      ASSERT(ipa_zero(s->saddr) || !ipa_is_ip4(s->saddr));
      ASSERT(ipa_zero(s->daddr) || !ipa_is_ip4(s->daddr));
      af = AF_INET6;
      break;

    default:
      bug("Invalid subtype %d", s->subtype);
    }
  }

  switch (s->type)
  {
  case SK_TCP_ACTIVE:
  case SK_TCP_PASSIVE:
    fd = socket(af, SOCK_STREAM, IPPROTO_TCP);
    bind_port = s->sport;
    bind_addr = s->saddr;
    do_bind = bind_port || ipa_nonzero(bind_addr);
    break;

#ifdef HAVE_LIBSSH
  case SK_SSH_ACTIVE:
    fd = sk_open_ssh(s);
    break;
#endif

  case SK_UDP:
    fd = socket(af, SOCK_DGRAM, IPPROTO_UDP);
    bind_port = s->sport;
    bind_addr = (s->flags & SKF_BIND) ? s->saddr : IPA_NONE;
    do_bind = 1;
    break;

  case SK_IP:
    fd = socket(af, SOCK_RAW, s->dport);
    bind_port = 0;
    bind_addr = (s->flags & SKF_BIND) ? s->saddr : IPA_NONE;
    do_bind = ipa_nonzero(bind_addr);
    break;

  case SK_MAGIC:
    af = 0;
    fd = s->fd;
    break;

  default:
    bug("sk_open() called for invalid sock type %d", s->type);
  }

  if (fd < 0)
    ERR("socket");

  s->af = af;
  s->fd = fd;

  if (sk_setup(s) < 0)
    goto err;

  if (do_bind)
  {
    if (bind_port)
    {
      int y = 1;

      if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &y, sizeof(y)) < 0)
	ERR2("SO_REUSEADDR");

#ifdef CONFIG_NO_IFACE_BIND
      /* Workaround missing ability to bind to an iface */
      if ((s->type == SK_UDP) && s->iface && ipa_zero(bind_addr))
      {
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &y, sizeof(y)) < 0)
	  ERR2("SO_REUSEPORT");
      }
#endif
    }
    else
      if (s->flags & SKF_HIGH_PORT)
	if (sk_set_high_port(s) < 0)
	  log(L_WARN "Socket error: %s%#m", s->err);

    sockaddr_fill(&sa, s->af, bind_addr, s->iface, bind_port);
    if (bind(fd, &sa.sa, SA_LEN(sa)) < 0)
      ERR2("bind");
  }

  if (s->password)
    if (sk_set_md5_auth(s, s->saddr, s->daddr, -1, s->iface, s->password, 0) < 0)
      goto err;

  switch (s->type)
  {
  case SK_TCP_ACTIVE:
    sockaddr_fill(&sa, s->af, s->daddr, s->iface, s->dport);
    if (connect(fd, &sa.sa, SA_LEN(sa)) < 0 && 
	errno != EINTR && errno != EAGAIN && errno != EINPROGRESS &&
	errno != ECONNREFUSED && errno != EHOSTUNREACH && errno != ENETUNREACH)
      ERR2("connect");
    break;

  case SK_TCP_PASSIVE:
    if (listen(fd, 8) < 0)
      ERR2("listen");
    break;

  case SK_SSH_ACTIVE:
  case SK_MAGIC:
    break;
  }

  s->owner = p;

  EVENT_LOCKED_INIT_LOCK(s);
  init_list(&s->LOCKED_STRUCT_NAME(event_state).tx_chain);
  init_list(&s->LOCKED_STRUCT_NAME(event_state).used_tx_bufs);

  if (s->type == SK_TCP_ACTIVE)
    sk_schedule_tx(s);

  return 0;

err:
  close(fd);
  s->fd = -1;
  return -1;
}

int
sk_open_unix(sock *s, char *name)
{
  struct sockaddr_un sa;
  int fd;

  /* We are sloppy during error (leak fd and not set s->err), but we die anyway */

  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;

  if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
    return -1;

  /* Path length checked in test_old_bird() but we may need unix sockets for other reasons in future */
  ASSERT_DIE(strlen(name) < sizeof(sa.sun_path));

  sa.sun_family = AF_UNIX;
  strcpy(sa.sun_path, name);

  if (bind(fd, (struct sockaddr *) &sa, SUN_LEN(&sa)) < 0)
    return -1;

  if (listen(fd, 8) < 0)
    return -1;

  s->fd = fd;
  return 0;
}


#define CMSG_RX_SPACE MAX(CMSG4_SPACE_PKTINFO+CMSG4_SPACE_TTL, \
			  CMSG6_SPACE_PKTINFO+CMSG6_SPACE_TTL)
#define CMSG_TX_SPACE MAX(CMSG4_SPACE_PKTINFO,CMSG6_SPACE_PKTINFO)

static void
sk_prepare_cmsgs(sock *s, struct msghdr *msg, void *cbuf, size_t cbuflen)
{
  if (sk_is_ipv4(s))
    sk_prepare_cmsgs4(s, msg, cbuf, cbuflen);
  else
    sk_prepare_cmsgs6(s, msg, cbuf, cbuflen);
}

static void
sk_process_cmsgs(sock *s, struct msghdr *msg)
{
  struct cmsghdr *cm;

  s->laddr = IPA_NONE;
  s->lifindex = 0;
  s->rcv_ttl = -1;

  for (cm = CMSG_FIRSTHDR(msg); cm != NULL; cm = CMSG_NXTHDR(msg, cm))
  {
    if ((cm->cmsg_level == SOL_IP) && sk_is_ipv4(s))
    {
      sk_process_cmsg4_pktinfo(s, cm);
      sk_process_cmsg4_ttl(s, cm);
    }

    if ((cm->cmsg_level == SOL_IPV6) && sk_is_ipv6(s))
    {
      sk_process_cmsg6_pktinfo(s, cm);
      sk_process_cmsg6_ttl(s, cm);
    }
  }
}

struct sk_buf {
  LOCKED_STRUCT(event_state, node n;);
  void *buf;
  uint begin;
  uint len;
  ip_addr addr;
  uint port;
};

static inline int
sk_sendmsg(sock *s, struct sk_buf *buf)
{
  struct iovec iov = {buf->buf, buf->len};
  byte cmsg_buf[CMSG_TX_SPACE];
  sockaddr dst;
  int flags = 0;

  sockaddr_fill(&dst, s->af, buf->addr, s->iface, buf->port);

  struct msghdr msg = {
    .msg_name = &dst.sa,
    .msg_namelen = SA_LEN(dst),
    .msg_iov = &iov,
    .msg_iovlen = 1
  };

#ifdef CONFIG_DONTROUTE_UNICAST
  /* FreeBSD silently changes TTL to 1 when MSG_DONTROUTE is used, therefore we
     cannot use it for other cases (e.g. when TTL security is used). */
  if (ipa_is_ip4(s->daddr) && ip4_is_unicast(ipa_to_ip4(s->daddr)) && (s->ttl == 1))
    flags = MSG_DONTROUTE;
#endif

#ifdef CONFIG_USE_HDRINCL
  byte hdr[20];
  struct iovec iov2[2] = { {hdr, 20}, iov };

  if (s->flags & SKF_HDRINCL)
  {
    sk_prepare_ip_header(s, hdr, iov.iov_len);
    msg.msg_iov = iov2;
    msg.msg_iovlen = 2;
  }
#endif

  if (s->flags & SKF_PKTINFO)
    sk_prepare_cmsgs(s, &msg, cmsg_buf, sizeof(cmsg_buf));

  return sendmsg(s->fd, &msg, flags);
}

static inline int
sk_recvmsg(sock *s, void *buf, uint len)
{
  struct iovec iov = {buf, len};
  byte cmsg_buf[CMSG_RX_SPACE];
  sockaddr src;

  struct msghdr msg = {
    .msg_name = &src.sa,
    .msg_namelen = sizeof(src), // XXXX ??
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = cmsg_buf,
    .msg_controllen = sizeof(cmsg_buf),
    .msg_flags = 0
  };

  int rv = recvmsg(s->fd, &msg, 0);
  if (rv < 0)
    return rv;

  //ifdef IPV4
  //  if (cf_type == SK_IP)
  //    rv = ipv4_skip_header(pbuf, rv);
  //endif

  sockaddr_read(&src, s->af, &s->faddr, NULL, &s->fport);
  sk_process_cmsgs(s, &msg);

  if (msg.msg_flags & MSG_TRUNC)
    s->flags |= SKF_TRUNCATED;
  else
    s->flags &= ~SKF_TRUNCATED;

  return rv;
}

static struct sk_buf *
sk_buf_store(sock *s, const struct sk_buf *buf)
{
  struct sk_buf *nb = mb_alloc(s->pool, sizeof(struct sk_buf) + (buf->len - buf->begin));

  *nb = (struct sk_buf) {
    .buf = nb + 1,
    .begin = 0,
    .len = buf->len - buf->begin,
  };

  EVENT_LOCKED_INIT_LOCK(nb);

  memcpy(nb + 1, buf->buf + buf->begin, buf->len - buf->begin);

  return nb;
}

#define CANCEL_ACTION return -1

static int
sk_maybe_write(sock *s, struct sk_buf *buf, _Bool the_bird_locked)
{
  int e;

  switch (s->type)
  {
  case SK_TCP:
  case SK_MAGIC:
  case SK_UNIX:
    while (buf->begin < buf->len)
    {
      e = write(s->fd, buf->buf + buf->begin, buf->len - buf->begin);

      if (e < 0)
      {
	if (errno != EINTR && errno != EAGAIN)
	{
	  /* EPIPE is just a connection close notification during TX */
	  int er = errno == EPIPE ? 0 : errno;
	  CALL_TX_ERR(s, er, the_bird_locked);
	  return -1;
	}

	return 0;
      }

      buf->begin += e;
    }

    return 1;

#ifdef HAVE_LIBSSH
  case SK_SSH:
    while (buf->begin < buf->len)
    {
      e = ssh_channel_write(s->ssh->channel, buf->buf + buf->begin, buf->len - buf->begin);

      if (e < 0)
      {
	s->err = ssh_get_error(s->ssh->session);
	CALL_TX_ERR(s, ssh_get_error_code(s->ssh->session), the_bird_locked);
	return -1;
      }

      buf->begin += e;
    }
    return 1;
#endif

  case SK_UDP:
  case SK_IP:
    {
      e = sk_sendmsg(s, buf);

      if (e >= 0)
	return 1;
      else if (errno == EAGAIN || errno == EINTR)
	return 0;
      else
      {
	/* EPIPE is just a connection close notification during TX */
	int er = errno == EPIPE ? 0 : errno;
	CALL_TX_ERR(s, er, the_bird_locked);
	return -1;
      }
    }

  default:
    bug("sk_maybe_write: unknown socket type %d", s->type);
  }
}

#undef CANCEL_ACTION

void sk_schedule_tx_locked(LOCKED(event_state), sock *s);
_Bool sk_write_from_tx_hook(LOCKED(event_state), sock *s);

static int
sk_write_or_store(sock *s, struct sk_buf *buf)
{
  /* We have a buffer to write and we don't know the state of the TX queue.
   * It is either running or empty. If it is empty, we want to try to write
   * directly; otherwise we just put the data in the queue */

  /* It is also assumed that the writer is either non-cancellable
   * or has the socket owner locked, therefore we don't need to check
   * for cancellation here. */

  _Bool store = 0;
  struct sk_buf *nb = NULL;

  list flush_bufs;
  init_list(&flush_bufs);

  EVENT_LOCKED_NOFAIL
  {
    AUTO_TYPE su = UNLOCKED_STRUCT(event_state, s);

    /* There may be two different active writers.
     * 1) a TX coroutine which checks the chain for next buffers before ending
     * 2) a direct writer which writes and ends with no such check
     * We must distinguish between these two later, anyway for now we want
     * to store the buffer and then maybe schedule TX.
     */
    if (su->tx_coro && !sk_write_from_tx_hook(CURRENT_LOCK, s) || su->tx_active)
      store = 1;
    else
      /* The socket is completely free, locking it */
      su->tx_active = 1;

    if (!EMPTY_LIST(su->used_tx_bufs))
    {
      add_tail_list(&flush_bufs, &su->used_tx_bufs);
      init_list(&su->used_tx_bufs);
    }
  }

  node *fn;
  WALK_LIST_FIRST(fn, flush_bufs)
  {
    rem_node(fn);
    mb_free(fn);
  }
    
  if (store)
  {
    /* We have to copy the buffer as it may (and should) be allocated locally */
    nb = sk_buf_store(s, buf);

    /* And now let's check what has changed */
    EVENT_LOCKED_NOFAIL
    {
      AUTO_TYPE su = UNLOCKED_STRUCT(event_state, s);

      /* The socket is still occupied by somebody else, queuing */
      if (su->tx_coro && !sk_write_from_tx_hook(CURRENT_LOCK, s) || su->tx_active)
	add_tail(&su->tx_chain, &UNLOCKED_STRUCT(event_state, nb)->n);
      else
      {
	/* The socket has been freed inbetween, we fall back to direct write */
	store = 0;
	su->tx_active = 1;
      }
    }

    if (store)
      /* We have dropped our buf into the queue, others will take care of it. */
      return 0;
  }

  /* Now we want to write the buffer. */
  int e = sk_maybe_write(s, buf, 1);

  /* If we have written whole the packet, we are now done */
  if (e == 1)
  {
    if (s->type == SK_TCP || s->type == SK_UNIX)
      ASSERT_DIE(buf->begin == buf->len);

    goto done;
  }

  /* If an error has occured, we are done at all */
  if (e < 0)
    goto done;

  /* In case of partial write, we have to store the buffer unless already stored */
  if (nb)
    nb->begin = buf->begin;
  else
    nb = sk_buf_store(s, buf);

  EVENT_LOCKED_NOFAIL {
    AUTO_TYPE su = UNLOCKED_STRUCT(event_state, s);

    /* This is the first packet to continue writing with */
    add_head(&su->tx_chain, &UNLOCKED_STRUCT(event_state, nb)->n);

    /* Passing the chain to the asynchronous writer thread */
    if (!su->tx_coro)
      sk_schedule_tx_locked(CURRENT_LOCK, s);
    else
      ASSERT_DIE(sk_write_from_tx_hook(CURRENT_LOCK, s));

    su->tx_active = 0;
  }

  return 0;

done:
  EVENT_LOCKED_NOFAIL {
    AUTO_TYPE su = UNLOCKED_STRUCT(event_state, s);

    /* We are leaving the socket free */
    su->tx_active = 0;

    /* Wait, what if somebody has been blocked on us? */
    if (!EMPTY_LIST(su->tx_chain))
      sk_schedule_tx_locked(CURRENT_LOCK, s);
  }

  /* If the buf has been allocated, it is no longer needed */
  if (nb)
    mb_free(nb);

  return e;
}

int
sk_rx_ready(sock *s)
{
  int rv;
  struct pollfd pfd = { .fd = s->fd };
  pfd.events |= POLLIN;

 redo:
  rv = poll(&pfd, 1, 0);

  if ((rv < 0) && (errno == EINTR || errno == EAGAIN))
    goto redo;

  return rv;
}

/**
 * sk_send - send data to a socket
 * @s: socket
 * @len: number of bytes to send
 *
 * This function sends @len bytes of data prepared in the
 * transmit buffer of the socket @s to the network connection.
 * If the packet can be sent immediately, it does so and returns
 * 1, else it queues the packet for later processing, returns 0
 * and calls the @tx_hook of the socket when the tranmission
 * takes place.
 */
int
sk_send(sock *s, void *buf, uint len)
{
  struct sk_buf sb = {
    .buf = buf,
    .len = len,
    .addr = s->daddr, /* unused on stream sockets */
    .port = s->dport, /* unused on stream sockets */
  };

  return sk_write_or_store(s, &sb);
}

/**
 * sk_send_to - send data to a specific destination
 * @s: socket
 * @len: number of bytes to send
 * @addr: IP address to send the packet to
 * @port: port to send the packet to
 *
 * This is a sk_send() replacement for connection-less packet sockets
 * which allows destination of the packet to be chosen dynamically.
 * Raw IP sockets should use 0 for @port.
 */
int
sk_send_to(sock *s, void *buf, uint len, ip_addr addr, unsigned port)
{
  ASSERT_DIE(s->type == SK_UDP || s->type == SK_IP);

  struct sk_buf sb = {
    .buf = buf,
    .len = len,
    .addr = addr,
    .port = port ? port : s->dport,
  };

  return sk_write_or_store(s, &sb); 
}

#ifdef HAVE_LIBSSH
#define CANCEL_ACTION return 0
static int
sk_read_ssh(sock *s, struct sock_rx_buf *buf)
{
  ssh_channel rchans[2] = { s->ssh->channel, NULL };
  struct timeval timev = { 1, 0 };

  for (uint max = 8;
      (ssh_channel_select(rchans, NULL, NULL, &timev) == SSH_EINTR) && max;
      max--)
    ;

  if (ssh_channel_is_eof(s->ssh->channel) != 0)
  {
    /* The remote side is closing the connection */
    CALL_RX_ERR(s, 0, 0);
    return 0;
  }

  if (rchans[0] == NULL)
    return 0; /* No data is available on the socket */

  const int read_bytes = ssh_channel_read_nonblocking(s->ssh->channel, buf->buf + buf->pos, buf->end - buf->pos, 0);
  if (read_bytes > 0)
  {
    /* Received data */
    buf->pos += read_bytes;
    return 1;
  }
  else if (read_bytes == 0)
  {
    if (ssh_channel_is_eof(s->ssh->channel) != 0)
    {
      /* The remote side is closing the connection */
      CALL_RX_ERR(s, 0, 0);
    }
  }
  else
  {
    s->err = ssh_get_error(s->ssh->session);
    CALL_RX_ERR(s, ssh_get_error_code(s->ssh->session), 0);
  }

  return 0; /* No data is available on the socket */
}
#undef CANCEL_ACTION
#endif

#define CANCEL_ACTION return

void
sk_read(sock *s, struct sock_rx_buf *buf, int revents)
{
  switch (s->type)
  {
  case SK_TCP_PASSIVE:
    THE_BIRD_LOCKED_CALL(s, sk_passive_connected(s, SK_TCP));
    return;

  case SK_UNIX_PASSIVE:
    THE_BIRD_LOCKED_CALL(s, sk_passive_connected(s, SK_UNIX));
    return;

  case SK_TCP:
  case SK_UNIX:
    {
      int c = read(s->fd, buf->buf + buf->pos, buf->end - buf->pos);

      if (c < 0)
      {
	if (errno != EINTR && errno != EAGAIN)
	  CALL_RX_ERR(s, errno, 0);
	else if (errno == EAGAIN && !(revents & POLLIN))
	{
	  log(L_ERR "Got EAGAIN from read when revents=%x (without POLLIN)", revents);
	  CALL_RX_ERR(s, 0, 0);
	}
      }
      else if (!c)
	CALL_RX_ERR(s, 0, 0);
      else
      {
	buf->pos += c;
	break;
      }
      return;
    }

#ifdef HAVE_LIBSSH
  case SK_SSH:
    if (sk_read_ssh(s, buf))
      break;
    else
      return;
#endif

  case SK_MAGIC:
    THE_BIRD_LOCKED_CALL(s, CALL_RX_HOOK(s, buf));
    return;

  case SK_IP:
  case SK_UDP:
    {
      int e = sk_recvmsg(s, buf->buf, buf->end);

      if (e < 0)
      {
	if (errno != EINTR && errno != EAGAIN)
	  CALL_RX_ERR(s, errno, 0);
	return;
      }
      
      buf->pos = e;
      THE_BIRD_LOCKED_CALL(s, CALL_RX_HOOK(s, buf));

      return;
    }

  default:
    bug("sk_read: unknown socket type %d", s->type);
  }

  uint consumed;
  THE_BIRD_LOCKED_CALL(s, consumed = CALL_RX_HOOK(s, buf));
  
  if (consumed < buf->pos)
  {
    buf->pos -= consumed;
    memmove(buf->buf, buf->buf + consumed, buf->pos);
  }
  else
  {
    ASSERT_DIE(consumed == buf->pos);
    buf->pos = 0;
  }
}

#undef CANCEL_ACTION
#define CANCEL_ACTION return 0

_Bool
sk_write(sock *s)
{
  _Bool ret = 0;
  switch (s->type)
  {
  case SK_TCP_ACTIVE:
    {
      sockaddr sa;
      sockaddr_fill(&sa, s->af, s->daddr, s->iface, s->dport);

      if (connect(s->fd, &sa.sa, SA_LEN(sa)) >= 0 || errno == EISCONN)
      {
	sk_tcp_connected(s);
	THE_BIRD_LOCKED_CALL(s, ret = CALL_TX_HOOK(s));
      }
      else if (errno != EINTR && errno != EAGAIN && errno != EINPROGRESS)
	CALL_TX_ERR(s, errno, 0);

      return ret;
    }

#ifdef HAVE_LIBSSH
  case SK_SSH_ACTIVE:
    {
      while (1) switch (sk_ssh_connect(s))
      {
	case SSH_OK:
	  s->type = SK_SSH;
	  THE_BIRD_LOCKED_CALL(s, ret = CALL_TX_HOOK(s));
	  return ret;

	case SSH_AGAIN:
	  continue;

	case SSH_ERROR:
	  s->err = ssh_get_error(s->ssh->session);
	  CALL_TX_ERR(s, ssh_get_error_code(s->ssh->session), 0);
	  return 0;
      }
    }
#endif

  default:
    {
      while (1) {
	struct sk_buf *buf = NULL;
	EVENT_LOCKED ({ return 0; }) {
	  AUTO_TYPE su = UNLOCKED_STRUCT(event_state, s);
	  ASSERT_DIE(su->tx_active == 0);

	  if (!EMPTY_LIST(su->tx_chain))
	    /* The buffer to write */
	    buf = HEAD(su->tx_chain);
	}

	if (!buf)
	  break;

	DBG("Writing buffer %p (%p)\n", buf, &buf);

	int e = sk_maybe_write(s, buf, 0);
	if (e == 0)
	  return 1;
	if (e < 0)
	  return 0;
	
	if (s->type == SK_TCP || s->type == SK_UNIX)
	  ASSERT_DIE(buf->begin == buf->len);

	ASSERT_DIE(e == 1);
	EVENT_LOCKED ({ return 0; })
	{
	  rem_node(&UNLOCKED_STRUCT(event_state, buf)->n);
	  add_tail(
	      &UNLOCKED_STRUCT(event_state, s)->used_tx_bufs,
	      &UNLOCKED_STRUCT(event_state, buf)->n
	      );
	}
      }

      THE_BIRD_LOCKED_CALL(s, ret = CALL_TX_HOOK_IF_EXISTS(s));
      if (!ret)
	EVENT_LOCKED ({ return 0; })
	  if (!EMPTY_LIST(UNLOCKED_STRUCT(event_state, s)->tx_chain))
	    ret = 1;

      return ret;
    }
  }
}

#undef CANCEL_ACTION

int sk_is_ipv4(sock *s)
{ return s->af == AF_INET; }

int sk_is_ipv6(sock *s)
{ return s->af == AF_INET6; }

#define CANCEL_ACTION return

void
sk_err(sock *s, int revents, _Bool rx)
{
  int se = 0, sse = sizeof(se);
  if ((s->type != SK_MAGIC) && (revents & POLLERR))
    if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &se, &sse) < 0)
    {
      log(L_ERR "IO: Socket error: SO_ERROR: %m");
      se = 0;
    }

  if (rx)
    CALL_RX_ERR(s, se, 0);
  else
    CALL_TX_ERR(s, se, 0);
}

#undef CANCEL_ACTION

void
sk_dump_all(void)
{
  debug("Open sockets listing not implemented yet\n");
  /*
  node *n;
  sock *s;

  debug("Open sockets:\n");
  WALK_LIST(n, sock_list)
  {
    s = SKIP_BACK(sock, n, n);
    debug("%p ", s);
    sk_dump(&s->r);
  }
  debug("\n");
  */
}

#if 0

/*
 *	Internal event log and watchdog
 */

#define EVENT_LOG_LENGTH 32

struct event_log_entry
{
  void *hook;
  void *data;
  btime timestamp;
  btime duration;
};

static struct event_log_entry event_log[EVENT_LOG_LENGTH];
static int event_log_pos, event_log_num, watchdog_active;
static btime loop_time;

static _Thread_local struct event_log_entry *event_open;
static _Thread_local btime last_time;

/**
 * io_log_event - mark approaching event into event log
 * @hook: event hook address
 * @data: event data address
 *
 * Store info (hook, data, timestamp) about the following internal event into
 * a circular event log (@event_log). When latency tracking is enabled, the log
 * entry is kept open (in @event_open) so the duration can be filled later.
 */
void
io_log_event(void *hook, void *data)
{
  if (config->latency_debug)
    io_update_time();

  struct event_log_entry *en = event_log + event_log_pos;

  en->hook = hook;
  en->data = data;
  en->timestamp = last_time;
  en->duration = 0;

  event_log_num++;
  event_log_pos++;
  event_log_pos %= EVENT_LOG_LENGTH;

  event_open = config->latency_debug ? en : NULL;
}

void
io_close_event(void)
{
  if (event_open)
    io_update_time();
}

void
io_log_dump(void)
{
  int i;

  log(L_DEBUG "Event log:");
  for (i = 0; i < EVENT_LOG_LENGTH; i++)
  {
    struct event_log_entry *en = event_log + (event_log_pos + i) % EVENT_LOG_LENGTH;
    if (en->hook)
      log(L_DEBUG "  Event 0x%p 0x%p at %8d for %d ms", en->hook, en->data,
	  (int) ((last_time - en->timestamp) TO_MS), (int) (en->duration TO_MS));
  }
}

void
watchdog_sigalrm(int sig UNUSED)
{
  /* Update last_time and duration, but skip latency check */
  config->latency_limit = 0xffffffff;
  io_update_time();

  /* We want core dump */
  abort();
}

static inline void
watchdog_start1(void)
{
  io_update_time();

  loop_time = last_time;
}

static inline void
watchdog_start(void)
{
  io_update_time();

  loop_time = last_time;
  event_log_num = 0;

  if (config->watchdog_timeout)
  {
    alarm(config->watchdog_timeout);
    watchdog_active = 1;
  }
}

static inline void
watchdog_stop(void)
{
  io_update_time();

  if (watchdog_active)
  {
    alarm(0);
    watchdog_active = 0;
  }

  btime duration = last_time - loop_time;
  if (duration > config->watchdog_warning)
    log(L_WARN "I/O loop cycle took %d ms for %d events",
	(int) (duration TO_MS), event_log_num);
}
#endif


/*
 *	Main I/O Loop
 */

static void
pipe_kick(int fd)
{
  char v = 1;
  int rv;

 try:
  rv = write(fd, &v, 1);
  if (rv < 0)
  {
    if (errno == EINTR)
      goto try;
    if (errno == EAGAIN)
      return;
    die("wakeup write: %m");
  }
}

void
io_init(void)
{
  krt_io_init();
  // XXX init_times();
  // XXX update_times();
  boot_time = current_time();

  u64 now = (u64) current_real_time();
  srandom((uint) (now ^ (now >> 32)));
}

void
timers_wait(struct timeloop *loop)
{
  int poll_tout;
  LOCKED_DO_NOFAIL(timer, loop->domain)
  {
    timer *t = timers_first(CURRENT_LOCK, loop);
    poll_tout = t ? TM_REMAINS_U(t) TO_MS : -1;
  }
  
  if (poll_tout == 0)
    return;

  struct pollfd pfd = {
    .fd = loop->fds[0],
    .events = POLLIN,
  };

  if ((poll(&pfd, 1, poll_tout) < 0) && (errno != EINTR) && (errno != EAGAIN))
    die("poll: %m");

  char buf[64];
  int e = read(loop->fds[0], buf, 64);
  if (e < 0 && errno != EINTR && errno != EAGAIN)
    die("pipe read: %m");

  DBG("timer loop pipe drain: %d\n", e);
}

void
timers_ping(struct timeloop *loop)
{
  pipe_kick(loop->fds[1]);
}

void
test_old_bird(char *path)
{
  int fd;
  struct sockaddr_un sa;

  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    die("Cannot create socket: %m");
  if (strlen(path) >= sizeof(sa.sun_path))
    die("Socket path too long");
  bzero(&sa, sizeof(sa));
  sa.sun_family = AF_UNIX;
  strcpy(sa.sun_path, path);
  if (connect(fd, (struct sockaddr *) &sa, SUN_LEN(&sa)) == 0)
    die("I found another BIRD running.");
  close(fd);
}
