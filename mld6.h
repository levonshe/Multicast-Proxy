/*	$KAME: mld6.h,v 1.13 2004/06/09 15:52:57 suz Exp $	*/

/*
 * Copyright (C) 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 *  Questions concerning this software should be directed to
 *  Mickael Hoerdt (hoerdt@clarinet.u-strasbg.fr) LSIIT Strasbourg.
 *
 */
/*
 * This program has been derived from pim6dd.        
 * The pim6dd program is covered by the license in the accompanying file
 * named "LICENSE.pim6dd".
 */
/*
 * This program has been derived from pimd.        
 * The pimd program is covered by the license in the accompanying file
 * named "LICENSE.pimd".
 *
 */


#ifndef MLD6_H
#define MLD6_H
#ifdef __linux__
#include <netinet/icmp6.h>
#endif

#define RECV_BUF_SIZE	        64*1024
#define SO_RECV_BUF_SIZE_MAX	256*1024
#define SO_RECV_BUF_SIZE_MIN	48*1024
#define MINHLIM							1
#ifdef __linux__
// TODO /usr/include/linux/ipv6.h:struct in6_pktinfo
struct in6_pktinfo {
   struct in6_addr ipi6_addr;
   int             ipi6_ifindex;
};

#define ICMP6_MEMBERSHIP_QUERY MLD_LISTENER_QUERY //FreeBSD compatability ICMP 130
#define ICMP6_MEMBERSHIP_REPORT MLD_LISTENER_REPORT //FreeBSD compatability ICMP 131
#define ICMP6_MEMBERSHIP_REDUCTION MLD_LISTENER_REDUCTION //FreeBSD compatability ICMP 132
#define MLD_LISTENER_DONE  MLD_LISTENER_REDUCTION //FreeBSD compatability ICMP 132
#endif

/* for OSs without the definition of MLDv2 Report ICMPv6 number */
#ifndef MLDV2_LISTENER_REPORT
#define MLDV2_LISTENER_REPORT 143
//MLDV2_LISTENER_REPORT are sent with an IP destination address of FF02:0:0:0:0:0:0:1
#endif


extern int mld6_socket;
extern int mld6_proxy_socket;
extern char *mld6_recv_buf;
extern struct sockaddr_in6 allrouters_group;
extern struct sockaddr_in6 allnodes_group;
extern char *mld6_send_buf;

void init_mld6 __P((void));
int send_mld6 __P((int type, int code, struct sockaddr_in6 *src,
		   struct sockaddr_in6 *dst, struct in6_addr *group,
		   int index, int delay, int datalen, int alert));
void mld6_read __P((int socket_fd));
void mld6SendGenericQueryDs __P((void));
/* portability with older KAME headers */
#ifndef MLD_LISTENER_QUERY
#define MLD_LISTENER_QUERY	130
#define MLD_LISTENER_REPORT	131
#define MLD_LISTENER_DONE	132
#define MLD_MTRACE_RESP		201
#define MLD_MTRACE		202

#ifndef HAVE_MLD_HDR
struct mld_hdr {
	struct icmp6_hdr mld_icmp6_hdr;
	struct in6_addr	mld_addr;
};
#define mld_type mld_icmp6_hdr.icmp6_type
#define mld_code mld_icmp6_hdr.icmp6_code
#define mld_maxdelay mld_icmp6_hdr.icmp6_maxdelay

#else

#define mld_hdr		mld6_hdr
#define mld_type	mld6_type
#define mld_code	mld6_code
#define mld_maxdelay	mld6_maxdelay
#define mld_addr	mld6_addr
#endif

#define mld_cksum	mld6_cksum
#define mld_reserved	mld6_reserved
#endif

#ifndef MLD_MTRACE_RESP
#define MLD_MTRACE_RESP		201
#endif
#ifndef MLD_MTRACE
#define MLD_MTRACE		202
#endif

#ifndef IP6OPT_RTALERT_MLD
#define IP6OPT_RTALERT_MLD	0
#define IP6OPT_RTALERT		0x05
#endif

#ifndef IP6OPT_ROUTER_ALERT
#define IP6OPT_ROUTER_ALERT	IP6OPT_RTALERT
#endif
#ifndef IP6OPT_RTALERT_LEN
#define	IP6OPT_RTALERT_LEN	4
#endif
#ifndef IN6ADDR_LINKLOCAL_ALLNODES_INIT
#define IN6ADDR_LINKLOCAL_ALLNODES_INIT \
	{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
static const struct in6_addr in6addr_linklocal_allnodes = IN6ADDR_LINKLOCAL_ALLNODES_INIT;
#endif

#endif
