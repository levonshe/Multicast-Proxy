/*	$KAME: vif.h,v 1.29 2004/06/09 19:09:22 suz Exp $	*/

/*
 * Copyright (c) 1998-2001
 * The University of Southern California/Information Sciences Institute.
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
/*
 * Part of this program has been derived from mrouted.
 * The mrouted program is covered by the license in the accompanying file
 * named "LICENSE.mrouted".
 *
 * The mrouted program is COPYRIGHT 1989 by The Board of Trustees of
 * Leland Stanford Junior University.
 *
 */

#ifndef VIF_H
#define VIF_H

#include "defs.h"
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/icmp6.h>
#include <linux/mroute6.h>
typedef u_int16_t mifi_t;
extern int total_interfaces;
extern int default_vif_status;
extern int udp_socket;
extern int mld_proxy_socket;

extern mifi_t numvifs;
extern int vifs_down; 
extern int phys_vif;


#define NO_VIF            	((mifi_t)MAXUVIFS) /* An invalid vif index */
#define DEFAULT_METRIC 		1
#define VIFF_DOWN		0x0000100
#define VIFF_DISABLED       	0x0000200
#define VIFF_QUERIER		IF_STATE_DOWNSTREAM
#define VIFF_REXMIT_PRUNES	0x0004000
#define VIFF_NONBRS		0x0080000
#define VIFF_POINT_TO_POINT	0x0400000	
#define VIFF_NOLISTENER         0x0800000       /* no listener on the link   */
#define VIFF_ENABLED       	0x1000000
#define NBRTYPE 		u_long
#define NBRBITS			sizeof(NBRTYPE) *8


extern if_set if_nullset;
#define IF_ISEMPTY(p) (memcmp((p), &if_nullset, sizeof(if_nullset)) == 0)
#define IF_SAME(p1, p2) (memcmp((p1),(p2),sizeof(*(p1))) == 0)
#define IF_CLR_MASK(p, mask) \
  {\
    int idx;\
    for (idx = 0; idx < sizeof(*(p))/sizeof(fd_mask); idx++) {\
        (p)->ifs_bits[idx] &= ~((mask)->ifs_bits[idx]);\
    }\
  }
#define IF_MERGE(p1, p2, result) \
  {\
    int idx;\
    for (idx = 0; idx < sizeof(*(p1))/sizeof(fd_mask); idx++) {\
        (result)->ifs_bits[idx] = (p1)->ifs_bits[idx]|(p2)->ifs_bits[idx]; \
    }\
  } 


#define VFRF_EXACT 0x0001
#define VFT_ACCEPT 1
#define VFT_DENY   2
#define VFF_BIDIR 1


#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC             1  //usr/include/bits/time.h
#define CLOCK_REALTIME            0
#endif

//typedef	void	( *cfunc_t )( void *  );

typedef struct
{
	cfunc_t callback;
	mifi_t mifi;
	struct listaddr *g;
	struct sockaddr_in6* mcast_group;
	struct listaddr *source;
	int q_time;
} timer_cbk_t;

typedef struct
{
        cfunc_t callback;
	mifi_t mifi;
	struct uvif *v;
	int q_time;
} uvif_timer_cbk_t;

struct listaddr {
	struct listaddr *al_next; /* link to next addr, MUST BE FIRST */
	struct listaddr *sources; /* list of sources for this group */
        struct sockaddr_in6 mcast_group; /* multicast group */
        struct sockaddr_in6 transmitter; /* TODO perhaps >sin6_addr? sender of multicast */
	/* 
	 * al_timer contains a lifetime of this entry regarding MLD.  
	 * It corrensponds to many kinds of lifetimes.
	 * [MLDv1]
	 * - remaining time until the next Query (v->uv_querier->al_timer)
	 * - group-expiry timer (v->uv_group->al_timer)
	 * - LLQT value (v->uv_group->al_timer) 
	 * [MLDv2]
	 * - remaining time until the next query (v->uv_querier->al_timer)
	 * - filter-timer (v->uv_group->al_timer)
	 * - source-expiry timer (v->uv_group->sources->al_timer)
	 * - group LLQT (v->uv_group->al_timer) 
	 * - source LLQT (v->uv_group->sources->al_timer)
	 *
	 *  Please keep in mind that the actual timeout is handled by
	 *  callout-queue corresponding to its group_mbship_timer, except
	 *  Query transmission.
	 */
	int8_t   llqi;       /* Last Listener Query Interval, default 1 sec */
	int8_t   llqc;       /* Last Listener Query Count, set it uv_mld_llq  to  before LLquery will be snt, decr by 1 at timer expire until 0 if mld_report will be heard */
	u_long   al_timer;
	time_t   al_ctime;    /* entry creation time */

	u_int8_t           added_to_mfc;
	u_int8_t           filter_mode; /* filter mode for mldv2 */
	u_int8_t           comp_mode;  /* compatibility mode */
	u_int8_t           listeners; /* count subscribers */
	
	
	/* timer to return from mldv1-compatibility mode */
	u_int8_t           al_CheckingListenerMode; /* TRUE I'm in checking listener state */
	u_int8_t           al_rob;	  /* robustness */
	if_set             downstream_ifset; /* populated only for upstream element of array */
	
	struct epoll_event group_report_timer_event;
	timer_cbk_t        report_timer_callback;
	int                group_report_timer; /* FD -timer for group membership  this is timer reverenced by rfc 2710*/
	
	struct epoll_event group_rxmt_timer_event;
	timer_cbk_t        rxmt_timer_callback;
	int                group_rxmt_timer;  /* FD - timer for  retransmit group specific query - as responce for leave msg this is timer reverenced by rfc 2710 as rxmt timer */
	
	timer_cbk_t        filterMode_timer_callback;
	int                mldv2_filterMode_timer;
	struct epoll_event filterMode_timer_event;
	
	 /* Older  Version  Timeout   - per MA address*/
	
	struct epoll_event uv_back2mldv2_time_event;
	timer_cbk_t        uv_back2mldv2_timer_callback;
	int                uv_back2mldv2_timer;
};

enum { LESSTHANLLQI = 1, MORETHANLLQI };
#define al_genid al_alu.alu_genid
#define al_reporter al_alu.alu_reporter

/*
 * User level Virtual Interface structure 
 *
 * A "virtual interface" is either a physical, multicast-capable interface
 * (called a "phyint"), a virtual point-to-point link (called a "tunnel")
 * or a "register vif" used by PIM. The register vif is used by the     
 * Designated Router (DR) to send encapsulated data packets to the
 * Rendevous Point (RP) for a particular group. The data packets are
 * encapsulated in PIM messages (IPPROTO_PIM = 103) and then unicast to
 * the RP.
 * (Note: all addresses, subnet numbers and masks are kept in NETWORK order.)
 */
struct uvif {
	u_int8 uv_flags;		

	//struct phaddr *uv_linklocal;	/* link-local address of this vif */
	struct sockaddr_in6 uv_linklocal;	/* link-local address of this vif */
	struct sockaddr_in6 uv_prefix;	/* prefix (phyints only) */
	struct in6_addr	uv_subnetmask;	/* subnet mask (phyints only) */

	char    uv_name[IFNAMSIZ];	/* interface name */
	u_int16 uv_ifindex;	/*  if_nametoindex -  index of the real phusical interface */
	u_int16 state;	        /* IF_STATE_DOWNSTREAM/IF_STATE_UPSTREAM */
	struct listaddr *uv_groups; /* list of local groups  (phyints only) */
	u_int8 fastleave;
        u_int32 gen_query_timer; /* Group Query timer */
	
	#define uvif_timer  gen_query_timer
	u_int16	uv_gq_timer;	/* Group Query timer */
	u_int8_t interfaceStartupQueryCount;	/* Startup Query Count */
	u_int8_t uv_mld_version;	/* mld version of this mif */
	u_int16 uv_mld_robustness; /* robustness variable of this vif (mld6 protocol) */
	u_int32 uv_mld_query_interval; /* query interval of this vif (mld6 protocol) */
	u_int32 uv_mld_query_rsp_interval;  /* query response interval of this vif (mld6 protocol) */
	u_int32 uv_mld_llqi;      /* last listener query interval */
	u_int32 uv_mld_llqc;      /* last listener query count */
	

	void *config_attr;	/* temporary buffer while parsing config */

	/* incoming MLD packets on this interface */
	u_quad_t uv_in_mld_query;
	u_quad_t uv_in_mld_report;
	u_quad_t uv_in_mld_done;
	/* outgoing MLD packets on this interface */
	u_quad_t uv_out_mld_query;
	u_quad_t uv_out_mld_report;
	u_quad_t uv_out_mld_done;
	/* statistics about the forwarding cache in kernel */
	u_quad_t uv_cache_miss;
	u_quad_t uv_cache_notcreated;
	
	uint32_t threshold;
	uint32_t ratelimit;
	
	struct epoll_event uv_genQuery_timer_event;
	uvif_timer_cbk_t   uv_genQuery_timer_callback;
	int                uv_genQuery_timer;

};
extern struct uvif uvifs[];

struct phaddr {
	struct phaddr 		*pa_next;
	struct sockaddr_in6 	pa_addr;
	struct sockaddr_in6 	pa_rmt_addr;	/* valid only in case of P2P I/F */
	struct sockaddr_in6 	pa_prefix;
	struct in6_addr 	pa_subnetmask;
};




extern int config_vif_from_kernel( struct uvif *v);
extern void start_all_vifs(void);
int activate_back_to_mldv2_timer (mifi_t mifi);
extern void    init_vifs __P((void));
extern void    stop_all_vifs __P((void));
extern void    check_vif_state __P((void));
struct sockaddr_in6 * max_globmcast_groupess __P((void));
struct sockaddr_in6 * uv_global __P((mifi_t));
extern mifi_t   locmcast_groupess  __P((struct sockaddr_in6 *src));
struct sockaddr_in6 * local_iface __P((char *ifname));
extern mifi_t   find_vif_direct     __P((struct sockaddr_in6 *src));
extern mifi_t  find_vif_direct_local   __P((struct sockaddr_in6 *src));
extern int vif_forwarder __P((if_set *p1 ,if_set *p2));
extern if_set *vif_and __P((if_set *p1, if_set *p2, if_set *result)); 
extern if_set *vif_xor __P((if_set *p1, if_set *p2, if_set *result));
extern struct uvif *find_vif __P((char *ifname, int, int));
extern char *mif_name __P((unsigned short));
extern mifi_t find_vif_by_ifindex(int ifindex);
/* Phase 2 - for now on, use kernel 
extern int __P(vif_merge_with_upstream(struct listaddr * g, struct sockaddr_in6 * grp,unsigned short mld_version));
extern int __P(vif_upstream_delete(struct listaddr * g, struct sockaddr_in6 * grp,unsigned short mld_version));
*/

/* interface independent statistics */
struct mfc_cache_stat {
        /* kernel mfc cache internals */
        u_quad_t kern_add_cache;
        u_quad_t kern_add_cache_fail;
        u_quad_t kern_del_cache;
        u_quad_t kern_del_cache_fail;
        u_quad_t kern_sgcnt_fail;
};

extern struct mfc_cache_stat mfc_cache_stat;

#endif
