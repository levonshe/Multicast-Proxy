/*	$KAME: route.c,v 1.28 2004/05/19 14:05:03 suz Exp $	*/

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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#ifdef __linux__
#include <netinet/icmp6.h>
#include <linux/mroute6.h>
#else
#include <netinet6/ip6_mroute.h>
#endif
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include "defs.h"
#include "vif.h"
#include "debug.h"
#include "route.h"
#include "mld6.h"
#include "mld6_proto.h"
#include "kern.h"
#include "inet6.h"

static void process_cache_miss (struct mrt6msg * im);
static void process_wrong_iif (struct mrt6msg * im);



/* Return the iif for given address */
#if 0
mifi_t
get_iif(address)
    struct sockaddr_in6	*address;
{
    struct rpfctl   rpfc;

    k_req_incoming(address, &rpfc);
    if (IN6_IS_ADDR_UNSPECIFIED(&rpfc.rpfneighbor.sin6_addr))
	return (NO_VIF);
    return (rpfc.iif);
}
#endif

/*
 * TODO: check again the exact setup if the source is local or directly
 * connected!!! Yes Really for Ipv6!!
 */
/*
 * TODO: XXX: change the metric and preference for all (S,G) entries per
 * source or RP?
 */
/*
 * TODO - If possible, this would be the place to correct set the source's
 * preference and metric to that obtained from the kernel and/or unicast
 * routing protocol.  For now, set it to the configured default for local
 * pref/metric.
 */

/*
 * TODO: XXX: currently `source` is not used. Will be used with IGMPv3 where
 * we have source-specific Join/Prune.
 */



void 
process_kernel_call()
{
    register struct mrt6msg *im;	/* igmpmsg control struct */

    im = (struct mrt6msg *) mld6_recv_buf;

    switch (im->im6_msgtype)
    {
    case MRT6MSG_NOCACHE:
	process_cache_miss(im);
	break;
    case MRT6MSG_WRONGMIF:
	IF_DEBUG(DEBUG_KERN)
	    log_msg(LOG_DEBUG, 0, " cache miss MRT6MSG_WRONGMIF: calling stup process_wrong_iif ");
	process_wrong_iif(im);
	break;
    default:
	IF_DEBUG(DEBUG_KERN)
	    log_msg(LOG_DEBUG, 0, "Unknown kernel_call code");
	break;
    }
}


/*
 * TODO: when cache miss, check the iif, because probably ASSERTS shoult take
 * place
 */

static void
process_cache_miss(im)
    struct mrt6msg *im;
{
    static struct sockaddr_in6 source;
    static struct sockaddr_in6 group;
    struct listaddr * g;
    mifi_t          iif, mifi, vifi;
    register struct uvif *v;

    init_sin6(&source);
    //init_sin6(&mfc_source);
    init_sin6(&group);
    

    /*
     * When there is a cache miss, we check only the header of the packet
     * (and only it should be sent up by the kernel.)
     */
    group.sin6_addr = im->im6_dst;
    group.sin6_scope_id = inet6_uvif2scopeid(&group, &uvifs[im->im6_mif]);
    source.sin6_addr = im->im6_src;
    source.sin6_scope_id = inet6_uvif2scopeid(&source, &uvifs[im->im6_mif]);
    iif = im->im6_mif;
    

    if (IN6_IS_ADDR_MC_NODELOCAL(&group.sin6_addr) ||/* sanity? */
    	IN6_IS_ADDR_MC_LINKLOCAL(&group.sin6_addr))
    {
            log_msg(LOG_DEBUG, 0, "Error : process_cache_miss IN6_IS_ADDR_MC_NODELOCAL || IN6_IS_ADDR_MC_LINKLOCAL ");
	    goto fail;

    }
    // Lev- find mifi -it must have come from upstream
    for (vifi = 0; vifi < numvifs; ++vifi) {
	if  (uvifs[vifi].uv_ifindex == iif)
	   break;
    }
    if ( vifi >=numvifs ) {
	  log_msg(LOG_DEBUG, 0, "BUG interface uv_ifindex %d not found in uvifs ", iif);
	  return;
	}
    if ( vifi != upStreamVif || iif != upstream_idx )
    {
      log_msg(LOG_DEBUG, 0, "Error : cache miss  not for i interface=%d  - not upStream   interface upstream_idx= %d  ", iif, upstream_idx);
	    goto fail;
    }
    uvifs[vifi].uv_cache_miss++;
    //find group in the upstream interface group list
    g = check_multicast_listener(&uvifs[upStreamVif], &group);
    if (g == NULL )
    {
      log_msg(LOG_ERR, 0, "Error : cache_miss on %d but group is nit found in upstream  interface list, exiting ", iif);
      return;
    }
    /* TODO: check if correct in case the source is one of my addresses */
    /*
     * If I am the DR for this source, create (S,G) and add the register_vif
     * to the oifs.
     */
    
     /* TODO: if there are too many cache miss for the same (S,G), install
     * negative cache entry in the kernel (oif==NULL) to prevent too many
     * upcalls.
     */
     uvifs[vifi].uv_groups;

     memcpy( &(g->transmitter), &source, sizeof(source));
     add_mfc6(&source, /* sender of multicast*/ 
	 &group,  /* multicast address - the destination */
	 upstream_idx,  /* from where it come - upstream */
         &(g->downstream_ifset) /*set of inteface to route to */
	 );

#ifdef KERNEL_MFC_WC_G
// TODO 
	    if (mrtentry_ptr->flags & (MRTF_WC | MRTF_PMBR))
		if (!(mrtentry_ptr->flags & MRTF_MFC_CLONE_SG))
		    mfc_source = IN6ADDR_ANY_N;
#endif				/* KERNEL_MFC_WC_G */
fail:
     return;
     
}


/*
 * A multicast packet has been received on wrong iif by the kernel. Check for
 * a matching entry. If there is (S,G) with reset SPTbit and the packet was
 * received on the iif toward the source, this completes the switch to the
 * shortest path and triggers (S,G) prune toward the RP (unless I am the RP).
 * Otherwise, if the packet's iif is in the oiflist of the routing entry,
 * trigger an Assert.
 */

static void
process_wrong_iif(im)
    struct mrt6msg *im;
{

    short iif = im->im6_mif;

    log_msg(LOG_DEBUG, 0, "Error : process_wrong_iif   interface=%d  - not upStream   interface upstream_idx= %d  ", iif, upstream_idx);

}
struct listaddr *
find_multicast_listener(
	struct uvif *v,
	struct sockaddr_in6 *group )
{
	struct listaddr *g;

	/* Look for the group in our listener list. */
	for (g = v->uv_groups; g != NULL; g = g->al_next) {
		if (inet6_equal(group, &g->mcast_group))
			break;
	}
	return g;
}
