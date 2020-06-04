/*	$KAME: kern.c,v 1.13 2004/06/14 05:45:29 itojun Exp $	*/

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

#ifdef HAVE_CONFIG_H
#include <../include/config.h>
#endif
#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <net/if.h>
#ifdef __FreeBSD__
#include <net/if_var.h>
#endif
#include <net/route.h>
#include <netinet/in.h>
#ifdef __linux__
#include <linux/mroute6.h>
#else
#include <netinet6/ip6_mroute.h>
#endif
#ifdef HAVE_NETINET6_IN6_VAR_H
#include <netinet6/in6_var.h>
#endif
#include <syslog.h>
#include <errno.h>
#include "defs.h"
#include "vif.h"
#include "inet6.h"
#include "vif.h"
#include "mld6_proto.h"
#include "kern.h"

int mroute_socket;

/*  
 * Open/init the multicast routing in the kernel and sets the MRT_ASSERT
 * flag in the kernel.
 *
 */
int enableMRouter(void)
{
   int             rc=0,v = 1;
   if (( mroute_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
        log_msg(LOG_ERR, errno, "cannot open multicast routing socket");
	return -1;
    }

    if ((rc=setsockopt(mroute_socket, IPPROTO_IPV6, MRT6_INIT, (char *) &v, sizeof(v))) < 0)
	log_msg(LOG_ERR, errno, "cannot enable multicast routing on routing socket");

   return rc;
}

/*
 * Stops the multicast routing in the kernel and resets the MRT_ASSERT flag
 * in the kernel.
 */

int
disableMRouter(void)
{
    int             rc=0;

    if ( (rc=setsockopt(mroute_socket, IPPROTO_IPV6, MRT6_DONE, (char *) NULL, 0)) < 0)
    {
	log_msg(LOG_ERR, errno, "cannot disable multicast routing in kernel");
    }
    
   close(mroute_socket);
   return rc;

}

add_mfc6(struct sockaddr_in6 *origin, /* sender of multicast*/ 
	 struct sockaddr_in6 *mcastgrp,  /* multicast address - the destination */
	 mifi_t in,  /* from where it come - upstream */
         struct if_set *out /*set of inteface to route to */ )
{
        struct mf6cctl mf6c;

        if (mroute_socket < 0)
               log_msg(LOG_ERR, errno, " multicast routing is not enabled ");
	memset(&mf6c, 0, sizeof(mf6c));
        memcpy(&mf6c.mf6cc_origin, origin, sizeof(mf6c.mf6cc_origin)); // ??? will IPv6 any address
        memcpy( &mf6c.mf6cc_mcastgrp, mcastgrp, sizeof(mf6c.mf6cc_mcastgrp));
        mf6c.mf6cc_parent = in;
        //mf6c.mf6cc_ifset = *out;
	memcpy( &mf6c.mf6cc_ifset , out,  sizeof (struct if_set));

        if (setsockopt(mroute_socket, IPPROTO_IPV6, MRT6_ADD_MFC, &mf6c, sizeof(mf6c)) < 0) {
                log_msg(LOG_ERR, errno, " error adding MFC enrey ");
        }
}
/* delete one of the routes for the group, i.e remove route to one of downstream interfaces */
del_mfc6(struct sockaddr_in6 *origin, /* sender of multicast*/ 
	 struct sockaddr_in6 *mcastgrp,  /* multicast address - the destination */
	 mifi_t in  /* from where it come - upstream */
         )
{
        struct mf6cctl mf6c;
	struct listaddr *g;
	mifi_t vifi;
      

        if (mroute_socket < 0)
               log_msg(LOG_ERR, errno, " multicast routing is not enabled/initialized ");
	for (vifi = 0;  vifi < numvifs; ++vifi ) {
	  if (uvifs[vifi].uv_ifindex=in )
	       break;
	}
	if ( vifi >=numvifs ) {
	  log_msg(LOG_DEBUG, 0, "BUG interface uv_index %d not found in uvifs ", in);
	  return;
	}
	g = check_multicast_listener(&uvifs[vifi], mcastgrp);
	if ( g == NULL) {
	 	log_msg(LOG_DEBUG, 0, "BUG listener not found for %s on mif %d",
		    inet6_fmt(&(mcastgrp->sin6_addr)), in);
		return;
	}
	if ( (! IF_ISSET ( in, &(g->downstream_ifset) ) ) ) {
	 	log_msg(LOG_DEBUG, 0, "BUG, downstream_ifset is not active for mif %d, Proxy is not listening for %s on mif",
		    in, inet6_fmt(&(mcastgrp->sin6_addr)));
		return;
	}
	IF_CLR(in, &(g->downstream_ifset));
	memset(&mf6c, 0, sizeof(mf6c));
        memcpy(&mf6c.mf6cc_origin, origin, sizeof(mf6c.mf6cc_origin)); // ??? will IPv6 any address
        memcpy( &mf6c.mf6cc_mcastgrp, mcastgrp, sizeof(mf6c.mf6cc_mcastgrp));
        mf6c.mf6cc_parent = in;
        memcpy( &mf6c.mf6cc_ifset , &(g->downstream_ifset), sizeof (struct if_set));

        if (setsockopt(mroute_socket, IPPROTO_IPV6, MRT6_ADD_MFC, &mf6c, sizeof(mf6c)) < 0) {
                log_msg(LOG_ERR, errno, " error adding MFC enrey ");
        }
}
