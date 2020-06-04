/*	$KAME: vif.c,v 1.45 2005/05/19 08:11:27 suz Exp $	*/

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

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/epoll.h>
#include <bits/time.h>

#include <sys/timerfd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#ifdef __linux__
#include <linux/mroute6.h>
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC             1  //usr/include/linux/time.h
#endif
//#include <linux/time.h>
#else
#include <netinet6/ip6_mroute.h>
#endif
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <ifaddrs.h>
#include "defs.h"
#include "vif.h"
#include "mld6.h"
#include "mld6v2.h"
#include "route.h"
#include "config.h"
#include "inet6.h"
#include "kern.h"
#include "mld6_proto.h"
#include "mld6v2_proto.h"
#include "debug.h"


struct uvif	uvifs[MAXUVIFS];	/*the list of virtualsinterfaces */
struct mfc_cache_stat mfc_cache_stat;
mifi_t numvifs;				/*total number of interface */
u_int16_t upStreamVif;
u_int16_t upstream_idx;

int vifs_down;

int default_vif_status;
int phys_vif; /* An enabled vif that has a global address */
int udp_socket;
int total_interfaces;
if_set			if_nullset;
if_set			if_result;

void start_all_vifs __P((void));
void start_vif __P((mifi_t vifi));
void stop_vif __P((mifi_t vivi));
int update_reg_vif __P((mifi_t register_vifi));
static int move_to_mldv2_mode(void * p);

static int delete_back_to_mldv2_timer ( struct uvif *v);
static int start_back_to_mldv2_timer ( struct uvif *v, int secs);
static int stop_back_to_mldv2_timer ( struct uvif *v);
static int create_back_to_mldv2_timer ( mifi_t mifi, struct uvif *v);
extern void add_phaddr __P((struct uvif *, struct sockaddr_in6 *,
		           struct in6_addr *, struct sockaddr_in6 *));
static int read_config(void);

static int read_config(void)
{
     if( ! loadConfig( configfilename ) ) {
            log_msg(LOG_ERR, 0, "Unable to load config file...");
          exit(8);
    }
    // Configures VIF states and settings
    return  configureVifs(); 
     // counts from 1, but array is numfis -1
}

void init_vifs()
{
	mifi_t vifi;
	struct uvif *v;
	int enabled_vifs;

	numvifs = 0;
	memset(&uvifs[0], 0,  sizeof(uvifs) );
	memset(&mfc_cache_stat, 0, sizeof(mfc_cache_stat) );

	/*
	 * Configure the vifs based on the interface configuration of
	 * the kernel and the contents of the configuration file.
	 * (Open a UDP socket for ioctl use in the config procedures if
	 * the kernel can't handle IOCTL's on the MLD socket.)
	 */

/* TODO - send_mld6
	udp_socket=mld6_socket;

	if (udp_socket <=0 )
	    log_msg(LOG_ERR, errno, "Fail - no UDP6 socket to get/set network interface flags");

*/
	
	for (vifi = 0, v = uvifs; vifi < MAXUVIFS; ++vifi, ++v) {
		memset(v, 0, sizeof(*v));
		
		v->uv_mld_version = MLD6_DEFAULT_VERSION;
		v->uv_mld_robustness = MLD6_DEFAULT_ROBUSTNESS_VARIABLE;
		v->uv_mld_query_interval = MLD6_DEFAULT_QUERY_INTERVAL;
		v->uv_mld_query_rsp_interval = MLD6_DEFAULT_QUERY_RESPONSE_INTERVAL;
		v->uv_mld_llqi = MLD6_DEFAULT_LAST_LISTENER_QUERY_INTERVAL;
		v->uv_mld_llqc = MLD6_DEFAULT_ROBUSTNESS_VARIABLE; 
	}
	IF_DEBUG(DEBUG_IF)
		log_msg(LOG_DEBUG, 0, "Interfaces world initialized...");
	IF_DEBUG(DEBUG_IF)
		log_msg(LOG_DEBUG, 0, "Getting vifs from %s", configfilename);
        enabled_vifs=read_config(); // returns N of interfaces  N DS +1 UP
	
        numvifs=enabled_vifs+1;  /* enabled_vifs -counting from 0, */
	if ( numvifs < 2)  /* counting from 1, */
		log_msg(LOG_ERR, 0, "can't forward: %s",
		    enabled_vifs == 0 ? "no enabled vifs" :
		     "only one enabled vif");
	numvifs = enabled_vifs+1;
        printf ( "Found %d interfaces in the config file \n", numvifs);
	for (vifi = 0, v = uvifs; vifi < numvifs; ++vifi, ++v)
        {
	   config_vif_from_kernel(v);
        }
        IF_DEBUG(DEBUG_IF)
	     dump_vifs(log_fp);

}


void start_all_vifs(void)
{
	mifi_t vifi;
	struct uvif *v;
	u_int action;

	
	for (vifi = 0, v = uvifs; vifi < numvifs; ++vifi, ++v) {
			

			if (v->state == IF_STATE_DISABLED) {
				IF_DEBUG(DEBUG_IF)
					log_msg(LOG_DEBUG, 0,
					    "%s is %s; vif #%u out of service",
					    v->uv_name,
					    v->state & IF_STATE_DISABLED ? "DISABLED" : "DOWN",
					    vifi); 
				continue;
			}
			start_vif(vifi);
	}
}

/*
 * Initialize the vif and add to the kernel. The vif can be either
 * physical, register or tunnel (tunnels will be used in the future
 * when this code becomes PIM multicast boarder router.
 */
void start_vif (mifi_t vifi)
{
	struct uvif *v;

	v = &uvifs[vifi];
	
	// Sanity
	if ( ! (v->uv_ifindex) )
	{
	    log_msg(LOG_ERR, 0 , "start_vif() Sanity check failed for %s, vifi=%d",v->uv_name,vifi);
	    return; // wrong interface 
	}

	/* Tell kernel to add, i.e. start this vif */

	k_add_vif(mld6_socket,vifi,&uvifs[vifi]);
	IF_DEBUG(DEBUG_IF)
		log_msg(LOG_DEBUG,0,"%s comes up ,vif #%u now in service",v->uv_name,vifi);

	if ((v->uv_ifindex != upstream_idx ))
	{ /* not upstream */
	    /*
	     * Join the ALL-ROUTERS multicast group on the interface.
	     * This allows mtrace requests to loop back if they are run
	     * on the multicast router.this allow receiving mld6 messages too.
	     */
	    k_join(mld6_socket, &allrouters_group.sin6_addr, v->uv_ifindex);

	    /*
	     * Until neighbors are discovered, assume responsibility for sending
	     * periodic group membership queries to the subnet.  Send the first
	     * query.
	     */
	    v->uv_flags |= VIFF_QUERIER;
	    
	   
	    if (v->interfaceStartupQueryCount <=0 )
	        v->interfaceStartupQueryCount = MLD6_DEFAULT_ROBUSTNESS_VARIABLE ;
	    
	    create_genQuery_timer (vifi, v);

#ifdef HAVE_MLDV2 // TODO

            if (v->uv_mld_version & MLDv2)          
                query_groupsV2(v); 
            else
                if (v->uv_mld_version & MLDv1)  
#endif
                        query_groups(v);        
  
	} /* not upstream */
}

/*
 * Stop a vif (either physical interface, tunnel or
 * register.) If we are running only PIM we don't have tunnels.
 */ 


void
stop_vif(mifi_t vifi)
{
	struct uvif *v;
	struct listaddr *a;
	
 
	/*
	 * TODO: make sure that the kernel viftable is
	 * consistent with the daemon table
	 */
	v = &uvifs[vifi];
	if (vifi !=upStreamVif )
	{ /* not upstream */
		stop_genQuery_timer ( v); /* stop Generic Queries timer */
		k_leave(mld6_socket, &allrouters_group.sin6_addr,
			v->uv_ifindex);

		/*
		 * Discard all group addresses.  (No need to tell kernel;
		 * the k_del_vif() call will clean up kernel state.)
		 */
		while (v->uv_groups != NULL)
		{
			a = v->uv_groups;
			v->uv_groups = a->al_next;
			stop_genQuery_timer(v);
			/* reset all the timers */
			delete_report_timer (a);
			delete_rxmt_timer (a);


			/* frees all the related sources */
			while (a->sources != NULL) {
			    struct listaddr *curr = a->sources;
			    a->sources = a->sources->al_next;
			    delete_report_timer (curr);
			    delete_rxmt_timer (curr);
			    free((char *)curr);
			}
			a->sources = NULL;

			/* discard the group */
			delete_group (vifi,  a);
			delete_group_upstream (vifi, &a->mcast_group);
			free((char *)a);
		}
		v->uv_groups = NULL;    
	} /* not upstream */
	/*
	 * Delete the interface from the kernel's vif structure.
	 */
	if (vifi !=upStreamVif )
	{
	    delete_genQuery_timer ( v);
	   
	}
	k_del_vif( mld6_socket, vifi);
	v->uv_flags = (v->uv_flags & ~VIFF_QUERIER & ~VIFF_NONBRS) | VIFF_DOWN;

        
	// TODO -stop back_to_mldv2_timer
	/*TODO
	if (v->uv_querier != NULL) {
	    free(v->uv_querier);
	    v->uv_querier = NULL;
	}
        */
	/* I/F address list */
	

	vifs_down = TRUE;

	IF_DEBUG(DEBUG_IF)
		log_msg(LOG_DEBUG, 0, "%s goes down, vif #%u out of service",
			v->uv_name, vifi);
}

int config_vif_from_kernel( struct uvif *v)
{

	short rc=0;
	struct sockaddr_in6 addr;
	struct in6_addr mask;
	short flags;
	struct ifaddrs *ifap, *ifa;

	return rc;
}





/*  
 * See if any interfaces have changed from up state to down, or vice versa,
 * including any non-multicast-capable interfaces that are in use as local
 * tunnel end-points.  Ignore interfaces that have been administratively
 * disabled.
 */     
void
check_vif_state()
{
    register mifi_t vifi;
    register struct uvif *v;
    struct ifreq ifr;
    static int checking_vifs=0;

    /*
     * XXX: TODO: True only for DVMRP?? Check.
     * If we get an error while checking, (e.g. two interfaces go down
     * at once, and we decide to send a prune out one of the failed ones)
     * then don't go into an infinite loop!
     */
    if( checking_vifs )
	return;

    vifs_down=FALSE;
    checking_vifs=TRUE;

    /* TODO: Check all potential interfaces!!! */
    /* Check the physical and tunnels only */
    for( vifi=0 , v=uvifs ; vifi<numvifs ; ++vifi , ++v )
    {
	if( v->uv_flags & ( VIFF_DISABLED|MIFF_REGISTER	) )
	    continue;

	strncpy(ifr.ifr_name, v->uv_name, IFNAMSIZ);
  
	/* get the interface flags */
	if( ioctl( udp_socket , SIOCGIFFLAGS , (char *)&ifr )<0 )
	    log_msg(LOG_ERR, errno,
        	"check_vif_state: ioctl SIOCGIFFLAGS for %s", ifr.ifr_name);

	if( v->uv_flags & VIFF_DOWN )
	{
	    if ( ifr.ifr_flags & IFF_UP )
	    {
		start_vif( vifi );
	    }
	    else
		vifs_down=TRUE;
	}
	else
	{
	    if( !( ifr.ifr_flags & IFF_UP ))
	    {
		log_msg( LOG_NOTICE ,0,
		     "%s has gone down ; vif #%u taken out of  service",
		     v->uv_name , vifi );
		stop_vif ( vifi );
		vifs_down = TRUE;
	    }
	}
    }

    checking_vifs=0;
}



/*  
 * If the source is directly connected, or is local address,
 * find the vif number for the corresponding physical interface
 * (tunnels excluded).
 * Return the vif number or NO_VIF if not found.
 */ 

mifi_t
find_vif_by_ifindex(int ifindex)
{
   register struct uvif *v;
   register int i;
   for (i = 0, v = uvifs; i < numvifs; i++) {
        if ( v->uv_ifindex == ifindex )
	  return i;
        v++;
   }
return -1;
}
/*  
 * If the source is directly connected, or is local address,
 * find the vif number for the corresponding physical interface
 * (tunnels excluded).
 * Return the vif number or NO_VIF if not found.
 */ 



/*  
 * stop all vifs
 */ 
void
stop_all_vifs()
{
    mifi_t vifi;
    struct uvif *v;
 
    for (vifi = 0, v=uvifs; vifi < numvifs; ++vifi, ++v) {
	if (v->uv_flags & (VIFF_DOWN | VIFF_DISABLED))
		continue;
	stop_vif(vifi);
    }
}

void TimerExpire_and_move_to_mldv2_mode (void *p);


