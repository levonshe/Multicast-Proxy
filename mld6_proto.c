/*	$KAME: mld6_proto.c,v 1.46 2005/05/19 08:11:26 suz Exp $	*/

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
/*
 * Part of this program has been derived from mrouted.
 * The mrouted program is covered by the license in the accompanying file
 * named "LICENSE.mrouted".
 *
 * The mrouted program is COPYRIGHT 1989 by The Board of Trustees of
 * Leland Stanford Junior University.
 *
 */
#include <time.h>
//#include <linux/time.h>
#include <sys/types.h>
#include <sys/param.h>
#include <errno.h>
#include <error.h>
//#include <sys/time.h>
#include <sys/socket.h>
#include <sys/times.h>
#include <sys/timerfd.h>

#include <sys/epoll.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#ifdef __linux__
#include <linux/mroute6.h>
#else
#include <netinet6/ip6_mroute.h>
#endif
#include <netinet/icmp6.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "defs.h"
#include "mld6.h"
#include "vif.h"
#include "mld6_proto.h"
#include "mld6v2.h"
#include "mld6v2_proto.h"
#include "debug.h"
#include "inet6.h"
#include "route.h"
#include "kern.h"
#include "mroute-api.h"
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC             1  //usr/include/bits/time.h
#define CLOCK_REALTIME              0
#endif

/*
 * Forward declarations.
 */
static void SendQuery (mifi_t mifi, struct sockaddr_in6 * mcast_group);
int mld_merge_with_upstream(mifi_t mifi, struct sockaddr_in6 * mcast_group_address ,short  mld_version , struct sockaddr_in6 * source);
//void recv_listener_report(short ifindex , mifi_t mifi, struct sockaddr_in6 *  src, struct sockaddr_in6 *mcast, short mld_version);
extern struct listaddr * make_new_group( mifi_t mifi,  struct sockaddr_in6* mcast_grp, short mld_version);
//static int create_report_timer ( struct listaddr *g);
//static int create_rxmt_timer ( struct listaddr *g);

//static int delete_report_timer ( struct listaddr *g);
//static int delete_rxmt_timer ( struct listaddr *g);



//static int stop_report_timer ( struct listaddr *g);
//static int start_report_timer ( struct listaddr *g, int secs);

//static void delete_group( mifi_t mifi, struct listaddr *group );

static void ExpireRtrmtTimer (void *p);
static void ExpireRFCTimer(void * p);

extern int epfd;  // created in main 

/*
 * Send group membership queries on that interface if I am querier.
 */
void
query_groups(struct uvif *v)
{
	v->uv_gq_timer = MLD6_QUERY_INTERVAL;
	{
		int ret;

		if (v->interfaceStartupQueryCount)
		{	
		   start_genQuery_timer ( v, MLD6_STARTUP_QUERY_INTERVAL  ); /* start Qeneric quries on interface query timer */
		   
		   v->interfaceStartupQueryCount--;
		}
		else
		{
		    start_genQuery_timer ( v, MLD6_QUERY_INTERVAL  ); /* start Qeneric quries on interface query timer */
		}   
		    
		ret = send_mld6(MLD_LISTENER_QUERY, 0,
			&v->uv_linklocal, NULL,
			(struct in6_addr *)&in6addr_any, v->uv_ifindex,
			MLD6_QUERY_RESPONSE_INTERVAL, 0, 1);
		if (ret == TRUE)
			v->uv_out_mld_query++;
	}
}

/*
 * Process an incoming host membership query
 */
#ifdef VIOLET // TODO  may come only from upsteream
void
accept_listener_query(iface, src, dst, group, tmo)
	short iface;
	struct sockaddr_in6 *src;
	struct in6_addr *dst, *group;
	int tmo;
{
	register int mifi;
	register struct uvif *v;
	register struct listaddr *g;
	struct sockaddr_in6 group_sa;

	init_sin6(&group_sa);

	/* Ignore my own listener query */
	if (locmcast_groupess(src) != NO_VIF)
		return;

	if ((mifi = find_vif_direct(src)) == NO_VIF) {
		IF_DEBUG(DEBUG_MLD)
			log_msg(LOG_INFO, 0,
			    "accept_listener_query: can't find a mif");
		return;
	}
	v = &uvifs[mifi];
	if ((v->uv_mld_version & MLDv1) == 0) {
		log_msg(LOG_WARNING,0,
		    "Mif %s configured in MLDv2 received MLDv1 query (src %s)!",
		    v->uv_name,sa6_fmt(src));
		return;
	}

	IF_DEBUG(DEBUG_MLD)
		printf(
		    "accepting multicast listener query on %s: "
		    "src %s, dst %s, grp %s",
		    v->uv_name,
		    sa6_fmt(src), inet6_fmt(dst), inet6_fmt(group));
	v->uv_in_mld_query++;

	if (!inet6_equal(&v->uv_querier->mcast_group, src)) {
		/*
		 * This might be:
		 * - A query from a new querier, with a lower source address
		 *   than the current querier (who might be me).
		 * - A query from a new router that just started up and
		 *   doesn't know who the querier is.
		 */
		 // LEV
		 //However, the querier election rules defined for MLDv2 do not apply to the eRouter.
		 // The eRouter MUST always act as an MLD querier on its Customer-Facing Interfaces
		// The eRouter MUST NOT perform the router portion of MLDv2 on the Operator-Facing Interface.
		if (inet6_lessthan(src,
				   (v->uv_querier ? &v->uv_querier->mcast_group
				    : &v->uv_linklocal))) {
			IF_DEBUG(DEBUG_MLD)
				printf( "new querier %s (was %s) "
				    "on mif %d",
				    sa6_fmt(src),
				    v->uv_querier ?
				    sa6_fmt(&v->uv_querier->mcast_group) :
				    "me", mifi);

			v->uv_flags &= ~VIFF_QUERIER;
			v->uv_querier->mcast_group = *src;
			time(&v->uv_querier->al_ctime);
		}
	}

	/*
	 * Ignore the query if we're (still) the querier.
	 */
	if ((v->uv_flags & VIFF_QUERIER) != 0)
		return;

	/*
	 * Reset the timer since we've received a query.
	 */
	if (v->uv_querier && inet6_equal(src, &v->uv_querier->mcast_group))
		v->uv_querier->al_timer = MLD6_OTHER_QUERIER_PRESENT_INTERVAL;

	/*
	 * If this is a Group-Specific query, we must set our membership timer
	 * to [Last Member Query Count] * the [Max Response Time] in the
	 * packet.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(group)) {
		printf(
			"nothing to do with general-query on router-side, "
			"except for querier-election");
		return;
	}

	IF_DEBUG(DEBUG_MLD)
		printf(
		    "%s for %s from %s on mif %d, timer %d",
		    "Group-specific membership query",
		    inet6_fmt(group), sa6_fmt(src), mifi, tmo);

	group_sa.sin6_addr = *group;
	group_sa.sin6_scope_id = inet6_uvif2scopeid(&group_sa, v);
	
	g = check_multicast_listener(v, &group_sa);
	if (g == NULL) {
		printf( "listener not found for %s on mif %d",
		    inet6_fmt(group), mifi);
		return;
	}
	if (g->group_rxmt_timer == 0) {
		printf(
		    "no query found for %s on mif %d", inet6_fmt(group), mifi);
		return;
	}

	/* setup a timeout to remove the group membership */
	if (g->group_report_timer)
		g->group_report_timer = DeleteTimer(g->group_report_timer);
	g->al_timer = MLD6_LAST_LISTENER_QUERY_COUNT * tmo / MLD6_TIMER_SCALE;

	/* use group_rxmt_timer to record our presence in last-member state */
	g->group_rxmt_timer = -1;
	g->group_report_timer = SetTimer(mifi, g);
	IF_DEBUG(DEBUG_MLD)
		printf(
		    "timer for grp %s on mif %d set to %ld",
		    inet6_fmt(group), mifi, g->al_timer);
}
#endif
/*
 * Process an incoming group membership report.
 */
void accept_listener_report( short ifindex,
	struct sockaddr_in6 *src,
	struct in6_addr *dst,struct in6_addr  *group)
{
	mifi_t mifi;
	struct uvif *v = NULL;
	struct sockaddr_in6 group_sa;
        printf(  // TODO Lev 
			    "accept_listener_report: group(%s) \n"
			    , inet6_fmt(group));
	
	if (IN6_IS_ADDR_MC_LINKLOCAL(group)) {
		IF_DEBUG(DEBUG_MLD)
		      //printf(
	               printf(  // TODO Lev 
			    "accept_listener_report: group(%s) has the "
			    "link-local scope. discard", inet6_fmt(group));
		return;
	}
	
        // just find mifi for physical interface =ifindex
	if ( (mifi = find_vif_by_ifindex(ifindex)) <0 ) {
		IF_DEBUG(DEBUG_MLD)
			log_msg(LOG_INFO, 0,
			    "accept_listener_report: can't find a mif");
		return;
	}

	v = &uvifs[mifi];
	init_sin6(&group_sa);
	group_sa.sin6_addr = *group;
	group_sa.sin6_scope_id = inet6_uvif2scopeid(&group_sa, v);

	if ((v->uv_mld_version & MLDv1) == 0) {
	      // TODO - check RFC to change mode
		printf(
		    "ignores MLDv1 report for %s on non-MLDv1 Mif %s",
		    inet6_fmt(group), v->uv_name);
		return;
	}

	IF_DEBUG(DEBUG_MLD)
		//printf(
	          printf(  // TODO Lev
		    "accepting multicast listener report: "
		    "src %s,dst %s, grp %s\n",
		    sa6_fmt(src),inet6_fmt(dst), inet6_fmt(group));

	v->uv_in_mld_report++;

	recv_listener_report(ifindex, mifi, src, &group_sa, MLDv1);
	
}

/* shared with MLDv1-compat mode in mld6v2_proto.c */
void
recv_listener_report(short ifindex , mifi_t mifi, struct sockaddr_in6 *  src, struct sockaddr_in6 *mcast, short mld_version)
{
	struct uvif *v = &uvifs[mifi];
	register struct listaddr *g;
	
	/*
	 * Look for the group in our group list; if found,
	 *  1) if necessary, shift to MLDv1-compat-mode
	 *  2) just reset MLD-related timers (nothing special is necessary
	 *     regarding compat-mode, since an MLDv2 TO_EX{NULL} message
	 *     is also handled in here in the same manner as MLDv1 report).
	 */
	g = check_multicast_listener(v, mcast);
	
	if (g != NULL) 
	{
	  
	      log_msg(LOG_DEBUG, 0, " Report for exiting group %s",sa6_fmt(mcast) );
		/* the group  FOUND */
		/* stop retransmit  timers */
		stop_rxmt_timer(g);
		
		start_report_timer( g, MLD6_LISTENER_INTERVAL );
		// Prepare next retransmit when (if) leave|done message will be heard
		g->llqc =(v->fastleave ) ? 0 :  v->uv_mld_llqc;  // Prepare retrt count of Group Specific queries
		return;
	}
        
	/* MAKE NEW GROUP , and add it to the list and update kernel cache. */
	
	
	
	if ( (g = make_new_group(  mifi, mcast, mld_version)) == NULL) 
	{
	        log_msg(LOG_ERR, 0, "make_new_group %s to interface %s failed", sa6_fmt(mcast) ,v->uv_name );
		return;
	}
	// else group created, start to poll it
	mld_merge_with_upstream ( mifi , mcast, mld_version, NULL); // /merge group

	return;
}

int mld_merge_with_upstream(mifi_t mifi,  struct sockaddr_in6 * mcast_group_address ,short  mld_version , struct sockaddr_in6 *source)
{
	register struct uvif *v = &uvifs[upStreamVif];
	register struct listaddr *g;
	short new_group=0;
	
	/*
	 * Look for the group in the interface's  group list; if found,
	 *  .
	 */
	
        g = check_multicast_listener(v,mcast_group_address );

	if (g == NULL )
	{
	       
               IF_DEBUG(DEBUG_IF)
		      printf(
			     "The group %s doesn't exist on Upstream interface %s, trying to add it\n", sa6_fmt(mcast_group_address), v->uv_name);

               g = make_new_group(  upStreamVif,  mcast_group_address, mld_version);  // Create a group
	       if (g == NULL) 
	       {
	          log_msg(LOG_ERR, 0, "make_new_group G=%s on Upstream interface %s  failed\n", sa6_fmt(mcast_group_address), v->uv_name);
		  return;
	       }
	       new_group=1;
	       
        }
	
	
	   
	if ( source != NULL && mld_version == MLDv2 )
	{
		 struct listaddr *s;
		 // Find whether multicast source address is already registered on upstream interface
		 s = check_multicastV2_listener(&uvifs[upStreamVif], mcast_group_address, g, source);
	
		 if  (s != NULL )
		 {
		      IF_DEBUG(DEBUG_IF)
		            printf( 
			      " (G,S) = (%s ,%s)  already exist in upstream interface database\n", sa6_fmt(mcast_group_address), sa6_fmt(source), v->uv_name);      
	              return;   // no merge required, source is present in upStreamVif
		 }
	          else
		  {
			s = make_new_source( upStreamVif , g, mcast_group_address, source );
			if (s == NULL) 
			{
			      log_msg(LOG_ERR, 0, "make_new_(group, source )= (%s,%s) on Upstream interface %s  failed\n", sa6_fmt(mcast_group_address),  sa6_fmt(source), v->uv_name);
			      return;
			}
			s->listeners++;  //Advance counter only for new source report
		  }
			  if (s == NULL) 
	          
		 // Only new source going to proxy join
		  
                  k_join_src( mld6_proxy_socket, mcast_group_address, source , upstream_idx);  // Add new  SSM to upstream interface,  (will exit on error)
                  IF_DEBUG(DEBUG_IF)
		            printf( 
			      " (G,S) = (%s ,%s)  join request sent on interface %s\n", sa6_fmt(mcast_group_address), sa6_fmt(source), v->uv_name);   
		  
	}
	else     
	{
	        if ( new_group)
		{
	        /* Make a proxy action - join the group */
                 k_join( mld6_proxy_socket, &mcast_group_address->sin6_addr,  upstream_idx);  //will exit on error
		 IF_DEBUG(DEBUG_IF)
		            printf( 
			      " (G,*) = (%s ,*)  join request sent on interface %s\n", sa6_fmt(mcast_group_address),  v->uv_name);
		}
        }
        
	// Prepare set of downstream interfaces when the cache miss will occur
         
         if  (! IF_ISSET(uvifs[mifi].uv_ifindex,  &(g->downstream_ifset)) )
	 {
	            g->listeners++;  //count only how many DS  interfaces are listening
                    IF_SET(uvifs[mifi].uv_ifindex,& (g->downstream_ifset));
		   
	            IF_DEBUG(DEBUG_IF)
		            printf( " interface %s  added to downstream ifset of (G,*)= %s\n", uvifs[mifi].uv_name, sa6_fmt(mcast_group_address));
	   
	}
	return g->listeners;
}


void accept_listener_done(
        short ifindex,
	struct sockaddr_in6 *src,
	struct in6_addr *dst, struct in6_addr* multicast_address)
{
	mifi_t mifi;
	struct uvif *v = NULL;
	struct sockaddr_in6 multicast_socket;
        if (ifindex == upstream_idx )
	    return;
	/* Don't create routing entries for the LAN scoped addresses */
	/* sanity? */
	if (IN6_IS_ADDR_MC_NODELOCAL(multicast_address)) {
		IF_DEBUG(DEBUG_MLD)
			printf(
			    "accept_listener_done: address multicast node "
			    " local(%s), ignore it...", inet6_fmt(multicast_address));
		return;
	}

	if (IN6_IS_ADDR_MC_LINKLOCAL(multicast_address)) {
		IF_DEBUG(DEBUG_MLD)
			printf(
			    "accept_listener_done: address multicast "
			    "link local(%s), ignore it ...", inet6_fmt(multicast_address));
		return;
	}

	if ((mifi = find_vif_by_ifindex(ifindex)) < 0) {
		IF_DEBUG(DEBUG_MLD)
			log_msg(LOG_INFO, 0,
			    "accept_listener_done: can't find a mif");
		return;
	}

	v = &uvifs[mifi];
	if ( v->state & VIFF_QUERIER == 0 ) // Sanity
	{
	  // RFC 2710 - done significant only on querier interfaces 
	  IF_DEBUG(DEBUG_MLD)
			log_msg(LOG_INFO, 0, "Got a Done on non querier interface %s", v->uv_name );
	  return;
	}
	if ( v->uv_groups == NULL ) // Sanity
	{
	  // RFC 2710 - done significant only when inerface is in listening state
	  // if it have registeres groups - it is listening  
	  IF_DEBUG(DEBUG_MLD)
			log_msg(LOG_INFO, 0, "Gat a Done on non listening interface %s", v->uv_name );
	  return;
	}
	init_sin6(&multicast_socket);
	multicast_socket.sin6_addr = *multicast_address;
	multicast_socket.sin6_scope_id = inet6_uvif2scopeid(&multicast_socket, v);

	/*
	 * MLD done does not affect mld-compatibility;
	 * draft-vida-mld-v2-05.txt section 7.3.2 says:
	 *  The Multicast Address Compatibility Mode variable is based
	 *  on whether an older version report was heard in the last
	 *  Older Version Host Present Timeout seconds.
	 */
	if ((v->uv_mld_version & MLDv1) == 0) {
		printf(
		    "ignores MLDv1 done for %s on non-MLDv1 Mif %s",
		    inet6_fmt(multicast_address), v->uv_name);
		return;
	}

	IF_DEBUG(DEBUG_MLD)
		log_msg(LOG_INFO, 0,
		    "accepting listener done message: src %s, dst %s, grp %s\n",
		    sa6_fmt(src), inet6_fmt(dst), inet6_fmt(multicast_address));
	v->uv_in_mld_done++;
        
	recv_listener_done(ifindex, mifi, src, &multicast_socket);
	
}


/* shared with MLDv1-compat mode in mld6v2_proto.c
 1  -send a group specific query to ensure no more subscribers exist 
*/
void
recv_listener_done(
	short ifindex,
	mifi_t mifi,
	struct sockaddr_in6 *src,struct sockaddr_in6  *group_multicast_socket )
{
	struct uvif *v = &uvifs[mifi];
	register struct listaddr *g;
	int ret = FALSE;

	/*
	 * XXX: in MLDv1-compat mode, non-querier is allowed to ignore MLDv2
	 * report?
	 */
	// XXX LEV if ((v->uv_flags & VIFF_QUERIER) == 0 && v->uv_pim_dr != NULL)
	// XXX	return;

	/*
	 * Look for the group in our group list in order to set up a
	 * short-timeout query.
	 */
	 g = check_multicast_listener(v,group_multicast_socket);

		if ( g == NULL) {
		    log_msg(LOG_ERR, 0, "[accept_done_message] for G=%s not exist on interface %s\n",
			       sa6_fmt(group_multicast_socket), v->uv_name);;
		}
		IF_DEBUG(DEBUG_MLD)
			printf( "[accept_done_message] for G=%s\n",
			       sa6_fmt( &g->mcast_group) );
			       
		if ( v->fastleave)
		{
		    delete_group(mifi ,g);
		    delete_group_upstream(mifi ,group_multicast_socket );  // Try to remove group on proxy if no more registered listeners on other interfaces
		    IF_DEBUG(DEBUG_MLD)
			printf( 
			     "Received  done_message for G=%s on FastLeave track \n",
			    sa6_fmt( &g->mcast_group) );
		    return;
		}
		
		/* still waiting for a reply to a query, ignore the done */
		if (g->llqc) {
		        IF_DEBUG(DEBUG_MLD)
			printf( "  Ignoring repeated done_message for G=%s\n",
			      sa6_fmt(&(g->mcast_group)));
			return;
		}
                g->llqc=MLD6_LAST_LISTENER_QUERY_COUNT;
		
		SendQuery(mifi, &g->mcast_group);
		v->uv_out_mld_query++;
		
		start_report_timer ( g, MLD6_LISTENER_INTERVAL); 
		
	        start_rxmt_timer ( g, 2);
			          
				 
	
}

void delete_group ( mifi_t mifi, struct listaddr *group )
{       
   struct listaddr *current;
   struct listaddr **head_of_list =  &(uvifs[mifi].uv_groups);  // head of the list - group stored perform interface
   IF_DEBUG(DEBUG_IF)
        log_msg (LOG_DEBUG, 0,
	         "Entering delete_group() G=%s for interface %s\n", sa6_fmt(&group->mcast_group), uvifs[mifi].uv_name  ) ;
   
	if (mifi != upStreamVif )
	{
	    delete_report_timer(group);
	    delete_rxmt_timer(group);
	}
	while ((current = * head_of_list) != NULL) 
        {
		if (current == group)
		{
			*head_of_list = current->al_next;  // chain next list element instead of current 
			free((char *) current);
		} 
		else
		{
			head_of_list = &current->al_next;
		}
	}
}

void delete_group_upstream ( mifi_t mifi, struct sockaddr_in6 * group_multicast)
{       
       short  intfce = uvifs[mifi].uv_ifindex;
       register struct uvif *v = &uvifs[upStreamVif];
       register struct listaddr *group;
      
       if_set zero;
       
       
       IF_ZERO(&zero);
       
        group = check_multicast_listener( v, group_multicast );
	
	if ( group == NULL )
	      log_msg(LOG_ERR, 0, "cannot delete a multicast group  for G=%s  on  interface %s, group not exist\n",
			       sa6_fmt(group_multicast), v->uv_name);;
        IF_DEBUG(DEBUG_IF)
        log_msg (LOG_DEBUG, 0,
	         "Entering delete_group_upstream G=%s\n", sa6_fmt(&group->mcast_group) ) ;
		 
	IF_DEBUG(DEBUG_IF)
        log_msg (LOG_DEBUG, 0,
	         "Entering delete_group_upstream G=%s\n", sa6_fmt(&group->mcast_group) ) ;	 
		 
	 IF_CLR( intfce, &(group->downstream_ifset));
	 
	// IF_DEBUG(DEBUG_IF)
         log_msg (LOG_DEBUG, 0,
		
	         "Clearing bitmask for %s  delete_group_upstream G=%s\n",  uvifs[mifi].uv_name,  sa6_fmt(&group->mcast_group) ) ;
	 
	 // Test if  other DS interface still have active listeners for this group
	 if ( memcmp( &group->downstream_ifset, &zero, sizeof(if_set)) == 0  )
	 {
	        // No more listeners
	         IF_DEBUG(DEBUG_IF)
                        log_msg (LOG_DEBUG, 0,
	                "No DS interfaces in ifset bitmask delete_group_upstream G=%s\n", sa6_fmt(&group->mcast_group) ) ;
	         k_leave( mld6_proxy_socket, &group->mcast_group.sin6_addr, upstream_idx);   // Send DONE|Leave  MLD message
	   
		 k_del_mfc(mroute_socket, &group->transmitter,  &group->mcast_group); // Delete mcast entries in kernel MFC cache
		 
		 delete_group(upStreamVif, group);
	        
		 
	 }
        
}	
	
/*
 * Send a group-specific query.  This function shouldn't be called when
 * the interface is configured with MLDv2, to prevent MLDv2 hosts from
 * shifting to MLDv1-compatible mode unnecessarily.
 * (now it's called only from SetQueryTimer() when the interface is
 *  configured in MLDv1, so the above condition is satisfied)
 */
static void
SendQuery(mifi_t mifi, struct sockaddr_in6* mcast_group)
{
	int8_t ret=0;
	register struct uvif *v = &uvifs[mifi];

	/* sanity check */
	if (v->uv_mld_version & MLDv2) {
		printf(
			"MLDv2-ready I/F %s cannot send MLDv1 Query",
			v->uv_name);
		return;
	}
	/*
		 * if an interface is configure in MLDv2, query is done
		 * by MLDv2, regardless of compat-mode.
		 * (draft-vida-mld-v2-05.txt section 7.3.2 page 39)
		 *
		 * if an interface is configured only with MLDv1, query
		 * is done by MLDv1.
		 */
	#ifdef HAVE_MLDV2
	if (v->uv_mld_version & MLDv2) {
			ret = send_mld6v2(MLD_LISTENER_QUERY, 0,
					  &v->uv_linklocal, NULL,
					  mcast_group, v->uv_ifindex,
					  MLD6_QUERY_RESPONSE_INTERVAL, 0, TRUE,
					  SFLAGNO, v->uv_mld_robustness,
					  v->uv_mld_query_interval, FALSE);
	}
	else
	#endif
	    if (v->uv_mld_version & MLDv1)
	    {
		ret = send_mld6(MLD_LISTENER_QUERY, 0,
				&v->uv_linklocal, NULL,
				&mcast_group->sin6_addr, v->uv_ifindex,
				 MLD6_QUERY_RESPONSE_INTERVAL, 0, 1);
	  }
	
	if (ret == TRUE)
		v->uv_out_mld_query++;
	
	
}


/*
 * Checks for MLD listener: returns TRUE if there is a receiver for the group
 * on the given uvif, or returns FALSE otherwise.
 */
struct listaddr *
check_multicast_listener( struct uvif *v  ,struct sockaddr_in6 *group)
{
	struct listaddr *g;

	/* Look for the group in our listener list. */
	for (g = v->uv_groups; g != NULL; g = g->al_next) {
		if (inet6_equal(group, &g->mcast_group))
			break;
	}
	return g;
}

struct listaddr * find_group_in_list(struct uvif *v, struct listaddr * group)
{
	struct listaddr *g;

	/* Look for the group in our listener list. */
	for (g = v->uv_groups; g != NULL; g = g->al_next) {
		if (g == group )
			break;
	}
	return g;
}
/* Make new group as responce to MLD report message */
struct listaddr *  make_new_group(mifi_t mifi ,  struct sockaddr_in6 *grp , short mld_version)
{
    
	register struct listaddr * g;
	register struct uvif *v=&uvifs[mifi];
	
	
	IF_DEBUG(DEBUG_MLD)
		printf(
		    "The group %s is new, trying to add it to interface %s\n",sa6_fmt(grp), v->uv_name  );
		
	g = (struct listaddr *) malloc(sizeof(struct listaddr));
	if (g == NULL)
	{
		log_msg(LOG_ERR, 0, "ran out of memory");	/* fatal */
		exit(15);
	}
	memset(g, 0, sizeof(*g));
	memcpy(&g->mcast_group , grp, sizeof(*grp));
	
	if ( mifi != upStreamVif )
	{
	create_rxmt_timer (g,  ExpireRtrmtTimer);   /* Create timer to wait for group leave expiration */
	g->rxmt_timer_callback.mifi=mifi;
	g->rxmt_timer_callback.g=g;
	
	g->rxmt_timer_callback.q_time=MLD6_LISTENER_INTERVAL;
	g->rxmt_timer_callback.mcast_group=&g->mcast_group;
	
	create_report_timer (g, ExpireRFCTimer); /* Create timer to wait for membership expiration */
	
	
	g->report_timer_callback.q_time=MLD6_LISTENER_INTERVAL;
	g->report_timer_callback.mcast_group=&g->mcast_group;
	g->report_timer_callback.mifi=mifi;
	
	/* Start timer to wait for membership expiration */
	    start_report_timer (g, MLD6_LISTENER_INTERVAL);
	}
	g->comp_mode = mld_version;
	
	if (g->comp_mode == MLDv2)
		g->filter_mode = MODE_IS_EXCLUDE;
	if ((uvifs[mifi].uv_mld_version & MLDv2) && (g->comp_mode == MLDv1))
	{
		printf(
			"created a group in MLDv1 compat-mode for %s on Mif %s",
			sa6_fmt(grp),uvifs[mifi].uv_name);
	}
	g->llqc =(v->fastleave ) ? 0 :  v->uv_mld_llqc;  // Prepare retrt count of Group Specific queries
	/* insert group fist  in the list of the groups of this interface */
	g->al_next = v->uv_groups;
	v->uv_groups = g;
        time(&g->al_ctime);
	return g;
}


void ExpireRtrmtTimer (void *p)
{
  timer_cbk_t * params = (timer_cbk_t *) p;
  register struct uvif *v= &uvifs[params->mifi];
 
	 
  if ( (! p ) || (!  params->g) )
  {
      log_msg(LOG_ERR, 0,
			"ExpireRtrmtTimer callback parameters sanity, (p=%p) group param->g=%p NULL", p, params->g);
      exit(15);
  }
   if ( ! find_group_in_list( v, params->g) )
  {
      log_msg(LOG_ERR, 0,
                         "BUG ExpireRtrmtTimer, group %s does not exist at interface %s\n", sa6_fmt(&params->g->mcast_group), params->mifi);
      exit (15);
  }
  IF_DEBUG(DEBUG_TIMER)
      printf("ExpireRtrmtTimer for G=%s  timeout at %lu \n",
	      sa6_fmt(&(params->g->mcast_group)), time(NULL) -  params->g->al_timer);
  /*
   * Multicast-Address-Specific Queries sent in response to
   Done messages ,
 */
  if ( (params->g->llqc--) <=0 )
  {
      IF_DEBUG(DEBUG_TIMER)
	  log_msg(LOG_DEBUG, 0,
	   
			"ExpireRtrmtTimer, group %s  at interface %s  Rtrtm counter is %d and timer must be  stopped\n", sa6_fmt(&params->g->mcast_group), uvifs[params->mifi].uv_name, params->g->llqc );
      stop_rxmt_timer ( params->g);
      delete_group_upstream (params->mifi, &params->g->mcast_group);
      delete_group (params->mifi, params-> g);
      return;
  }
  else
  {
	switch( params->g->comp_mode )
	{
       case MLDv1:
		      SendQuery( params->mifi, &params->g->mcast_group); break;
       case MLDv2: 
		      Send_GS_QueryV2(&uvifs[params->mifi], params->g); break;
	default:
	      log_msg(LOG_WARNING, 0, "interface %s mld mode is invalid, neither MLDv1 nor MLDv2" , uvifs[params->mifi].uv_name);
	}	
     
  }
  
   IF_DEBUG(DEBUG_TIMER)
	  log_msg(LOG_DEBUG, 0,
			"ExpireRtrmtTimer, group %s  at interface %s  Rtrtm counter is %d , starting report_timer\n", sa6_fmt(&params->g->mcast_group), uvifs[params->mifi].uv_name ,params->g->llqc );
     start_report_timer ( params->g, 
			     MLD6_ROBUSTNESS_VARIABLE *  
			    MLD6_QUERY_RESPONSE_INTERVAL);  // Checking listeners mode, 2 timers ru
 
}
int create_rxmt_timer ( struct listaddr *g, cfunc_t  callback )
{	
   int rc;
	IF_DEBUG(DEBUG_TIMER)
        printf( 
	       "create_rxmt_timer for G=%s \n", sa6_fmt(&g->mcast_group));
	rc=g->group_rxmt_timer = timerfd_create( CLOCK_MONOTONIC ,0 ) ;
	if (rc < 0) 
        {
                log_msg(LOG_ERR, errno, "cannot create rxmt_timer");
                exit(10);
        }
   
	g->group_rxmt_timer_event.events=EPOLLIN;
	
	g->rxmt_timer_callback.g=g;
	g->rxmt_timer_callback.callback=callback;
        g->group_rxmt_timer_event.data.ptr= &g->rxmt_timer_callback;
	
        /* add timer  to the timers poll set/queue */
	rc=epoll_ctl(epfd, EPOLL_CTL_ADD, g->group_rxmt_timer,  &g->group_rxmt_timer_event);
	if (rc < 0) 
        {
                log_msg(LOG_ERR, errno, "cannot add  rxmt_timer to epoll list");
                exit(10);
       }
      return 0;
}
int start_rxmt_timer ( struct listaddr *g, short sec)
{
    struct itimerspec  tspec;
	short secs;
	int rc;
	IF_DEBUG(DEBUG_TIMER)
        printf(
	      "start_rxmt_timer for G=%s with period=%d\n", sa6_fmt(&g->mcast_group ),sec); 
	if (g->group_rxmt_timer <=0)
	{
	   log_msg(LOG_CRIT, 0, "Rxmt_timer was not created for G=%s ", sa6_fmt(&g->mcast_group ));
	   
	}
        secs= (sec  <=0 )  ? 1 : (sec % 10);
	 /*minimum leave - 1sec, retransmit delay could not be . 10- sec */
	IF_DEBUG(DEBUG_TIMER)
        printf(
	      "Correction :start_rxmt_timer for G=%s with period=%d\n", sa6_fmt(&g->mcast_group ),secs); 
	tspec.it_interval.tv_sec=secs; // timer interval
	tspec.it_interval.tv_nsec=random() % 10000;
	tspec.it_value.tv_sec=secs; // timer first expire at tv_sec
	tspec.it_value.tv_nsec=random() % 100000;
	rc=timerfd_settime(g->group_rxmt_timer, 0, &tspec, NULL);
	if (rc < 0) 
        {
                log_msg(LOG_ERR, errno, "cannot start rxmt_timer ");
                exit(10);
         }
         g->al_timer=time(NULL);
  return 0;
}

int stop_rxmt_timer ( struct listaddr *g)
{
        struct itimerspec  tspec;
	int rc;
	IF_DEBUG(DEBUG_TIMER)
	    log_msg(LOG_DEBUG, 0, "Stop rxmt timer of G,S =%s,%s on %s ", sa6_fmt(&g->rxmt_timer_callback.g->mcast_group ), 
		         (g->rxmt_timer_callback.source) ?sa6_fmt(&g->rxmt_timer_callback.source->mcast_group) : NULL, 
	                  uvifs[g->rxmt_timer_callback.mifi].uv_name);
	   
	memset(&tspec,0, sizeof(tspec));
	
	if (g->group_rxmt_timer)
	{
	  
 	    /* report received :-  delete leave timer from timers poll set */
	    rc= timerfd_settime(g->group_rxmt_timer, 0, &tspec, NULL); // tspec Zero stops the timer
	    if (rc < 0) 
             {
                log_msg(LOG_ERR, errno, "cannot stop  rxmt_timer ");
                exit(10);
             }	
		
	}
	return 0;
}

void ExpireRFCTimer(void * p)
{
  timer_cbk_t * params=(timer_cbk_t *) p;
  /* Group membership had expired */
  /* if no reports was heard, send query - No */
  /* RFC says 
    If an address's timer expires, it is
   assumed that there are no longer any listeners for that address
   present on the link, so it is deleted from the list and its
   disappearance is made known to the multicast routing component.
   */
  
   if ( (! p ) || (!  params->g) )
   {
      log_msg(LOG_ERR, 0,
			"ExpireReport Timer, callback parameters  NULL");
      exit(15);
   }
   if ( ! find_group_in_list( &uvifs[params->mifi], params->g) )
   {
       log_msg(LOG_ERR, 0,
			"BUG ExpireReportTimer, group %s does not exist at interface %s", sa6_fmt(&params->g->mcast_group), uvifs[params->mifi].uv_name );
      exit (15);
   }
   IF_DEBUG(DEBUG_TIMER)
   printf( 
          "Expired Report Timer for G=%s,  timeout in %lu secs\n",
         sa6_fmt( &(params->g->mcast_group)) , time(NULL) -  params->g->al_timer);
  
   delete_group (params->mifi, params-> g);
   delete_group_upstream (params->mifi, & params-> g->mcast_group);
} 
int create_report_timer ( struct listaddr *g, cfunc_t  callback)
{	
        int rc;
	printf("create_report_timer\n");
	rc=g->group_report_timer = timerfd_create( CLOCK_MONOTONIC , 0) ;
	if (rc <= 0) 
        {
            log_msg(LOG_ERR, errno, "cannot create group_report_timer ");
            exit(10);
        }
	g->group_report_timer_event.events=EPOLLIN;
         g->report_timer_callback.callback= (void *) callback;
	 g->report_timer_callback.g = g;
         g->group_report_timer_event.data.ptr = &g->report_timer_callback;
         /* add timer  to the timers poll set/queue */
	rc=epoll_ctl(epfd, EPOLL_CTL_ADD, g->group_report_timer,  &g->group_report_timer_event);
	if (rc < 0) 
        {
            log_msg(LOG_ERR, errno, "cannot add group_report_timer to epoll list");
            exit(10);
        }
        return 0;
}
int start_report_timer ( struct listaddr *g, short secs)
{
        struct itimerspec  tspec;
	int rc;
     
        printf(
	       "start_report_timer of G=%s for period=%d secs\n", sa6_fmt(&g->mcast_group ), secs); 
	if (g->group_report_timer <=0 )
	{
		        //log_msg(LOG_ALERT,0, "The group already exists, but report timer was not created as it should");
			
	}
	rc=secs;
	rc=50; // TODO LEV
        /* If no state change - just renew the timer */
	tspec.it_interval.tv_sec=rc+1; // timer period
	tspec.it_interval.tv_nsec=random() % 100000;
	tspec.it_value.tv_sec=rc; // timer expiration
	tspec.it_value.tv_nsec=random() % 100000;
	rc = timerfd_settime(g->group_report_timer, 0, &tspec, NULL);
	if (rc <0 )
	{
	    log_msg(LOG_ERR, errno, "BUG The group G=%s , cannot start report timer at % nsecs ", sa6_fmt(&g->mcast_group ),tspec.it_value.tv_nsec );
			exit(10);
	}
	g->al_timer=time(NULL);
}


int stop_report_timer ( struct listaddr *g)
{	struct itimerspec  tspec;
	int rc;
	memset(&tspec,0, sizeof(tspec) );
	IF_DEBUG(DEBUG_TIMER)
	      printf(
	       " stop_report_timer of G =%s\n", sa6_fmt(&g->mcast_group)) ;
	if (g->group_report_timer)
	{
 	        /* report received :-  delete leave timer from timers poll set */
		rc=timerfd_settime(g->group_report_timer, 0, &tspec, NULL); // tspec Zero stops the timer
		if (rc <0 )
	      {
		      log_msg(LOG_ERR, errno, "BUG: cannot stop report timer of G =%s\n", sa6_fmt(&g->mcast_group ));
		      exit(10);
	      }
	}
	
	return 0;
}

int delete_report_timer ( struct listaddr *g)
{
  struct itimerspec  tspec;
  IF_DEBUG(DEBUG_TIMER)
	  printf(" delete_report_timer of G =%s\n", sa6_fmt(&g->mcast_group));
  memset(&tspec,0, sizeof(tspec) );
  if (g->group_report_timer)
  {
      timerfd_settime(g->group_report_timer, 0, &tspec, NULL);
      IF_DEBUG(DEBUG_TIMER)
	    log_msg(LOG_DEBUG, 0, "Delete report timer of G,S =%s,%s on %s ", sa6_fmt(&g->mcast_group ), 
		         (g->report_timer_callback.source) ?sa6_fmt(&g->report_timer_callback.source->mcast_group) : NULL, 
	                  uvifs[g->rxmt_timer_callback.mifi].uv_name);
	   
      if (epoll_ctl(epfd, EPOLL_CTL_DEL,g->group_report_timer, &g->group_report_timer_event ) < 0) 
      {
	   log_msg(LOG_ERR,errno, "cannot remove group_report_timer of G =%s from epoll list", sa6_fmt(&g->mcast_group ));
            exit(10);
       }
       close(g->group_report_timer);
       g->group_report_timer=0;
       
  }
}
int delete_rxmt_timer ( struct listaddr *g)
{ 
  struct itimerspec  tspec;
  
	
  memset(&tspec,0, sizeof(tspec) );
  
  if (g->group_rxmt_timer)
  {
       timerfd_settime(g->group_rxmt_timer, 0, &tspec, NULL);
       IF_DEBUG(DEBUG_TIMER)
	    log_msg(LOG_DEBUG, 0, "Delete rxmt timer of G,S =%s,%s on %s ", sa6_fmt(&g->mcast_group ), 
		         (g->rxmt_timer_callback.source) ?sa6_fmt(&g->rxmt_timer_callback.source->mcast_group) : NULL, 
	                  uvifs[g->rxmt_timer_callback.mifi].uv_name);
	   
  
      if (epoll_ctl(epfd, EPOLL_CTL_DEL,g->group_rxmt_timer, &g->group_rxmt_timer_event ) < 0) 
      {
          log_msg(LOG_ERR, errno, "cannot remove group_rxmt_timer from epoll list");
          exit(10);
      }
      close(g->group_rxmt_timer);
      g->group_rxmt_timer=0;
  }
}


void ExpireGenericQueryTimer (void *p );
int create_genQuery_timer (mifi_t mifi, struct uvif *v)
{	
	v->uv_genQuery_timer = timerfd_create( CLOCK_MONOTONIC , 0 ) ;
	if ( ! v->uv_genQuery_timer )
	{
	  perror("Cannot create Generic Queries  Timer");
	  log_msg(LOG_DEBUG,errno, "Cannot create Generic Queries  Timer ");
	}
	v->uv_genQuery_timer_event.events=EPOLLIN;
	v->uv_genQuery_timer_event.data.ptr=&v->uv_genQuery_timer_callback;
        v->uv_genQuery_timer_callback.callback = ExpireGenericQueryTimer;
	v->uv_genQuery_timer_callback.mifi = mifi;
	v->uv_genQuery_timer_callback.v = v;
	printf("adding epoll event %p\n", v->uv_genQuery_timer_event.data.ptr );
	/* add timer  to the timers poll set/queue */
	if (epoll_ctl( epfd, EPOLL_CTL_ADD, v->uv_genQuery_timer,  &v->uv_genQuery_timer_event)  < 0 )
	{
	    perror("Cannot Add Generic Queries  Timer Event");
	}
	IF_DEBUG(DEBUG_TIMER)
	      printf("Created Generic queries timer \n");
        return 0;
}
int start_genQuery_timer ( struct uvif *v, int secs)
{
    struct itimerspec  tspec;
	int rc;
        IF_DEBUG(DEBUG_TIMER)
	    printf("start Generic queries timer with period=%d\n", secs); 
	if (v->uv_genQuery_timer <=0 )
	{
		        log_msg(LOG_ERR,0, "The uvif already exists, but timer was not created as it should");
			exit(10);
	}
        /* If no state change - just renew the timer */
        rc=secs;
	tspec.it_interval.tv_sec=rc; // timer period
	tspec.it_interval.tv_nsec=random() % 100000;
	tspec.it_value.tv_sec=rc -1; // Initial timer expiration LEV
	tspec.it_value.tv_nsec=random() % 100000;
	IF_DEBUG(DEBUG_TIMER)
	    printf("start_genQuery_timer  epfd=%d tfd=%d, interval=%u, nsec=%lu\n", epfd, v->uv_genQuery_timer,tspec.it_interval.tv_sec, tspec.it_interval.tv_nsec );
	rc=timerfd_settime(v->uv_genQuery_timer, 0, &tspec, NULL);
	if (rc <0 )
	{
	    log_msg(LOG_ERR,errno, "Cannot renew the  genQuery timer ");
			exit(10);
	}
}


int stop_genQuery_timer ( struct uvif *v)
{	
        struct itimerspec  tspec;
	memset(&tspec,0, sizeof(tspec) );
	IF_DEBUG(DEBUG_TIMER)
	    printf(" stop Generic queries timer \n");
	if (v->uv_genQuery_timer)
	{
	      timerfd_settime(v->uv_genQuery_timer, 0, &tspec, NULL); // tspec Zero stops the timer
	}
	return 0;
}

int delete_genQuery_timer ( struct uvif *v)
{
    struct itimerspec  tspec;
    IF_DEBUG(DEBUG_TIMER)
	  printf("delete Generic queries timer \n");
    memset(&tspec,0, sizeof(tspec) );
    if (v->uv_genQuery_timer)
	timerfd_settime(v->uv_genQuery_timer, 0, &tspec, NULL);
    if (epoll_ctl(epfd, EPOLL_CTL_DEL,v->uv_genQuery_timer, &v->uv_genQuery_timer_event ) < 0) 
    {
	log_msg(LOG_ERR, errno, "cannot disable uv_genQuery_timer ");
	exit(10);
   }
    close(v->uv_genQuery_timer);
}
void ExpireGenericQueryTimer (void *p )
{
    
    /* rearm the timer ? */
    uvif_timer_cbk_t * params=(uvif_timer_cbk_t *) p;
    register struct uvif *v=&uvifs[params->mifi];
    IF_DEBUG(DEBUG_TIMER)
	  printf("ExpireGenericQueryTimer\n");
    switch (v->uv_mld_version)
    {
      case MLDv2 :
		  {
		  query_groupsV2(v);
		  break;
		  }
      case MLDv1 :
		  {
		  query_groups(v);
		  break;
		  }
      default:
	      log_msg(LOG_WARNING, 0, "interface %s mld mode is invalid, neither MLDv1 nor MLDv2" , v->uv_name);
    }
}
