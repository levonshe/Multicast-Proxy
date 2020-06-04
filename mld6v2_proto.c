/*
 * $KAME: mld6v2_proto.c,v 1.50 2005/05/19 08:11:26 suz Exp $
 */

/*
 * Copyright (C) 1999 LSIIT Laboratory.
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
 * This program has been derived from pimd.
 * The pimd program is covered by the license in the accompanying file
 * named "LICENSE.pimd".
 *
 */
#include <errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#ifdef __linux__
#include <linux/mroute6.h>
#else
#include <netinet6/ip6_mroute.h>
#endif
#include <netinet/icmp6.h>
#include <linux/mroute6.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include "defs.h"
#include "vif.h"
#include "mld6.h"
#include "mld6_proto.h"
#include "mld6v2_proto.h"
#include "debug.h"
#include "inet6.h"
#include "mld6v2.h"
#include "mroute-api.h"
#include "route.h"
#include "kern.h"


#ifdef HAVE_MLDV2

 /* MLDv2 implementation
  *   - MODE_IS_INCLUDE, ALLOW_NEW_SOURCES, BLOCK_OLD_SOURCES,
  *	    (S,G) is handled
  *   - MODE_IS_EXCLUDE, CHANGE_TO_EXCLUDE
  *	    just regarded as MLDv1 join
  *   - CHANGE_TO_INCLUDE:
  *	    regarded as (S,G)
  *
  * If the Multicast Interface is configured to
  *	- any(both): goes to MLDv1-compat mode if MLDv1 is received.
  *	  (default)
  *	- MLDv1 only: ignores MLDv2 messages
  *	- MLDv2 only: ignores MLDv1 messages
  */

/*
 * Forward declarations.
 */
static void Send_GSS_QueryV2(struct uvif *v, struct listaddr *g, struct listaddr *s );
//static void DelVifV2 __P((void *arg));


static void accept_multicast_record(int ifindex, mifi_t mifi, struct mld_group_record_hdr *mard, struct sockaddr_in6 *src, struct sockaddr_in6 *grp);

struct listaddr * make_new_source(mifi_t mifi , struct listaddr *group, struct sockaddr_in6  *mcast_group, struct sockaddr_in6 *required_source_address );


/*
 * Send general group membership queries on that interface if I am querier.
 */
void query_groupsV2( struct uvif * v)
{

    v->uv_gq_timer = v->uv_mld_query_interval;
    if ((v->uv_flags & VIFF_QUERIER) &&
	(v->uv_flags & VIFF_NOLISTENER) == 0) {
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
	IF_DEBUG(DEBUG_MLD)
	    log_msg(LOG_DEBUG, 0,
		"sending multicast listener general query V2 on : %s ",
		v->uv_name);

	ret = send_mld6v2(MLD_LISTENER_QUERY, 0, &v->uv_linklocal,
			  NULL, (struct sockaddr_in6 *) NULL, v->uv_ifindex,
			  MLD6_QUERY_RESPONSE_INTERVAL, 0, TRUE, SFLAGNO,
			  v->uv_mld_robustness, v->uv_mld_query_interval,
			  FALSE);
	if (ret == TRUE)
		v->uv_out_mld_query++;
	else
	  log_msg(LOG_ERR, 0,
		"Failed to send  multicast listener general query V2 on : %s ",
		v->uv_name);
    }
}

/*
 * Send a group-source-specific v2 query.
 * Two specific queries are built and sent:
 *  1) one with S-flag ON with every source having a timer <= LLQI
 *  2) one with S-flag OFF with every source having a timer >LLQI
 * So we call send_mldv2() twice for different set of sources.
 */
static void  Send_GSS_QueryV2(struct uvif *v, struct listaddr *g , struct listaddr *s )
{
    int ret;

    if ((v->uv_flags & VIFF_QUERIER) == 0 || (v->uv_flags & VIFF_NOLISTENER)) {
	log_msg(LOG_DEBUG, 0,
		"don't send a GSS Query due to a lack of querying right");
	return;
    }
    if ( s == NULL || g == NULL)
    {
        log_msg(LOG_ALERT, 0,
		"BUG:Send_GSS_QueryV2 does  have emtpy (G,S) parameters (NULL)");
	return;
    }
      
    IF_DEBUG(DEBUG_MLD)
	    log_msg(LOG_DEBUG, 0,
		"sending multicast listener SSM_V2 query for (G,S)= (%s,%s) on : %s", sa6_fmt(&g->mcast_group), sa6_fmt(&s->mcast_group), v->uv_name);
		
    ret = send_mld6v2(MLD_LISTENER_QUERY, 0, &v->uv_linklocal,
		      &s->mcast_group, &g->mcast_group, v->uv_ifindex,
		      MLD6_QUERY_RESPONSE_INTERVAL, 0, TRUE, SFLAGNO,
		      v->uv_mld_robustness, v->uv_mld_query_interval, TRUE);
    if (ret == TRUE)
	v->uv_out_mld_query++;

    ret = send_mld6v2(MLD_LISTENER_QUERY, 0, &v->uv_linklocal,
		      &s->mcast_group, &g->mcast_group, v->uv_ifindex,
		      MLD6_QUERY_RESPONSE_INTERVAL, 0, TRUE, SFLAGYES,
		      v->uv_mld_robustness, v->uv_mld_query_interval, TRUE);
    if (ret == TRUE)
	v->uv_out_mld_query++;
    
}

/*
 * Send a group-specific v2 query.
 */
void Send_GS_QueryV2 (struct uvif *v, struct listaddr *g)
{

    int sflag = SFLAGNO;
    int ret;

    if ((v->uv_flags & VIFF_QUERIER) == 0 || (v->uv_flags & VIFF_NOLISTENER)) {
	log_msg(LOG_DEBUG, 0,
		"don't send a GS Query due to a lack of querying right");
	return;
    }

    if (g->al_timer > MLD6_LAST_LISTENER_QUERY_TIMER &&
	g->comp_mode == MLDv2)
	sflag = SFLAGYES;

    ret = send_mld6v2(MLD_LISTENER_QUERY, 0, &v->uv_linklocal,
		      NULL, &g->mcast_group, v->uv_ifindex,
		      MLD6_QUERY_RESPONSE_INTERVAL, 0, TRUE, sflag,
		      v->uv_mld_robustness, v->uv_mld_query_interval, FALSE);
    if (ret == TRUE)
	v->uv_out_mld_query++;
    g->al_rob--;

    /*
     * Schedule MLD6_ROBUSTNESS_VARIABLE specific queries.
     * is received or timer expired ( XXX: The timer granularity is 1s !!)
     */

    if (g->al_rob > 0) {
     
	start_rxmt_timer(g , 1);
    }
    
}

/*
 * Process an incoming host membership v2 query according to the spec (rfc
 * 2710),the router can be in two states : QUERIER or NON QUERIER , and the
 * router start in the QUERIER state.
 * warn if the interface is in MLDv1 mode
 */
#if 0  // violet phase 
void
accept_listenerV2_query(src, dst, query_message, datalen)
    struct sockaddr_in6 *src;
    struct in6_addr *dst;
    register char  *query_message;
    int             datalen;
{
    register int    vifi;
    register struct uvif *v;
    struct sockaddr_in6 group_sa;
    struct sockaddr_in6 source_sa;
    struct listaddr *g = NULL, *s;
    struct in6_addr *group;
    struct mldv2_hdr *mldh;
    int             tmo;
    int             numsrc;
    int             i;
    u_int8_t        qqi;
    u_int8_t        qrv;
    u_int8_t        sflag;

    init_sin6(&group_sa);
    init_sin6(&source_sa);

    /*
     * Ignore my own listener v2 query
     * since they are processed in the kernel
     */

    if (locmcast_groupess(src) != NO_VIF)
	return;

    if ((vifi = find_vif_direct(src)) == NO_VIF) {
	IF_DEBUG(DEBUG_MLD)
	    log_msg(LOG_INFO, 0, "accept_listenerv2_query: can't find a vif");
	return;
    }
    v = &uvifs[vifi];
    v->uv_in_mld_query++;

    if ((v->uv_mld_version & MLDv2) == 0 )
    {
      do 
      {   
         if (v->uv_groups == NULL )
	 {
	       v->uv_mld_version = MLDv2;
	       break;
	 }
	 else
         {
	    log_msg(LOG_WARNING, 0,
	            "Mif %s configured in MLDv1 received MLDv2 query (src %s, dst %s ), ignored",
	            v->uv_name, sa6_fmt(src), inet6_fmt(dst) );
	            // TODO - accept report as MLDv1
	    return;
	 }
      } while (0); 
    }
    
    mldh = (struct mldv2_hdr *) query_message;
    group = &mldh->mld_addr;

    /*
     * XXX Hard Coding
     */

    if ((tmo = ntohs(mldh->mld_icmp6hdr.icmp6_maxdelay)) >= 32768)
	tmo = decodeafloat(ntohs(mldh->mld_icmp6hdr.icmp6_maxdelay), 3, 12);
    numsrc = ntohs(mldh->mld_numsrc);
    if ((qqi = mldh->mld_qqi) >= 128)
	qqi = decodeafloat(mldh->mld_qqi, 3, 4);

    qrv = MLD_QRV(mldh->mld_rtval);
    sflag = MLD_SFLAG(mldh->mld_rtval);

    IF_DEBUG(DEBUG_MLD)
	log_msg(LOG_DEBUG, 0,
	    "accepting multicast listener query V2 on %s: "
	    "src %s, dst %s, grp %s\n"
	    "\t     sflag : %s,robustness : %d,qqi : %d maxrd :%d",
	    v->uv_name, sa6_fmt(src), inet6_fmt(dst), inet6_fmt(group),
	    sflag == SFLAGYES ? "YES" : "NO", qrv, qqi, tmo);

    /*
     * According to RFC2710 : when a query received from a router with a
     * lower IPv6 address than me  :
     *   - start other Querier present.
     *   - pass (or stay in the Non Querier state) .
     */

    if (inet6_lessthan(src, &v->uv_linklocal)) {
	IF_DEBUG(DEBUG_MLD)
	    if (!inet6_equal(src, &v->uv_querier->mcast_group))
		log_msg(LOG_DEBUG, 0, "new querier %s (was %s) on vif %d",
			sa6_fmt(src), sa6_fmt(&v->uv_querier->mcast_group), vifi);

	/* I'm not the querier anymore */
	v->uv_flags &= ~VIFF_QUERIER;
	v->uv_querier->mcast_group = *src;
	SET_TIMER(v->uv_querier->al_timer, MLD6_OTHER_QUERIER_PRESENT_INTERVAL);
	time(&v->uv_querier->al_ctime);
    }
    /*
     * else nothing : the new router will receive a query one day...
     */

    /*
     * Ignore the query if we're (still) the querier.
     */

    if ((v->uv_flags & VIFF_QUERIER) != 0)
	return;

    /*
     * routers adopt the most recent value of QRV and QQI unless
     * this value is null
     */
    if (qrv != 0) {
	v->uv_mld_robustness = qrv;
	IF_DEBUG(DEBUG_MLD)
	    log_msg(LOG_DEBUG, 0, "New Qrv adopted : %d",
		v->uv_mld_robustness);
    }
    if (qqi != 0) {
	v->uv_mld_query_interval = qqi;
	IF_DEBUG(DEBUG_MLD)
	    log_msg(LOG_DEBUG, 0, "New Qqi adopted : %d",
		v->uv_mld_query_interval);
    }

    /*
     * When S-flag is set, only querier election has to be done.
     * (draft-vida-mld-v2-08.txt section 5.1.7)
     */
    if (sflag == SFLAGYES) {
	log_msg(LOG_DEBUG, 0, "MLDv2 Query processing is suppressed");
	return;
    }

    if (IN6_IS_ADDR_UNSPECIFIED(group)) {
	log_msg(LOG_DEBUG, 0,
		"nothing to do with general-query on router-side, "
		"except for querier-election");
	return;
    }

    IF_DEBUG(DEBUG_MLD)
	log_msg(LOG_DEBUG, 0,
	    "%s for %s from %s on vif %d, timer %d",
	    "Group/Source-specific membership query V2",
	    inet6_fmt(group), sa6_fmt(src), vifi, tmo);

    group_sa.sin6_addr = *group;
    group_sa.sin6_scope_id = inet6_uvif2scopeid(&group_sa, v);

    /*
     * group-specific query:
     * Filter Timer should be lowered to [Last Listener Query Interval].
     */
    if (numsrc == 0) {
	IF_DEBUG(DEBUG_MLD)
		log_msg(LOG_DEBUG, 0, "Group-Specific-Query");
  
	//check_multicastV2_listener(v, &group_sa, g, NULL);
	g=check_multicast_listener(v, &group_sa, g);
	if (g == NULL) {
		log_msg(LOG_DEBUG, 0, "do nothing due to a lack of a "
			"correspoding group record");
		return;
	}

	/* setup a timeout to remove the multicast record */
	if (timer_leftTimer(g->group_mbship_timer) >
	    (int) (MLD6_LAST_LISTENER_QUERY_INTERVAL / MLD6_TIMER_SCALE)) {
	    timer_clearTimer(g->group_mbship_timer);
	    SET_TIMER(g->al_timer,
		MLD6_LAST_LISTENER_QUERY_INTERVAL / MLD6_TIMER_SCALE);
	    g->group_mbship_timer = SetTimer(vifi, g);
	}

	IF_DEBUG(DEBUG_MLD)
	    log_msg(LOG_DEBUG, 0,
		"timer for grp %s on vif %d set to %ld",
		inet6_fmt(group), vifi, g->al_timer);
	return;
    }

    /*
     * group-source-specific query:
     * for each sources in the Specific Query
     * message, lower our membership timer to [Last Listener Query Interval]
     */
    IF_DEBUG(DEBUG_MLD)
	log_msg(LOG_DEBUG, 0, "List of sources :");
    for (i = 0; i < numsrc; i++) {
	source_sa.sin6_addr = mldh->mld_src[i];
	source_sa.sin6_scope_id = inet6_uvif2scopeid(&source_sa, v);

	log_msg(LOG_DEBUG, 0, "%s", sa6_fmt(&source_sa));

	/*
	 * Section 7.6.1 draft-vida-mld-v2-08.txt : When a router
	 * receive a query with clear router Side Processing flag,
	 * it must update it's timer to reflect the correct
	 * timeout values : source timer for sources are lowered to LLQI
	 */

	s = check_multicastV2_listener(v, &group_sa, g, &source_sa);
	if (s == NULL)
		continue;

	/* setup a timeout to remove the source/group membership */
	if (timer_leftTimer(s->group_mbship_timer) >
	    (int) (MLD6_LAST_LISTENER_QUERY_INTERVAL / MLD6_TIMER_SCALE)) {
	    timer_clearTimer(s->group_mbship_timer);
	    SET_TIMER(s->al_timer,
		MLD6_LAST_LISTENER_QUERY_INTERVAL / MLD6_TIMER_SCALE);
	    s->group_mbship_timer = SetTimerV2(vifi, g, s);
	}

	IF_DEBUG(DEBUG_MLD)
	    log_msg(LOG_DEBUG, 0,
		"timer for grp %s src %s on vif %d set to %ld",
		inet6_fmt(group), sa6_fmt(&source_sa), vifi, s->al_timer);
    }
}
#endif //violet
/*
 * Process an incoming group membership report. Note : this can be possible
 * only if The Router Alert Option have been set and I'm configured as a
 * router (net.inet6.ip6.forwarding=1) because report are sent to the
 * multicast group. processed in QUERIER and Non-QUERIER State
 * actually there is a timer per group/source pair. It's the easiest solution
 * but not really efficient...
 */
void accept_listenerV2_report(  int ifindex, /* network interface message was received from */
    struct sockaddr_in6 *src,
    struct in6_addr *dst,
    char  *report_message,
    int             datalen 
   )
{

    register mifi_t vifi;
    register struct uvif *v;
    struct mld_report_hdr *report;
    struct mld_group_record_hdr *mard;
    int             i, records_in_the_report, numsrc, totsrc;
    struct sockaddr_in6 group_sa;
    char *p;

    init_sin6(&group_sa);

    if ((vifi = find_vif_by_ifindex(ifindex)) < 0) {
	IF_DEBUG(DEBUG_MLD)
	    log_msg(LOG_INFO, 0, "accept_listenerV2_report : can't find a vif");
	return;
    }

    v = &uvifs[vifi];

    if ((v->uv_mld_version & MLDv2) == 0) {
	log_msg(LOG_WARNING, 0,
	    "Mif %s configured in MLDv1 received MLDv2 report,ignored",
	    v->uv_name);
	return;
    }

    IF_DEBUG(DEBUG_MLD)
	log_msg(LOG_DEBUG, 0,
	    "accepting multicast listener V2 report: "
	    "src %s,dst %s", sa6_fmt(src), inet6_fmt(dst));

    report = (struct mld_report_hdr *) report_message;
    records_in_the_report = ntohs(report->mld_grpnum);

    v->uv_in_mld_report++;

    /*
     * loop through each multicast record
     */

    totsrc = 0;
    for (i = 0; i < records_in_the_report; i++) {
	struct mld_group_record_hdr *mard0 = (struct mld_group_record_hdr *)(report + 1);
	p = (char *)(mard0 + i) - sizeof(struct in6_addr) * i
		+ totsrc * sizeof(struct in6_addr);
	mard= (struct mld_group_record_hdr *) p;
	numsrc = ntohs(mard->numsrc);
	totsrc += numsrc;

	group_sa.sin6_addr = mard->group;
	//group_sa.sin6_scope_id = mard->group inet6_uvif2scopeid(&group_sa, v);

	if (IN6_IS_ADDR_MC_LINKLOCAL(&group_sa.sin6_addr)) {
	    /* too noisy */
	    IF_DEBUG(DEBUG_PKT)
		log_msg(LOG_DEBUG, 0,
		    "accept_listenerV2_report: group(%s) has the "
		    "link-local scope, discarding",
		    sa6_fmt(&group_sa));
	    continue;
	}
        
        if (IN6_IS_ADDR_MC_SITELOCAL(&group_sa.sin6_addr)) {
	    /* too noisy */
	    IF_DEBUG(DEBUG_PKT)
		log_msg(LOG_DEBUG, 0,
		    "accept_listenerV2_report: group(%s) has the "
		    "site-local scope, discarding\n",
		    sa6_fmt(&group_sa));
	    continue;
	}
	accept_multicast_record( ifindex, vifi, mard, src, &group_sa);
    }
}


/* handles multicast record in normal MLDv2-mode */
static void accept_multicast_record(int ifindex, mifi_t vifi, struct mld_group_record_hdr *mard, struct sockaddr_in6 *multicast_subscriber_address, struct sockaddr_in6 *required_multicast_group)
{
	struct uvif *v = &uvifs[vifi];
	int numsrc = ntohs(mard->numsrc);
	
	int j;
	struct sockaddr_in6 source_sa;
	struct listaddr *s = NULL;
	struct listaddr *g = NULL;

	init_sin6(&source_sa);

	/* sanity check */
	if ( vifi != upStreamVif)
	{
	if (v->uv_flags & VIFF_NOLISTENER) {
	         log_msg(LOG_WARNING, 0,
				"Sanity failed :Got listener report on non-listener interface");
		return;
	}
	}
	if (required_multicast_group == NULL)
		return;

	/* just locate group */
	 g = check_multicast_listener(v, required_multicast_group); // returns g -: pointer to group record if any
	 

	switch (mard->record_type) {
	case CHANGE_TO_INCLUDE_MODE:  // filter_mode changes to include, RFC  ref TO_IN(X), wheere X - source to include, i.e to join
	    if (numsrc == 0) {
		if (g == NULL) {
			log_msg(LOG_DEBUG, 0,
				"Need to delete  previousely excluded sources but no group found, impossible to delete non-existent record");
			return;
		}
		/* RFC5710 - delete_source is obsolete */
		// TODO  delete_source 
		if (g->filter_mode ==  MODE_IS_EXCLUDE)
		{
		     g->filter_mode = MODE_IS_INCLUDE; // Guard repetetive reports
		}
		else
		{
		     mld_merge_with_upstream(vifi,  required_multicast_group,  MLDv2 , NULL ); // try to merge  with upstream interface database in ASM mode
	             g->llqc=MLD6_DEFAULT_ROBUSTNESS_VARIABLE;
		     Send_GS_QueryV2(v, g);
		     // TODO DEB 0, 1000 start_rxmt_timer(g, 1);
		     // TODO DEB 0, 1000start_report_timer(g, MLD6_LISTENER_INTERVAL);
		}
		 g->filter_mode = MODE_IS_INCLUDE; // Guard repetetive reports
		 
		 break;
	    }
	    /* FALLTHTOUGH */
	case MODE_IS_INCLUDE:
	case ALLOW_NEW_SOURCES:
	    for (j = 0; j < numsrc; j++) {
		/*
		 * Look for the multicast_subscriber_address/group
		 * in our multicast_subscriber_address/group list; if found, reset its timer.
		 * (B)=MALI implementation
		 */
		source_sa.sin6_addr = mard->src[j];
		source_sa.sin6_scope_id = inet6_uvif2scopeid(&source_sa, v);
		IF_DEBUG(DEBUG_MLD)
		    log_msg(LOG_DEBUG, 0, "processing (G,S)=%s,%s", sa6_fmt(required_multicast_group),
			sa6_fmt(&source_sa));


		g = check_multicast_listener(v, required_multicast_group); // returns g -: pointer to group known on interface v
		if ( g == NULL )
	        {
			IF_DEBUG(DEBUG_MLD)
			    log_msg(LOG_DEBUG, 0,
				"The group does not exixt , trying to add it");
	                 g = make_new_group( vifi , required_multicast_group , MLDv2); //TODO check multicast_subscriber_address ? sender or  SSM
			 //create_filterMode_timer(g); //TODO needed only in exclude mode
			 g->filter_mode = MODE_IS_INCLUDE; // by default, created in EXCLUDE         
	        }
		else // (g != NULL) 
		{
		    stop_rxmt_timer(g);
		    start_report_timer(g, MLD6_LISTENER_INTERVAL ) ;
		}
		s = check_multicastV2_listener(v, required_multicast_group, g, &source_sa); // find whether the (S,G) record exists in interface' v list
		if (s != NULL) 
		{
		    IF_DEBUG(DEBUG_MLD)
			log_msg(LOG_DEBUG, 0, " ALLOW_NEW_SOURCES : The Source/group already exist");

		     /*
		     * delete old timers , set a timer for expiration
		     * => restart timer for this source/group
		     */
		     stop_rxmt_timer(s);
		     
		     start_report_timer(s, MLD6_LISTENER_INTERVAL ) ;  // Renew timer - just as RFC3810 says
		     
		} 
		else  // New source, s == NULL
		{
		    /*
		     * If not found, add it to the list 
		     */
		    
		    s=make_new_source(vifi , g, required_multicast_group,  &source_sa); //allocate a new source record  , start source timer
		    s->filter_mode=MODE_IS_INCLUDE;
		    
		    mld_merge_with_upstream(vifi,  required_multicast_group,  MLDv2 ,&source_sa ); // try to merge  with upstream interface database in SSM mode
		}
	    }
	    break;

	case BLOCK_OLD_SOURCES:
	    if (g == NULL) {
		log_msg(LOG_WARNING, 0,
			"Group %s does not exist, ignoring the  BLOCK_OLD_SOURCES report", sa6_fmt(required_multicast_group));
		return;
	    }
	    if (g->comp_mode == MLDv1) {
		log_msg(LOG_DEBUG, 0, "ignores BLOCK msg in MLDv1-compat-mode");
		return;
	    }

	    /*
	     * Unlike RFC2710 section 4 p.7 (Routers in Non-Querier state
	     * MUST ignore Done messages), MLDv2 non-querier should
	     * accept BLOCK_OLD_SOURCES message to support fast-leave
	     * (although it's not explcitly mentioned).
	     */
	    for (j = 0; j < numsrc; j++) 
	    {
		/*
		 * Look for the multicast_subscriber_address/group
		 * in our multicast_subscriber_address/group list; in order to set up a short-timeout
		 * group/source specific query.
		 */

		source_sa.sin6_addr = mard->src[j];
		source_sa.sin6_scope_id = inet6_uvif2scopeid(&source_sa, v);

		s = check_multicastV2_listener(v, required_multicast_group, g, &source_sa);
		if (s == NULL) {
			log_msg(LOG_WARNING, 0,
			"Cannot accept BLOCK_OLD_SOURCE record"
			"for non-existent source (G,S)=(%s,%s)", sa6_fmt(required_multicast_group), sa6_fmt( &source_sa));
		        continue;
		}
		/*
		 * the source exist , so according to the spec, we will always
		 * send a source specific query here : A*B is true here
		 */
		
		/* scheduling MLD6_ROBUSTNESS_VAR specific queries to send */
	         /* => send a m-a-s	*/
	       /* start rxmt timer */
		s->llqc=MLD6_ROBUSTNESS_VARIABLE; // arm retransmit counter, decreases everu timer tick
                start_rxmt_timer(s, 1);  //deletes source on llqc=0
		Send_GSS_QueryV2(v, g, s);
		// TODO delete following
		if (s->al_CheckingListenerMode != LESSTHANLLQI) {
			s->al_CheckingListenerMode = LESSTHANLLQI;
			s->al_rob = MLD6_ROBUSTNESS_VARIABLE;
		}
	    }

	    break;

	case MODE_IS_EXCLUDE:
	    /* just regard as (*,G) but not shift to mldv1-compat-mode */
	    recv_listener_report(ifindex, vifi, multicast_subscriber_address, required_multicast_group, MLDv2);
	    break;

	case CHANGE_TO_EXCLUDE_MODE:
	    /*
	     * RFC3810 8.3.2 says "MLDv2 BLOCK messages are ignored, as are
	     * source-lists in TO_EX() messages".  But pim6sd does nothing,
	     * since it always ignores the source-list in a TO_EX message.
	     */
	    if (g && g->comp_mode == MLDv1) {
		log_msg(LOG_WARNING, 0,
		    "ignores TO_EX source list in MLDv1-compat-mode");
	    }
	    /* just regard as (*,G) but not shift to mldv1-compat-mode */
	    recv_listener_report(ifindex, vifi, multicast_subscriber_address, required_multicast_group, MLDv2);
	    break;

	default:
	    log_msg(LOG_NOTICE, 0,
		"wrong multicast report type : %d", mard->record_type);
	    break;
	}
}
void ExpireSourceRtrmtTimer (void *p);
void ExpireSourceTimer (void *p);
/*
 * Time out record of a source(s)/group membership on a vif
 */
struct listaddr *  make_new_source(mifi_t mifi , struct listaddr * group, struct sockaddr_in6  *mcast_group, struct sockaddr_in6 *required_source_address)
{
    
	register struct listaddr * source;
	register struct uvif *v=&uvifs[mifi];
	
	IF_DEBUG(DEBUG_MLD)
		printf( "The ((S,G)=(%s,%s) doesn't exist on %s, trying to add it\n",sa6_fmt(required_source_address) ,sa6_fmt(mcast_group), uvifs[mifi].uv_name);
		
	source = (struct listaddr *) malloc(sizeof(struct listaddr));
	if (source == NULL)
	{
		log_msg(LOG_ERR, 0, "ran out of memory");	/* fatal */
		exit(15);
	}
	memset(source, 0, sizeof(*source));
	memcpy(&source->mcast_group ,required_source_address , sizeof(source->mcast_group)); // store source assress
	source->sources=group;
	if ( mifi != upStreamVif )
	{
	
	   create_rxmt_timer (source,  ExpireSourceRtrmtTimer);   /* Create timer to wait for source leave expiration */
	   source->rxmt_timer_callback.q_time=1;
	   source->rxmt_timer_callback.mifi=mifi;
	   source->rxmt_timer_callback.g=group;
	   source->rxmt_timer_callback.source=source;
	   source->rxmt_timer_callback.mcast_group=mcast_group;
	   
	   
	   
	   
	   create_report_timer (source, ExpireSourceTimer); /* Create timer to wait for source expiration */ 
	   source->report_timer_callback.q_time=MLD6_LISTENER_INTERVAL;
	   source->report_timer_callback.mifi=mifi;
	   source->report_timer_callback.g=group;
	   source->report_timer_callback.source=source; 
	   source->report_timer_callback.mcast_group=mcast_group;
	
	   source->al_CheckingListenerMode = FALSE;
	/* Start timer to wait for membership expiration */
	   start_report_timer (source, MLD6_LISTENER_INTERVAL);
	   source->comp_mode=MLDv2;
	   //source->filter_mode=filter_mode;
	   
	   /* RFC 5790
	    * It is  generally unnecessary to support the filtering function that blocks sources.
	   if ( filter_mode == EXCLUDE )
	   {
	       start_filterMode_timer(g);
	   }
	   */
	}
	
	source->filter_mode=MODE_IS_INCLUDE;
	
	
	source->llqc =(v->fastleave ) ? 0 :  v->uv_mld_llqc;  // Prepare retrt count of Group Specific queries
	/* insert group fist  in the list of the groups of this interface */
	
	source->al_next=group->sources;  // set  a linked list previousely head to be on my right,  next of s  
	group->sources = source;         // make me (s) a head of the list
	
        time(&group->al_ctime);
	IF_DEBUG(DEBUG_MLD)
			log_msg(LOG_DEBUG, 0,
			    "*** Created new SSM (Group,Source) = (%s,%s) on interface %s *** : ",
			    sa6_fmt(&group->mcast_group), sa6_fmt(&source->mcast_group), v->uv_name);
	return source;
}



#if 0 // TODO was a cllback ?
static void DelVifV2(void  *arg)
{
    cbk_t          *cbk = (cbk_t *) arg;
    mifi_t          vifi = cbk->mifi;
    struct uvif    *v = &uvifs[vifi];
    struct listaddr *a, **anp, *g = cbk->g;
    struct listaddr *b, **anq, *s = cbk->s;

    /*
     * Source(s)/Group has expired delete all kernel cache entries with this
     * group
     */

    /*
     * protocol specific
     */

    IF_DEBUG(DEBUG_MLD)
	log_msg(LOG_DEBUG, 0,
	    "*** notify routing daemon ***: "
	    "group(%s),source(%s) has no more listeners on %s",
	    sa6_fmt(&g->mcast_group), sa6_fmt(&s->mcast_group), v->uv_name);

    delete_leaf(vifi, &s->mcast_group, &g->mcast_group);

    /*
     * increment statistics
     */
    v->uv_listener_timo++;

    anp = &(v->uv_groups);

    /*
     * unlink it from the chain
     * if there is no more source,delete the group
     */

    while ((a = *anp) != NULL) {
	if (a != g) {
	    anp = &a->al_next;
	    continue;
	}

	/* We have found the group, now search the source to be deleted */
	anq = &(a->sources);
	while ((b = *anq) != NULL) {
		if (b != s) {
		    anq = &b->al_next;
		    continue;
		}
		*anq = b->al_next;
		free(b);
		break;
	}

	/*
	 * no more sources, delete the group
	 * clear the checklist state for this group
	 */

	if (a->sources == NULL) {
		*anp = a->al_next;
		free(a);
	}
	break;
    }
    free(cbk);

}
#endif

/*
 * Set a timer to delete the record of a source/group membership on a vif.
 * typically used when report with record type
 * -BLOCK_OLD_SOURCES,MODE_IS_INCLUDE,ALLOW_NEW_SOURCES  or  m-a-s source/group is received
 */





/*
 * Checks for MLDv2 listeners: returns a pointer on the source/group if there
 * is a receiver for the group on the given uvif, or returns NULL otherwise.
 *
 * *g points the group if it exists on the given uvif. if the group does not
 * exist, *g is NULL.
 */
struct listaddr * check_multicastV2_listener(
	struct uvif *v,
	struct sockaddr_in6 *multicast_group,
	struct listaddr *g,
	struct sockaddr_in6 *source
	)
{
	struct listaddr *s;

	/*
	 * group scan: if v->uv_group is given from the argument,
	 * it's skipped to prevent unnecessary duplicated scanning
	 */
	if (multicast_group == NULL || g == NULL)
		return NULL;	/* sanity check */
	if (g) {
		if (!inet6_equal(multicast_group, &(g)->mcast_group))
			return NULL;	/* invalid group is given */
	} else {
		g = check_multicast_listener(v, multicast_group);
		if (g == NULL)
			return NULL;	/* multicast_group not found, source not found */
	}

	/* find  requred multicast source in the list of sources*/
	if (source == NULL)
		return NULL;	/*  sources list is empty */
	for (s = g->sources; s != NULL; s = s->al_next) {
		if (inet6_equal(source, &s->mcast_group)) // assumed that mcast_group hold source IPV6 address,  and not multicast group
			break;
	}
	return s;	/* multicast_group found, source searched  and foind*/
}


void mld_shift_to_v2mode(void * arg)
{
	cbk_t *cbk = (cbk_t *) arg;

	struct sockaddr_in6 *grp = &cbk->g->mcast_group;
	mifi_t mifi = cbk->mifi;
	struct uvif *v = &uvifs[mifi];
	struct listaddr *g = NULL;

	log_msg(LOG_DEBUG, 0,
	    "shift back mode from MLDv1-compat to MLDv2 for %s on Mif %s",
	    sa6_fmt(grp), v->uv_name);

	/* find group in  interface' group list*/
	g=check_multicast_listener(v, grp);
	if (g == NULL) {
		log_msg(LOG_ERR, 0,
		    "tried to shift back to MLDv2 mode for %s on Mif %s,"
		    "but there's no such group.",
		    sa6_fmt(grp), v->uv_name);
		return;	/* impossible */
	}

	g->comp_mode = MLDv2;
	//g->al_comp = 0;
	free(cbk);

	/* won't continue this timer and just return */
	return;
}
#endif
void ExpireFilterModeTimer (void *p );
int create_filterMode_timer ( struct listaddr * g)
{	
	g->mldv2_filterMode_timer = timerfd_create( CLOCK_MONOTONIC , 0 ) ;
	if ( ! g->mldv2_filterMode_timer )
	{
	  perror("Cannot create Generic Queries  Timer");
	  log_msg(LOG_DEBUG, errno, "Cannot create Generic Queries  Timer ");
	}
	g->filterMode_timer_event.events=EPOLLIN;
	g->filterMode_timer_event.data.ptr=&g->filterMode_timer_callback;
        g->filterMode_timer_callback.callback = ExpireFilterModeTimer;
	
	g->filterMode_timer_callback.g = g;
	printf("adding epoll event %p\n", g->filterMode_timer_event.data.ptr );
	/* add timer  to the timers poll set/queue */
	if (epoll_ctl( epfd, EPOLL_CTL_ADD, g->mldv2_filterMode_timer,  &g->filterMode_timer_event)  < 0 )
	{
	    perror("Cannot Add ExpireFilterModeTimer  Timer Event");
	}
        printf("Created ExpireFilterModeTimer timer \n");
        return 0;
}
int start_filterMode_timer (struct listaddr * g, int secs )
{
    struct itimerspec  tspec;
	int rc;
     
        printf("start Generic queries timer with period=%d\n", secs); 
	if (g->mldv2_filterMode_timer <=0 )
	{
		        log_msg(LOG_ERR,0, "The multicast group already exists, but timer was not created as it should");
			exit(10);
	}
        /* If no state change - just renew the timer */
        rc=secs;
	
	tspec.it_interval.tv_sec=rc; // timer period
	tspec.it_interval.tv_nsec=random() % 100000;
	tspec.it_value.tv_sec=rc -1; // Initial timer expiration LEV
	tspec.it_value.tv_nsec=0;
	printf("start_filterMode_timer  epfd=%d tfd=%d, interval=%u, nsec=%lu\n", epfd, g->mldv2_filterMode_timer,tspec.it_interval.tv_sec, tspec.it_interval.tv_nsec );
	rc=timerfd_settime(g->mldv2_filterMode_timer, 0, &tspec, NULL);
	if (rc <0 )
	{
	    log_msg(LOG_ERR,errno, "Cannot renew the  filterMode timer ");
			exit(10);
	}
}


int stop_filterMode_timer ( struct listaddr * g)
{	struct itimerspec  tspec;
	memset(&tspec,0, sizeof(tspec) );
	printf(" stop Generic queries timer \n");
	if (g->mldv2_filterMode_timer)
	{
	      timerfd_settime(g->mldv2_filterMode_timer, 0, &tspec, NULL); // tspec Zero stops the timer
	}
	return 0;
}

int delete_filterMode_timer (struct listaddr * g )
{
    struct itimerspec  tspec;
    printf("delete Generic queries timer \n");
    memset(&tspec,0, sizeof(tspec) );
    if (g->mldv2_filterMode_timer)
	timerfd_settime(g->mldv2_filterMode_timer, 0, &tspec, NULL);
    if (epoll_ctl(epfd, EPOLL_CTL_DEL,g->mldv2_filterMode_timer, &g->filterMode_timer_event ) < 0) 
    {
	log_msg(LOG_ERR, errno, "cannot disable uv_filterMode_timer ");
	exit(10);
   }
    close(g->mldv2_filterMode_timer);
}
void ExpireFilterModeTimer (void *p )
{
    
    /* On expiration of A Filter mode timer we try to return from EXCLUDE mode to INCLUDE */
   timer_cbk_t * params=(timer_cbk_t *) p;
   
    printf("ExpireFilterModeTimer\n");
   
    if ( (! p ) || (!  params->g) )
   {
      log_msg(LOG_ERR, 0,
			"ExpireFilterModeTimer, callback parameters  NULL");
      exit(15);
   }
   /*
   if ( ! find_group_in_list( &uvifs[params->mifi], params->g) )
   {
       log_msg(LOG_ERR, 0,
			"BUG ExpireFilterModeTime, group %s does not exist at interface %s", sa6_fmt(&params->g->mcast_group), params->mifi);
      exit (15);
   }
   */
   printf( 
          "Expired Report Timer for G=%s\n",
         sa6_fmt( &(params->g->mcast_group) ));
   
   
    switch (params->g->comp_mode)
    {
      case MLDv2 :   query_groupsV2(&uvifs[params->mifi]); break;
      case MLDv1 :   query_groups(&uvifs[params->mifi]);  break; // will restart the timer
      default:
     log_msg(LOG_ERR, errno, "group %s mld mode is invalid, neither MLDv1 nor MLDv2" , sa6_fmt(&params->g->mcast_group));
    }
}
void delete_source ( mifi_t mifi, struct listaddr *group, struct listaddr *source )
{       
   struct listaddr *current =group->sources ;
   struct listaddr * next = group->sources;  // head of the list - group stored perform interface
   struct listaddr *prev;
   
        if  ( mifi != upStreamVif )
	{
	    delete_report_timer(source);
	    delete_rxmt_timer(source);
	}
         prev=current; // head of the list 
	 while ((current = next) != NULL) 
        {
		if (current == source)
		{
		        printf (
	                      "delete source (G,S)=(%s,%s)\n", sa6_fmt(&group->mcast_group),sa6_fmt(&source->mcast_group ) )  ;
			if ( prev == group->sources && current==group->sources )  // head of the list 
			{
			    group->sources=NULL;
			}
			else
			{
			    prev->al_next = current->al_next;  // chain next list element instead of current 
			}
			
			free((char *) current);
			break;
		} 
		else
		{
		        prev=current;
			next = current->al_next;
		}
	}
	// if  (group->sources == NULL)  Group timer takes care ?
#ifdef TODO
	{
	     delete_group(mifi, group);
	     delete_group_upstream( mifi, group);
	}
#endif
}

void delete_source_upstream ( mifi_t mifi, struct listaddr *group, struct listaddr * source )
{    
   register struct uvif *v= &uvifs[mifi];
   short  intfce = uvifs[mifi].uv_ifindex;
   struct listaddr * s;
    
   
   
         printf (
	         "delete_source_upstream (G,S)=%s\n", sa6_fmt(&group->mcast_group) ,  sa6_fmt(&source->mcast_group)) ;
		 
         
         // First check if this source have active listeners
		 
	
	      s=check_multicastV2_listener( v, &group->mcast_group, group  , &source->mcast_group);
	      if  ( s== NULL) 
	      {
		    log_msg(LOG_ERR ,0, "BUG : delete for non existing source addr=%p, /n", source);
	      }
	      
	      s->listeners--;
	      
	     if (s->listeners >0 )
	     {
	         return;  // We still have a listeners for this source on this interfac
	     }
	    
	     // No more listeners for this source,  (we just delte source, other LAN cient may listen to the (G,*)
	      delete_source (upStreamVif, group, source );    
	          // TODO start_report_timer(group, 
	       

	   k_leave_src (mld6_proxy_socket,  &group->mcast_group.sin6_addr, &source->mcast_group.sin6_addr, upstream_idx );
	 
	 
	 
	 // TODO - send leave group to CMTS
}	 
void ExpireSourceTimer(void * p)
{
  timer_cbk_t * params=(timer_cbk_t *) p;
   register struct uvif *v= &uvifs[params->mifi];
  /* Group membership had expired */
  /* if no reports was heard, send query - No */
  /* RFC says 
    If an address's timer expires, it is
   assumed that there are no longer any listeners for that address
   present on the link, so it is deleted from the list and its
   disappearance is made known to the multicast routing component.
   */
   printf("%s\n", __func__);
   if ( (! p ) || (!  params->g) )
   {
      log_msg(LOG_ERR, 0,
			"BUG %s, callback parameters  NULL\n", __func__);
      exit(15);
   }
   /*
   if ( ! find_group_in_list( &uvifs[params->mifi], params->g) )
   {
       log_msg(LOG_ERR, 0,
			"BUG %s, group %s does not exist at interface %s",__func__, sa6_fmt(&params->g->mcast_group), params->mifi);
      exit (15);
   }
   */
   printf( 
          "Expired Source Timer for (G,S)= (%s,%s)\n",
         sa6_fmt( &(params->g->mcast_group) ), sa6_fmt( &(params->source->mcast_group) ) );
	 
	 // if  ( params->source-?al_CheckingListenerMode == FALSE )
  
   if  (params->g->filter_mode == MODE_IS_INCLUDE  && uvifs[params->mifi].fastleave == TRUE )  
   {
     /*  RFC3810
     * If the timer of a source from the Include List expires, the source is deleted from the Include List *
     */
      // soft leave
       delete_report_timer ( params->source);
       delete_rxmt_timer ( params->source);
       delete_source (params->mifi, params-> g, params->source);
       delete_source_upstream (params->mifi, params-> g, params->source);
       
       return;
   }
   if  (params->g->filter_mode == MODE_IS_INCLUDE  && uvifs[params->mifi].fastleave == FALSE )
   {
     params->source->al_CheckingListenerMode ==TRUE;
     params->source->llqc = MLD6_DEFAULT_ROBUSTNESS_VARIABLE ;
     start_report_timer(params->source, MLD6_LISTENER_INTERVAL);
     Send_GSS_QueryV2( v ,params->g , params->source);
     start_rxmt_timer(params->source, 1);  // will retry llqc times until decide to delete group
     return;
   }
} 

void ExpireSourceRtrmtTimer (void *p)
{
  timer_cbk_t * params = (timer_cbk_t *) p;
  register struct uvif *v= &uvifs[params->mifi];
 
	 
  if ( (! p ) || (!  params->g) )
  {
      log_msg(LOG_ERR, 0,
			"Expired SourceRtrmtTimer callback parameters sanity, (p=%p) group param->g=%p NULL", p, params->g);
   
  }
  /*
   if ( ! find_group_in_list( v, params->g) )
  {
      log_msg(LOG_ERR, 0,
                         "BUG ExpireRtrmtTimer, group %s does not exist at interface %s", sa6_fmt(&params->g->mcast_group), params->mifi);
      exit (15);
  }
  */
  IF_DEBUG(DEBUG_TIMER)
   
  log_msg(LOG_DEBUG ,0, 
          "Expired Source Retransmission Timer for (G,S)= (%s,%s) on %s\n",
         sa6_fmt( &(params->g->mcast_group) ), sa6_fmt( &(params->source->mcast_group)), v->uv_name );
  
  /*
   *  RFC 3810 defines fast leave as N query  restransmit attemts
  
 */
  if ( (params->source->llqc--) <=0 )
  {
      IF_DEBUG(DEBUG_TIMER)
      log_msg(LOG_DEBUG, 0,
			"%s: (G,S)=%s,%s  at interface %s   Rtrtsmit is %d and timer must be stopped",__func__, sa6_fmt(&params->g->mcast_group), sa6_fmt(&params->source->mcast_group),v->uv_name ,params->source->llqc--);
      
     
       delete_report_timer ( params->source);
       delete_rxmt_timer ( params->source);
       delete_source_upstream (params->mifi, params-> g, params->source);
       delete_source (params->mifi, params-> g, params->source);
  
  }
  else
  {
      printf( 
          "Expired Source Retransmission Timer for (G,S)= (%s,%s), sending GSS Query\n",
           sa6_fmt( &(params->g->mcast_group) ), sa6_fmt( &(params->source->mcast_group) ) );
	   
	  params->source->llqc--;
	  Send_GSS_QueryV2( v ,params->g , params->source);
	  start_report_timer(params->g, MLD6_LISTENER_INTERVAL); //will exclude group with empty source list   
      
  }
}
