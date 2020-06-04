/*	$KAME: defs.h,v 1.5 2001/08/09 10:10:06 suz Exp $	*/

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


#ifndef DEFS_H
#define DEFS_H

#ifdef HAVE_CONFIG_H
#include "../include/config.h"
#endif
#include <sys/select.h>
#include <sys/types.h>
#include <syslog.h>
#include <stdio.h>
#define	TRUE		1
#define	FALSE		0

#define	max( a , b )	( ( a )<( b )?( b ):( a ) )

typedef	void	( *ihfunc_t )( int i , fd_set * fds ) ;
typedef	void    ( *cfunc_t )( void *);
void log_msg( int Severity, int Errno, const char *FmtSt, ... );


/*  CONFIGCONFIGCONFIGCONFIG */

#define RANDOM()	random()

#define PRINTF printf
#define ALL_MCAST_GROUPS_LENGTH 8 
// ../include/ config.h #define HAVE_RFC3542 1
#define HAVE_RFC3542 1
typedef u_int32_t	u_int32;
typedef u_int16_t	u_int16;
typedef u_int8_t	u_int8;

extern char configfilename[];
extern u_int16_t upStreamVif;
extern u_int16_t upstream_idx;
#define MAXUVIFS 8
extern int epfd;
extern FILE * log_fp;
// Interface states
#define IF_STATE_DISABLED      0   // Interface should be ignored.
#define IF_STATE_UPSTREAM      1   // Interface is the upstream interface
#define IF_STATE_DOWNSTREAM    2   // Interface is a downstream interface

// Multicast default values...
#define DEFAULT_ROBUSTNESS     2
#define DEFAULT_THRESHOLD      1
#define DEFAULT_RATELIMIT      0

// Define timer constants (in seconds...)
#define INTERVAL_QUERY          125
#define INTERVAL_QUERY_RESPONSE  10
//#define INTERVAL_QUERY_RESPONSE  10

#define ROUTESTATE_NOTJOINED            0   // The group corresponding to route is not joined
#define ROUTESTATE_JOINED               1   // The group corresponding to route is joined
#define ROUTESTATE_CHECK_LAST_MEMBER    2   // The router is checking for hosts


#endif
