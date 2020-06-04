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


#ifndef MLD6V2_PROTO_H
#define MLD6V2_PROTO_H
#include "vif.h"
/* compatibility modes and mld versions */



extern void query_groupsV2 __P((struct uvif * v));
extern void Send_GS_QueryV2 __P((struct uvif *v, struct listaddr *g));
extern void accept_listenerV2_query __P((struct sockaddr_in6 * src,
					 struct in6_addr * dst,
					 register char *query_message,
					 int datalen));
extern void accept_listenerV2_report __P((int ifindex , struct sockaddr_in6 * src,
					  struct in6_addr * dst,
					  register char *report_message,
					  int datalen));
extern struct listaddr *check_multicastV2_listener __P((struct uvif * v,
							struct sockaddr_in6 *
							group,
							struct listaddr * g,
							struct sockaddr_in6 *
							source));
extern struct listaddr *  make_new_source(mifi_t mifi , struct listaddr * group, struct sockaddr_in6  *mcast_group, struct sockaddr_in6 *required_source_address);

extern void mld_shift_to_v2mode __P((void * ));
#endif