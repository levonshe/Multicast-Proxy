/*	$KAME: main.c,v 1.31 2003/09/02 09:48:45 suz Exp $	*/

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
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

#include <linux/mroute6.h>

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/timerfd.h>

#include "defs.h"
#include "debug.h"
#include "mld6.h"
#include "mld6_proto.h"
#include "vif.h"
#include "mroute-api.h"
#include "kern.h"
char            	configfilename[256];
static char            	versionstring[100];
char			*logfilename = "/var/tmp/mldproxy.log";

static char     	*pidfilename ="/var/run/mldproxy.pid";
int epfd;                /* contains epoll file descriptor, used in other files to add/remove pollable events like timers */

FILE * log_fp;
static int		foreground = 1;
static int      	sighandled = 0;

#define GOT_SIGINT      0x01
#define GOT_SIGHUP      0x02
#define GOT_SIGUSR1     0x04
#define GOT_SIGUSR2     0x08
#define GOT_SIGALRM     0x10
#ifdef SIGINFO
#define GOT_SIGINFO	0x20
#endif

char progname[128];  //exported to debug.c




/*
 * Forward declarations.
 */

//static void catch_signal__P((int));

static void restart __P((int));
static void cleanup __P((void));
static void usage(void);
static void usage(void);


/* To shut up gcc -Wstrict-prototypes */

int main(int argc, char **argv);
static void catch_signal(int sig);
static int parse_command_line( int argc, char ** argv);
static void print_debug_level(int debug);
static void check_privilegies(void);
static void init_log(void); 
static void init_mrouter(void);
static void daemonize(void);
static void init_signalhandler(void);
static int  RunEventLoop(void);
static void cleanup(void);
static void restart(int s);



/*
 * Signal handler.  Take note of the fact that the signal arrived so that the
 * main loop can take care of it.
 */
static void
catch_signal(int sig)
{
    switch (sig)
    {
    case SIGALRM:
	sighandled |= GOT_SIGALRM;
    case SIGINT:
    case SIGTERM:
	sighandled |= GOT_SIGINT;
	break;

    case SIGHUP:
	sighandled |= GOT_SIGHUP;
	break;

    case SIGUSR1:
	sighandled |= GOT_SIGUSR1;
	break;

    case SIGUSR2:
	sighandled |= GOT_SIGUSR2;
	break;

#ifdef SIGINFO
    case SIGINFO:
	sighandled |= GOT_SIGINFO;
	break;
#endif
    }
}

static int parse_command_line( int argc, char ** argv)
{
   extern struct debugname debugnames[];
  
    memset( progname, 0, sizeof (progname));
    strncpy(progname, argv[0], sizeof (progname) );
   
  
    argv++;
    argc--;
 
    while (argc > 0 && *argv[0] == '-')
    {
	if (strcmp(*argv, "-d") == 0)
	{
	    if (argc > 1 && *(argv + 1)[0] != '-')
	    {
		char           *p,
		               *q;
		int             i,
		                len;
		struct debugname *d;
		int 		no=0;

		argv++;
		argc--;
		debug = 0;
		p = *argv;
		q = NULL;
		while (p)
		{
		    q = strchr(p, ',');
		    if (q)
			*q++ = '\0';
		    if(p[0]=='-')
		    {
			no=1;
			p++;
		    }		
		    len = strlen(p);
		    for (i = 0, d = debugnames;
			 i < sizeof(debugnames) / sizeof(debugnames[0]);
			 i++, d++)
			if (len >= d->nchars && strncmp(d->name, p, len) == 0)
			    break;
		    if (i == sizeof(debugnames) / sizeof(debugnames[0]))
		    {
			int             j = 0xffffffff;
			int             k = 0;
			fprintf(stderr, "Valid debug levels: ");
			for (i = 0, d = debugnames;
			     i < sizeof(debugnames) / sizeof(debugnames[0]);
			     i++, d++)
			{
			    if ((j & d->level) == d->level)
			    {
				if (k++)
				    putc(',', stderr);
				fputs(d->name, stderr);
				j &= ~d->level;
			    }
			}
			putc('\n', stderr);
			usage();;
		    }
		    if(no)
		    {
			debug &=~d->level;
			no=0;
		    }
		    else
			debug |= d->level;
		    p = q;
		}
	    }
	    else
		debug = DEBUG_DEFAULT;
	}
	else if (strcmp(*argv, "-c") == 0) {
		if (argc > 1)
		{
		    argv++;
		    argc--;
		    strncpy(configfilename, *argv, sizeof(configfilename));
		}
		else
		    usage();;
	}
	else if (strcmp(*argv, "-f") == 0)
		foreground = 0;   
	else
		    usage();

	argv++;
	argc--;
    }	
    return argc;
}

static void usage(void)
{
	int tmpd = 0xffffffff;
	char c;
	extern struct debugname debugnames[];
	struct debugname *d;
	
	fprintf(stderr, "usage:mdlproxy[-c configfile] [-d [debug_level][,debug_level]] [-f]\n");
        fprintf(stderr, " [-f] : do a fork and become a daemon\n");
	fprintf(stderr, "debug levels: ");
	c = '(';
	for (d = debugnames; d < debugnames +
	     sizeof(debugnames) / sizeof(debugnames[0]); d++)
	{
	    if ((tmpd & d->level) == d->level)
	    {
		tmpd &= ~d->level;
		fprintf(stderr, "%c%s", c, d->name);
		c = ',';
	    }
	}
	fprintf(stderr, ")\n");
	exit(1);
}
static void print_debug_level(int debug)
{
    char c;
    struct debugname *d;

    if (debug != 0)
    {
	int tmpd = debug;
	fprintf(stderr, "debug level 0x%x ", debug);
	c = '(';
	for (d = debugnames; d < debugnames +
	     sizeof(debugnames) / sizeof(debugnames[0]); d++)
	{
	    if ((tmpd & d->level) == d->level)
	    {
		tmpd &= ~d->level;
		fprintf(stderr, "%c%s", c, d->name);
		c = ',';
	    }
	}
	fprintf(stderr, ")\n");
    }
}
static void check_privilegies(void)
{
    setlinebuf(stderr);

    if (geteuid() != 0)
    {
	fprintf(stderr, "mdlproxy: must be root\n");
	exit(1);
    }

}
static void init_log(void)
{
    extern char     todaysversion[];

    /* open a log file */
    if ((log_fp = fopen(logfilename, "w")) == NULL)
    {
	    fprintf(stderr,  "fopen(%s) errno=%d", logfilename, errno);
	    exit(2);
    }

    setlinebuf(log_fp);

    snprintf(versionstring, sizeof(versionstring), "mldproxy version %s", todaysversion);

    log_msg(LOG_INFO, 0, "%s starting", versionstring);
}

static void init_mrouter(void)
{
    int Err;
    Err = enableMRouter();
    switch ( Err ) {  //creates mld6_socket
    case 0: break;
    case EADDRINUSE: log_msg ( LOG_ERR, EADDRINUSE, "MC-Router API already in use" );
                     break;
    default: log_msg( LOG_ERR, Err, "MRT_INIT failed" );
             exit(2);
    }
}
static void init_eventqueue(void)
{  
    epfd = epoll_create1(0);
    if (epfd <=0 )
	log_msg(LOG_ERR, errno, "epoll_create failed");
}
static void init_signalhandler(void)
{
    struct sigaction sa;
    
    
    sa.sa_handler = catch_signal;
    sa.sa_flags = 0;		/* Interrupt system calls */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGALRM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
#ifdef SIGINFO
    sigaction(SIGINFO, &sa, NULL);
#endif
}
static void daemonize(void)
{
    FILE * fp;
    int Err;
    
    if (foreground == 0)
    {
	Err=daemon(0,0);
	if (Err <= 0 )
	  perror ( "Cannot daemonize");
    }

    fp = fopen(pidfilename, "w");
    if (fp != NULL)
    {
	fprintf(fp, "%d\n", (int) getpid());
	(void) fclose(fp);
    }
}

static void perform_action_on_signal(int sighandled)
{
         int     dummy=0,
                  dummysigalrm = SIGALRM;
		 
	    if (sighandled & GOT_SIGHUP)
	    {
		sighandled &= ~GOT_SIGHUP;
		restart(SIGHUP);
	    }
#ifdef SIGINFO
	    if (sighandled & GOT_SIGINFO)
	    {
		sighandled &= ~GOT_SIGINFO;
		dump_stat();
	    }
#endif
	    if (sighandled & GOT_SIGUSR1)
	    {
		sighandled &= ~GOT_SIGUSR1;
		fdump(SIGUSR1);
	    }
	    if (sighandled & GOT_SIGUSR2)
	    {
		sighandled &= ~GOT_SIGUSR2;
#ifdef notyet
		cdump(SIGUSR2);
#else
		//cfparse(0, 1);	/* reset debug level */
#endif
	    }
	    if (sighandled & GOT_SIGALRM)
	    {
		sighandled &= ~GOT_SIGALRM;
	    }
}
#include <sys/times.h>
#include <sys/epoll.h>
int RunEventLoop(void)
{
   
    int      Ready, i, secs, rc;
     
    clock_t before, after;
    struct epoll_event events[2];
    struct epoll_event evt;
    cfunc_t callback_fn;	    
    

    
     // First thing we send a membership query in downstream VIF's...
  
    // we already done it at start_vif 
    // mld6SendGenericQueryDs();
    evt.events = 0 ;
    evt.events |= EPOLLIN ;
    evt.data.fd = mld6_socket;
    
	       
  
  rc = epoll_ctl(epfd, EPOLL_CTL_ADD , mld6_socket, &evt);
    
    if (rc <0 )
	log_msg(LOG_ERR, errno, "epoll_ctl on mld6_socket failed");
    
    for (;;)
    {
      
        
	//  Each configured interface has just started query timers
	Ready=0;
	if ( (Ready = epoll_wait(epfd,  events, MAXUVIFS  ,  10000) ) < 0 ) //  -1 mean wait indefinetely, but interface query timeout should happen
	{
	    if (errno != EINTR)	
		log_msg(LOG_WARNING, errno, "epoll_wait failed");
	        exit (15); // for debug
	        continue;
	}
	if (Ready > 0)
	{
	    //printf ( " epoll returned %d  events\n", Ready);
	    for (i=0; i< Ready ; i++)
	    {
	         if (events[i].data.fd == mld6_socket)
	         {
		    /* Handle received message (MLD report, query) */
		    
		    mld6_read( mld6_socket); // process mld6 message
		    
		    continue;
	         }
	         else
	         /* timer fired on one of  the timers */
	         {
	             if (events[i].data.ptr)
		         {
		             timer_cbk_t  *p;
			 
			            p=( timer_cbk_t *) events[i].data.ptr;
			            callback_fn = p->callback;  //timer events callback function
		     
		                     if (p->callback)
		                     {
		                             //log_msg(LOG_DEBUG, 0, "got a timer event, callback addr = %p, callback arg =%p",p->callback , events[i].data.ptr );
	                                     (* callback_fn )(( void *)events[i].data.ptr);
		                      }
		            }
	          }
	         
	     }
  
         }
    }				/* Main loop for ;; */
}

int
main(int argc, char ** argv)
{
  int a;
  a=1;
  a=2;
  a=a+5;
  a++;
  
   // TODO - just for config debug 
   //check_privilegies();
  
    if (argc <= 1 ||  (parse_command_line(argc, argv) >0 ) )
    {
	usage();
	exit (1);
    }
    print_debug_level(debug);
    init_log();

    
    srandom(times(NULL));
    
    init_eventqueue();
    

    init_vifs();
    init_mrouter();
    
    init_mld6();  // opens mld6_sockets : one for lan rcv , one for WAN snd

    /* clean all the interfaces ... */
    start_all_vifs();
    daemonize();

    init_signalhandler();
   

    /*
     * Main endless receive loop, until SIGTERM or SIGINT
     */
    RunEventLoop();
    

    log_msg(LOG_NOTICE, 0, "%s exiting", versionstring);
    cleanup();
    exit(0);
}


/*
 * Performs all necessary functions to quit gracefully
 */
/* TODO: implement all necessary stuff */

static void
cleanup()
{
    mifi_t vifi;
    struct uvif *v;
    
    
    
    stop_all_vifs();
    

    disableMRouter();
}


/* TODO: not verified */
/*
 * Restart the daemon
 */

static void restart(int i)
{

    log_msg(LOG_NOTICE, 0, "%s restart", versionstring);

    /*
     * reset all the entries
     */
    /*
     * TODO: delete? 
    free_all_mfc ? , send done upstream ?
     */

    stop_all_vifs();
    disableMRouter();
    close(mld6_socket);
    close(udp_socket);

    /*
     * start processing again
     */

    // Reread config ?
    init_mrouter();
    init_mld6();
    init_vifs();
   
}
