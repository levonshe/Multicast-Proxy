/*
**  mldproxy - IGMP/MLD proxy based multicast router 
**  Copyright (C) 2005 Johnny Egeland <johnny@rlo.org>
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
**
**----------------------------------------------------------------------------
**
**  This software is derived work from the following software. The original
**  source code has been modified from it's original state by the author
**  of mldproxy.
**
**  smcroute 0.92 - Copyright (C) 2001 Carsten Schill <carsten@cschill.de>
**  - Licensed under the GNU General Public License, version 2
**  
**  mrouted 3.9-beta3 - COPYRIGHT 1989 by The Board of Trustees of 
**  Leland Stanford Junior University.
**  - Original license can be found in the Stanford.txt file.
**
*/
#include "defs.h"
#include "config.h"
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>


#include "mld6_proto.h"
/**
*   config.c - Contains functions to load and parse config
*              file, and functions to configure the daemon.              
*/
// Keeps common configuration settings 
struct Config {
    unsigned int        robustnessValue;
    unsigned int        queryInterval;
    unsigned int        queryResponseInterval;
    // Used on startup..
    unsigned int        startupQueryInterval;
    unsigned int        startupQueryCount;
    // Last member probe...
    unsigned int        lastMemberQueryInterval;
    unsigned int        lastMemberQueryCount;
    // Set if upstream leave messages should be sent instantly..
    unsigned short      fastUpstreamLeave;
};

// Linked list of networks... 
// Makes sense only for IPV4
struct SubnetList {
    u_int32_t              subnet_addr;
    u_int32_t              subnet_mask;
    struct SubnetList*  next;
};



#include "vif.h"
                                      
// Structure to keep configuration for VIFs...    
struct vifconfig {
    char*               name;
    short               state;
    int                 ratelimit;
    int                 threshold;

    // Keep allowed nets for VIF.
    struct SubnetList*  allowednets;
    
    // Next config in list...
    struct vifconfig*   next;
};
                 
// Structure to keep vif configuration
struct vifconfig*   vifconf;

// Keeps common settings...
static struct Config commonConfig;

// Prototypes...
struct vifconfig *parsePhyintToken(void);
struct SubnetList *parseSubnetAddress(char *addrstr);
// from confread.c
char *getCurrentConfigToken(void);
char *nextConfigToken(void);

void add_phaddr(struct uvif *v, struct sockaddr_in6 *addr,
		struct in6_addr *mask, struct sockaddr_in6 *rmt_addr);
void
add_phaddr(struct uvif *v, struct sockaddr_in6 *addr, struct in6_addr *mask, struct sockaddr_in6 *rmt)
{
#if 0 // TODO - I am not sure we need this , we need only uv_linklocal to send mld msg
	struct phaddr *pa;
	int i;
	
	if ((pa = malloc(sizeof(*pa))) == NULL)
	        log_msg(LOG_ERR, 0, "add_phaddr: memory exhausted");


	memset(pa,0,sizeof(*pa));
	pa->pa_addr= *addr;
	pa->pa_subnetmask = *mask;
	if (rmt)
		pa->pa_rmt_addr= *rmt;

	for(i = 0; i < sizeof(struct in6_addr); i++)
		pa->pa_prefix.sin6_addr.s6_addr[i] =
			addr->sin6_addr.s6_addr[i] & mask->s6_addr[i];
	pa->pa_prefix.sin6_scope_id = addr->sin6_scope_id;


	if (IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr)) {
		if(v->uv_linklocal) {
			log_msg(LOG_WARNING, 0,
			    "add_phaddr: found more than one link-local "
			    "address on %s",
			    v->uv_name);
		v->uv_linklocal = pa;
	}

	pa->pa_next = v->uv_addrs;
	v->uv_addrs = pa;
#endif
}



/**
*   Initializes common config..
*/
void initCommonConfig(void) {
    commonConfig.robustnessValue = DEFAULT_ROBUSTNESS;
    commonConfig.queryInterval = INTERVAL_QUERY;
    commonConfig.queryResponseInterval = INTERVAL_QUERY_RESPONSE;

    // The defaults are calculated from other settings.
    commonConfig.startupQueryInterval = (unsigned int)(INTERVAL_QUERY / 4);
    commonConfig.startupQueryCount = DEFAULT_ROBUSTNESS;

    // Default values for leave intervals...
    commonConfig.lastMemberQueryInterval = INTERVAL_QUERY_RESPONSE;
    commonConfig.lastMemberQueryCount    = DEFAULT_ROBUSTNESS;

    // If 1, a leave message is sent upstream on leave messages from downstream.
    commonConfig.fastUpstreamLeave = 0;

}

/**
*   Returns a pointer to the common config...
*/
struct Config *getCommonConfig(void) {
    return &commonConfig;
}

char *nextConfigToken(void);

/**
*   Loads the configuration from file, and stores the config in 
*   respective holders...
*/                 
int loadConfig(char *configFile) {
    struct vifconfig  *tmpPtr;
    struct vifconfig  **currPtr = &vifconf;
    char *token;
    
    // Initialize common config
    initCommonConfig();

    // Test config file reader...
    if(!openConfigFile(configFile)) {
        log_msg(LOG_ERR, 0, "Unable to open configfile from %s", configFile);
    }

    // Get first token...
    token = nextConfigToken();
    if(token == NULL) {
        log_msg(LOG_ERR, 0, "Config file was empty.");
    }

    // Loop until all configuration is read.
    while ( token != NULL ) {
        // Check token...
        if(strcmp("phyint", token)==0) {
            // Got a phyint token... Call phyint parser
            log_msg(LOG_DEBUG, 0, "Config: Got a phyint token.");
            tmpPtr = parsePhyintToken();
            if(tmpPtr == NULL) {
                // Unparsable token... Exit...
                closeConfigFile();
                log_msg(LOG_WARNING, 0, "Unknown token '%s' in configfile", token);
                return 0;
            } else {

                log_msg(LOG_DEBUG, 0, "IF name : %s", tmpPtr->name);
                log_msg(LOG_DEBUG, 0, "Next ptr : %p", tmpPtr->next);
                log_msg(LOG_DEBUG, 0, "Ratelimit : %d", tmpPtr->ratelimit);
                log_msg(LOG_DEBUG, 0, "Threshold : %d", tmpPtr->threshold);
                log_msg(LOG_DEBUG, 0, "State : %d", tmpPtr->state);
                log_msg(LOG_DEBUG, 0, "Allowednet ptr : %p", tmpPtr->allowednets);

                // Insert config, and move temp pointer to next location...
                *currPtr = tmpPtr;
                currPtr = &tmpPtr->next;
            }
        } 
        else if(strcmp("fastleave", token)==0) {
            // Got fastleave a  token....
            log_msg(LOG_DEBUG, 0, "Config: Quick leave mode enabled.");
            commonConfig.fastUpstreamLeave = 1;
            
            // Read next token...
            token = nextConfigToken();
            continue;
        } else {
            // Unparsable token... Exit...
            closeConfigFile();
            log_msg(LOG_WARNING, 0, "Unknown token '%s' in configfile", token);
            return 0;
        }
        // Get token that was not recognized by phyint parser.
        token = getCurrentConfigToken();
    }

    // Close the configfile...
    closeConfigFile();

    return 1;
}

/**
*   Appends extra VIF configuration from config file.
*/
int configureVifs() {
    unsigned i;
    struct vifconfig *confPtr;

    // If no config is availible, just return...
    if (vifconf == NULL) {
        log_msg(LOG_DEBUG, 0, "No config structure is filled with config data /n" );
        return;
    }

    // Loop through all VIFs...
    for ( i = 0, confPtr = vifconf ; i < MAXUVIFS ; i++)
    {
                
		   // struct SubnetList *vifLast;
		    strncpy(&(uvifs[i].uv_name[0]), confPtr->name,IFNAMSIZ);
                    //log_msg(LOG_DEBUG, 0, "Found config for %s", uvifs[i].uv_name);
                    printf( "Found config for %s\n", uvifs[i].uv_name);
		

                    // Set the VIF state 
                   uvifs[i].state = confPtr->state;
		   uvifs[i].uv_mld_llqi = MLD6_DEFAULT_LAST_LISTENER_QUERY_INTERVAL /1000; // convert ms to seconds
		   uvifs[i].uv_mld_query_interval = MLD6_DEFAULT_QUERY_INTERVAL;
                   uvifs[i].uv_mld_robustness = MLD6_DEFAULT_ROBUSTNESS_VARIABLE;
		   uvifs[i].uv_mld_query_rsp_interval = MLD6_DEFAULT_QUERY_RESPONSE_INTERVAL;
		   uvifs[i].interfaceStartupQueryCount = MLD6_DEFAULT_ROBUSTNESS_VARIABLE ; //yes. itss RFC says it is robustness by default
		   uvifs[i].uv_mld_version = MLDv2;
                   uvifs[i].threshold = confPtr->threshold;
                   uvifs[i].ratelimit = confPtr->ratelimit;
		   uvifs[i].uv_ifindex = if_nametoindex(confPtr->name);
		   uvifs[i].state=confPtr->state;
		   uvifs[i].fastleave = commonConfig.fastUpstreamLeave;
		   
		   if  (confPtr->state & IF_STATE_UPSTREAM) 
		   {
			uvifs[i].state=IF_STATE_UPSTREAM;  // it may mee upstream downsream or disabled
			upStreamVif=i;
			upstream_idx=uvifs[i].uv_ifindex;
		  }
	
		  
			    #if 0 // TODO - allowed nets - are relevant for Ipv6 ?
			    // Go to last allowed net on VIF...
			    for(vifLast = uvifs[i].allowednets; vifLast->next; vifLast = vifLast->next);
                        
			      // Insert the configured nets...
			      vifLast->next = confPtr->allowednets;
			#endif
		confPtr = confPtr->next;
		if ( confPtr == NULL)  
		    break; 
        }
        
	return i;
}


/**
*   Internal function to parse phyint config
*/
struct vifconfig *parsePhyintToken(void) {
    struct vifconfig  *tmpPtr;
    struct SubnetList **anetPtr;
    char *token;
    short parseError = 0;

    // First token should be the interface name....
    token = nextConfigToken();

    // Sanitycheck the name...
    if(token == NULL) return NULL;
    if(strlen(token) >= IF_NAMESIZE) return NULL;
    log_msg(LOG_DEBUG, 0, "Config: IF: Config for interface %s.", token);

    // Allocate memory for configuration...
    tmpPtr = (struct vifconfig*)malloc(sizeof(struct vifconfig));
    if(tmpPtr == NULL) {
        log_msg(LOG_ERR, 0, "Out of memory.");
    }

    // Set default values...
    tmpPtr->next = NULL;    // Important to avoid seg fault...
    tmpPtr->ratelimit = 0;
    tmpPtr->threshold = 1;
    tmpPtr->state = IF_STATE_DOWNSTREAM;
    tmpPtr->allowednets = NULL;

    // Make a copy of the token to store the IF name
    tmpPtr->name = strdup( token );
    if(tmpPtr->name == NULL) {
        log_msg(LOG_ERR, 0, "Out of memory.");
    }

    // Set the altnet pointer to the allowednets pointer.
    anetPtr = &tmpPtr->allowednets;

    // Parse the rest of the config..
    token = nextConfigToken();
    while(token != NULL) {
        if(strcmp("altnet", token)==0) {
            // Altnet...
            token = nextConfigToken();
            log_msg(LOG_DEBUG, 0, "Config: IF: Got altnet token %s.",token);

            *anetPtr = parseSubnetAddress(token);
            if(*anetPtr == NULL) {
                parseError = 1;
                log_msg(LOG_WARNING, 0, "Unable to parse subnet address.");
                break;
            } else {
                anetPtr = &(*anetPtr)->next;
            }
        }
        else if(strcmp("upstream", token)==0) {
            // Upstream
            log_msg(LOG_DEBUG, 0, "Config: IF: Got upstream token.");
            tmpPtr->state = IF_STATE_UPSTREAM;
        }
        else if(strcmp("downstream", token)==0) {
            // Downstream
            log_msg(LOG_DEBUG, 0, "Config: IF: Got downstream token.");
            tmpPtr->state = IF_STATE_DOWNSTREAM;
        }
        else if(strcmp("disabled", token)==0) {
            // Disabled
            log_msg(LOG_DEBUG, 0, "Config: IF: Got disabled token.");
            tmpPtr->state = IF_STATE_DISABLED;
        }
        else if(strcmp("ratelimit", token)==0) {
            // Ratelimit
            token = nextConfigToken();
            log_msg(LOG_DEBUG, 0, "Config: IF: Got ratelimit token '%s'.", token);
            tmpPtr->ratelimit = atoi( token );
            if(tmpPtr->ratelimit < 0) {
                log_msg(LOG_WARNING, 0, "Ratelimit must be 0 or more.");
                parseError = 1;
                break;
            }
        }
        else if(strcmp("threshold", token)==0) {
            // Threshold
            token = nextConfigToken();
            log_msg(LOG_DEBUG, 0, "Config: IF: Got threshold token '%s'.", token);
            tmpPtr->threshold = atoi( token );
            if(tmpPtr->threshold <= 0 || tmpPtr->threshold > 255) {
                log_msg(LOG_WARNING, 0, "Threshold must be between 1 and 255.");
                parseError = 1;
                break;
            }
        }
        else {
            // Unknown token. Break...
            break;
        }
        token = nextConfigToken();
    }

    // Clean up after a parseerror...
    if(parseError) {
        free(tmpPtr);
        tmpPtr = NULL;
    }

    return tmpPtr;
}
/*                                                                                                                                                                                                         
 * Convert an IP address in u_long (network) format into a printable string.                                                                                                                               
 */ 
char *inetFmt(uint32_t addr, char *s) {                                                                                                                                                                    
    register u_char *a;                                                                                                                                                                                    
                                                                                                                                                                                                           
    a = (u_char *)&addr;                                                                                                                                                                                   
    sprintf(s, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);                                                                                                                                                     
    return(s);                                                                                                                                                                                             
}  
/*                                                                                                                                                                                                         
 * Convert an IP subnet number in u_long (network) format into a printable                                                                                                                                 
 * string including the netmask as a number of bits.                                                                                                                                                       
 */                                                                                                                                                                                                        
char *inetFmts(uint32_t addr, uint32_t mask, char *s) {                                                                                                                                                    
    register u_char *a, *m;                                                                                                                                                                                
    int bits;                                                                                                                                                                                              
                                                                                                                                                                                                           
    if ((addr == 0) && (mask == 0)) {                                                                                                                                                                      
        sprintf(s, "default");                                                                                                                                                                             
        return(s);                                                                                                                                                                                         
    }                                                                                                                                                                                                      
    a = (u_char *)&addr;                                                                                                                                                                                   
    m = (u_char *)&mask;                                                                                                                                                                                   
    bits = 33 - ffs(ntohl(mask));                                                                                                                                                                          
                                                                                                                                                                                                           
    if (m[3] != 0) sprintf(s, "%u.%u.%u.%u/%d", a[0], a[1], a[2], a[3],                                                                                                                                    
                           bits);                                                                                                                                                                          
    else if (m[2] != 0) sprintf(s, "%u.%u.%u/%d",    a[0], a[1], a[2], bits);                                                                                                                              
    else if (m[1] != 0) sprintf(s, "%u.%u/%d",       a[0], a[1], bits);                                                                                                                                    
    else                sprintf(s, "%u/%d",          a[0], bits);                                                                                                                                          
                                                                                                                                                                                                           
    return(s);                                                                                                                                                                                             
}   
/**
*   Parses a subnet address string on the format
*   a.b.c.d/n into a SubnetList entry.
*/
struct SubnetList *parseSubnetAddress(char *addrstr) {
    struct SubnetList *tmpSubnet;
    char        *tmpStr;
    char     s1[16];
    uint32_t      addr = 0x00000000;
    uint32_t      mask = 0xFFFFFFFF;

    // First get the network part of the address...
    tmpStr = strtok(addrstr, "/");
    addr = inet_addr(tmpStr);

    tmpStr = strtok(NULL, "/");
    if(tmpStr != NULL) {
        int bitcnt = atoi(tmpStr);
        if(bitcnt <= 0 || bitcnt > 32) {
            log_msg(LOG_WARNING, 0, "The bits part of the address is invalid : %s, bits are %d.\n",tmpStr, bitcnt);
            return NULL;
        }

        mask <<= (32 - bitcnt);
    }

    if(addr == -1 || addr == 0) {
        log_msg(LOG_WARNING, 0, "Unable to parse address token '%s'.", addrstr);
        return NULL;
    }

    tmpSubnet = (struct SubnetList*) malloc(sizeof(struct SubnetList));
    tmpSubnet->subnet_addr = addr;
    tmpSubnet->subnet_mask = ntohl(mask);
    tmpSubnet->next = NULL;

    log_msg(LOG_DEBUG, 0, "Config: IF: Altnet: Parsed altnet to %s.",
	    inetFmts(tmpSubnet->subnet_addr, tmpSubnet->subnet_mask,s1));

    return tmpSubnet;
}
