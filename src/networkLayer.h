
/**
 * Created by Lucas Pierrat.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//#include <net/if_arp.h>
#include <netinet/in.h>
//#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <sys/socket.h>

#include "verbosity.h"
#include "transportLayer.h"

#define ARPOP_REQUEST   1
#define ARPOP_REPLY     2

#define ETHERNET        1
#define IPV4            2048

//use this structure for arp because there are some inaccessible fields in the structure in <net/if_arp.h>
struct arp_hdr {
    u_int16_t htype;    /* Hardware Type           */
    u_int16_t ptype;    /* Protocol Type           */
    u_char hlen;        /* Hardware Address Length */
    u_char plen;        /* Protocol Address Length */
    u_int16_t oper;     /* Operation Code          */
    u_char sha[6];      /* Sender Mac address */
    u_char spa[4];      /* Sender IP address       */
    u_char tha[6];      /* Target Mac address */
    u_char tpa[4];      /* Target IP address       */
};

/**
 * @brief this function processes the ip protocol
 * @param packet
 * @param verbosity
 */
void handle_ip(const u_char* packet, int verbosity);

/**
 * @brief this function processes the arp protocol
 * @param packet
 * @param verbosity
 */
void handle_arp(const u_char* packet, int verbosity);
