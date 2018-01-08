
/**
 * Created by Lucas Pierrat.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "bootp.h"
#include "verbosity.h"
#include "helper.h"
#include "telnet.h"
#include "dns.h"
#include "port.h"

/**
 * @brief this function processes the http protocol
 * @param payload
 * @param payload_size
 * @param is_secured: 1 if it is the secure version of http, else 0
 * @param verbosity
 */
void handle_http(const u_char* payload, int payload_size, int is_secured, int verbosity);

/**
 * @brief this function processes the pop protocol
 * @param payload
 * @param payload_size
 * @param verbosity
 */
void handle_pop(const u_char* payload, int payload_size, int verbosity);

/**
 * @brief this function processes the smtp protocol
 * @param payload
 * @param payload_size
 * @param is_secured: 1 if it is the secure version of smtp, else 0
 * @param verbosity
 */
void handle_smtp(const u_char* payload, int payload_size, int is_secured, int verbosity);

/**
 * @brief this function processes the imap protocol
 * @param payload
 * @param payload_size
 * @param verbosity
 */
void handle_telnet(const u_char* packet, int payload_size, int verbosity);

/**
 * @brief this function processes the telnet protocol
 * @param payload
 * @param payload_size
 * @param srcPort
 * @param verbosity
 */
void handle_ftp(const u_char* payload, int payload_size, int is_request, int srcPort, int verbosity);

/**
 * @brief this function processes the ftp protocol
 * @param payload
 * @param payload_size
 * @param is_request: 1 if it is a request (port 21), 0 if it is data (port 20)
 * @param verbosity
 */
void handle_imap(const u_char* payload, int payload_size, int verbosity);

/**
 * @brief this function processes the dns protocol
 * @param packet
 * @param verbosity
 */
void handle_dns(const u_char* packet, int verbosity);

/**
 * @brief this function proceses the bootp protocol
 * @param packet
 * @param verbosity
 */
void handle_bootp(const u_char* packet, int verbosity);

/**
 * @brief this function processes the dhcp protocol
 * @param packet
 * @param verbosity
 * @param xid
 */
void handle_dhcp(const u_char* packet, int verbosity, unsigned int xid);
