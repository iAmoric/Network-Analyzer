
/**
 * Created by Lucas Pierrat.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/udp.h>

#include "verbosity.h"
#include "port.h"
#include "applicationLayer.h"

/**
 * @brief this function processes the tcp protocol
 * @param packet
 * @param payload_size
 * @param verbosity
 */
void handle_tcp(const u_char* packet, int payload_size, int verbosity);

/**
 * @brief this function processes the udp protocol
 * @param packet
 * @param payload_size
 * @param verbosity
 */
void handle_udp(const u_char* packet, int payload_size, int verbosity);
