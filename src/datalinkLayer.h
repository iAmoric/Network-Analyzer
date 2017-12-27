
/**
 * Created by Lucas Pierrat.
 */

#include <stdio.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>

#include "verbosity.h"
#include "networkLayer.h"


/**
 * this function processes the ethernet protocol
 * @param packet
 * @param verbosity
 */
void handle_ethernet(const u_char* packet, int verbosity);
