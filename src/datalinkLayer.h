#include <stdio.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>

#include "verbosity.h"
#include "networkLayer.h"

void handle_ethernet(const u_char* packet, int verbosity);
