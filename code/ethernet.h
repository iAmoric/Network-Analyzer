#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>

#include "ip.h"
#include "arp.h"

void handle_ethernet(const u_char* packet);
