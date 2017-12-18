#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <sys/socket.h>

#include "transportLayer.h"

void handle_ip(const u_char* packet);
void handle_arp(const u_char* packet);
