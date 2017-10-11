#include <stdio.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

void handle_arp(const u_char* packet);
