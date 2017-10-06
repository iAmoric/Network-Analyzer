#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>

void handle_ip(const u_char* packet);
