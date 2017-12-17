#include <stdio.h>
#include <pcap.h>
#include <netinet/udp.h>
#include <netinet/in.h>

void handle_udp(const u_char* packet, int payload_size);
