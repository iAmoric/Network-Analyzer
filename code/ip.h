#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "tcp.h"
#include "udp.h"

void handle_ip(const u_char* packet);
