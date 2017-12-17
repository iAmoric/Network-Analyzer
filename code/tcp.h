#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

void handle_tcp(const u_char* packet);
