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

void handle_tcp(const u_char* packet, int payload_size, int verbosity);
void handle_udp(const u_char* packet, int payload_size, int verbosity);
