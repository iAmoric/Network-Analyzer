#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "bootp.h"
#include "verbosity.h"
#include "helper.h"
#include "telnet.h"

void handle_http(const u_char* payload, int payload_size, int is_secured, int verbosity);
void handle_pop(const u_char* payload, int payload_size, int verbosity);
void handle_smtp(const u_char* payload, int payload_size, int is_secured, int verbosity);
void handle_telnet(const u_char* packet, int payload_size, int verbosity);
void handle_ftp(const u_char* payload, int payload_size, int is_request, int verbosity);
void handle_imap(const u_char* payload, int payload_size, int verbosity);
void handle_dns(const u_char* packet, int verbosity);
void handle_bootp(const u_char* packet, int verbosity);
void handle_dhcp(const u_char* packet, int verbosity, unsigned int xid);
