#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <netinet/in.h>

#include "verbosity.h"

void handle_http(const u_char* payload, int payload_size, int is_secured, int verbosity);
void handle_pop(const u_char* payload, int payload_size, int verbosity);
void handle_smtp(const u_char* payload, int payload_size, int is_secured, int verbosity);
void handle_telnet(const u_char* packet, int verbosity);
void handle_ftp(const u_char* payload, int payload_size, int is_request, int verbosity);
void handle_imap(const u_char* payload, int payload_size, int verbosity);
void handle_dns(const u_char* packet, int verbosity);

void printPrintableAscii(const u_char* payload, int payload_size);
