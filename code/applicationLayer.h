#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <netinet/in.h>

void handle_http(const u_char* payload, int payload_size, int is_secured);
void handle_pop(const u_char* payload, int payload_size);
void handle_smtp(const u_char* payload, int payload_size, int is_secured);
void handle_telnet(const u_char* packet);
void handle_ftp(const u_char* payload, int payload_size, int is_request);
void handle_imap(const u_char* payload, int payload_size);
void handle_dns(const u_char* packet);

void printPrintableAscii(const u_char* payload, int payload_size);
