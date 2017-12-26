#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "bootp.h"
#include "verbosity.h"
#include "telnet.h"

void printPrintableAscii(const u_char* payload, int payload_size);
void printIPAddress(const u_char* payload, int payload_size);
void printAscii(const u_char* payload, int payload_size);
int displayOptionName(unsigned char option);
void displayOptionValue(unsigned char option, const u_char* payload, int payload_size);
int has_header(const u_char* payload);
int printHeader(const u_char* payload, int verbosity);
int is_command(const u_char* payload);
void printTelnetCommand(const u_char* payload, int payload_size);
void printTelnetOptions(int option);
