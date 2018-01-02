
/**
 * Created by Lucas Pierrat.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "bootp.h"
#include "verbosity.h"
#include "telnet.h"


/**
 * @brief this function print the payload in hexa and ascii format
 * @param payload
 * @param payload_size
 */
void printHexaAscii(const u_char* payload, int payload_size);

/**
 * @brief this function print the payload in ascii format
 * @param payload
 * @param payload_size
 */
void printAscii(const u_char* payload, int payload_size);

/**
 * @brief this function print one or more ip address(es)
 * @param payload
 * @param payload_size
 */
void printIPAddress(const u_char* payload, int payload_size);

/**
 * @brief this function print the name of the dhcp option
 * @param option
 * @return end: 0 if the option read was the end, else 1
 */
int dhcpOptionName(unsigned char option);

/**
* @brief this function print the content of the dhcp option. Can be ip address, ascii text or other
* @param option
* @param payload
* @param payload_size
*/
void dhcpOptionValue(unsigned char option, const u_char* payload, int payload_size);

/**
 * @brief this function test if the content of the http payload is an header
 * @param payload
 * @return 1 if the content start by 'GET', 'POST' or 'HTTP', else 0
 */
int has_header(const u_char* payload);

/**
 * @brief this function print the http header
 * @param payload
 * @param verbosity
 * @return readSize: the size of the header read
 */
int printHeader(const u_char* payload, int verbosity);

/**
 * @brief this function test if the telnet payload is a command (start by 0xff)
 * @param payload
 * @return 1 if it is a command (start by 0xff), else 0
 */
int is_command(const u_char* payload);

/**
 * @brief this function print the name of the telnet option
 * @param option
 */
void telnetCommand(const u_char* payload, int payload_size);

/**
 * @brief this function print the name of the telnet command, and option of the command
 * @param payload
 * @param payload_size
 */
void telnetOptions(int option);


int printDnsType(int type, int cnameFound);
void printDnsClass(int class);
void printDnsOpcode(int opcode);