
/**
 * Created by Lucas Pierrat.
 */

#include "helper.h"

/**
 * @brief this function prints the payload in hexa and ascii format
 * @param payload
 * @param payload_size
 */
void printHexaAscii(const u_char* payload, int payload_size){
    int i;
    int j;

    fprintf(stdout, "\n" );
    for(i = 0 ; i < payload_size ; i++) {
        if (i != 0 && i%32 == 0) { //if one line of hexa printing is complete

            fprintf(stdout, "\t\t");
            for(j = i-32; j < i; j++) {
                if (isprint(payload[j]))
                    fprintf(stdout, "%c", payload[j]);
                else fprintf(stdout, ".");
            }
            fprintf(stdout, "\n");
        }

        if(i%32 == 0) fprintf(stdout, "\t\t\t\t");
            fprintf(stdout, "%02X ", payload[i]);

        if (i == payload_size - 1) {  //print the last spaces

            for(j = 0; j < 31 - i%32; j++)
                fprintf(stdout, "   "); //extra spaces

            fprintf(stdout, "\t\t");

            for(j= i - i%32; j <= i; j++) {
                if(isprint(payload[j]))
                    fprintf(stdout, "%c", payload[j]);
                else
                    fprintf(stdout, ".");
            }

            fprintf(stdout,  "\n" );
        }
    }
}


/**
 * @brief this function prints the payload in ascii format
 * @param payload
 * @param payload_size
 */
void printAscii(const u_char* payload, int payload_size) {
    for (int i = 0; i < payload_size; i++)
        fprintf(stdout, "%c", *payload++);
}


/**
 * @brief this function prints one or more ip address(es)
 * @param payload
 * @param payload_size
 */
void printIPAddress(const u_char* payload, int payload_size) {
    int cpt = payload_size / 4;
    fprintf(stdout, ": ");
    for (int j = 0; j < cpt-1; j++){
        for (int i = 0; i < payload_size-1; i++)
            fprintf(stdout, "%d.", *payload++);
        fprintf(stdout, "%d | ", *payload++);
    }
    for (int i = 0; i < payload_size-1; i++)
        fprintf(stdout, "%d.", *payload++);
    fprintf(stdout, "%d", *payload++);
}


/**
 * @brief this function prints the name of the dhcp option
 * @param option
 * @return end: 0 if the option read was the end, else 1
 */
int dhcpOptionName(unsigned char option) {
    int end = 1;
    switch (option) {
        case TAG_SUBNET_MASK:       //1
            fprintf(stdout, "Subnet mask");
            break;
        case TAG_TIME_OFFSET:       //2
            fprintf(stdout, "Time offset");
            break;
        case TAG_GATEWAY:           //3
            fprintf(stdout, "Gateway");
            break;
        case TAG_DOMAIN_SERVER:     //6
            fprintf(stdout, "Domain Name Server");
            break;
        case TAG_HOSTNAME:          //12
            fprintf(stdout, "Host name");
            break;
        case TAG_DOMAINNAME:        //15
            fprintf(stdout, "Domain name");
            break;
        case TAG_BROAD_ADDR:        //28
            fprintf(stdout, "Broadcast address");
            break;
        case TAG_NETBIOS_NS:        //44
            fprintf(stdout, "Netbios over name server");
            break;
        case TAG_NETBIOS_SCOPE:     //47
            fprintf(stdout, "Netbios over scope");
            break;
        case TAG_REQ_ADDR:          //50
            fprintf(stdout, "Requested IP address");
            break;
        case TAG_LEASETIME:         //51
            fprintf(stdout, "Lease time");
            break;
        case TAG_DHCP_MSGTYPE:      //53
            fprintf(stdout, "DHCP message type");
            break;
        case TAG_SERVERID:          //54
            fprintf(stdout, "Server identifier");
            break;
        case TAG_PARAM_REQ:         //54
            fprintf(stdout, "Parameter request list");
            break;
        case TAG_CLASSID:           //60
            fprintf(stdout, "Client identifier");
            break;
        case TAG_END:               //255
            fprintf(stdout, "End");
            end = 0;
            break;
        default:
            fprintf(stdout, "Unknown");
            break;
    }
    return end;
}


/**
 * @brief this function prints the content of the dhcp option. Can be an ip address, ascii text or other
 * @param option
 * @param payload
 * @param payload_size
 */
void dhcpOptionValue(unsigned char option, const u_char* payload, int payload_size){
    //print an ip address if the value is an option address
    if (option == TAG_SUBNET_MASK || option == TAG_GATEWAY || option == TAG_DOMAIN_SERVER ||
        option == TAG_BROAD_ADDR || option == TAG_NETBIOS_NS || option == TAG_REQ_ADDR ||
        option == TAG_SERVERID) {
        printIPAddress(payload, payload_size);
    }

    //print the ascii characters if the value is text
    if (option == TAG_HOSTNAME || option == TAG_DOMAINNAME) {
        fprintf(stdout, ": ");
        fprintf(stdout, "\n\t\t\t\t");
        printAscii(payload, payload_size);
    }

    // for all options of the request list, print the option name
    if (option == TAG_PARAM_REQ) {
        fprintf(stdout, ": ");
        for (int i = 0; i < payload_size; i++){
            fprintf(stdout, "\n\t\t\t\t\t\t");
            option = *payload++;
            fprintf(stdout, "Option %d: ", option);
            dhcpOptionName(option);
        }
    }

    // print the dhcp message type if required
    if (option == TAG_DHCP_MSGTYPE) {
        fprintf(stdout, ": ");
        option = *payload;
        switch (option) {
            case DHCPDISCOVER:
                fprintf(stdout, "Discover");
                break;
            case DHCPOFFER:
                fprintf(stdout, "Offer");
                break;
            case DHCPREQUEST:
                fprintf(stdout, "Request");
                break;
            case DHCPDECLINE:
                fprintf(stdout, "Decline");
                break;
            case DHCPACK:
                fprintf(stdout, "Ack");
                break;
            case DHCPNAK:
                fprintf(stdout, "N-Ack");
                break;
            case DHCPRELEASE:
                fprintf(stdout, "Release");
                break;
            default:
                break;
        }
    }
}


/**
 * @brief this function tests if the content of the http payload is an header
 * @param payload
 * @return 1 if the content start by 'GET',  'POST' or 'HTTP', else 0
 */
int has_header(const u_char* payload) {
    if (payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T')
        return 1;

    else if (payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T')
        return 1;

    else if (payload[0] == 'H' && payload[1] == 'T' && payload[2] == 'T' && payload[3] == 'P')
        return 1;

    return 0;
}


/**
 * @brief this function prints the http header
 * @param payload
 * @param verbosity
 * @return readSize: the size of the header read
 */
int printHeader(const u_char* payload, int verbosity) {
    int i = 0;
    int readSize = 0;

    if (verbosity == HIGH)
        fprintf(stdout, "\t\t\t\t");

    while (1) {
        if (payload[i] == 0x0d) {
            if (payload[i+1] == 0x0a){
                if (verbosity != HIGH)   //only print the first line for low/Medium verbosity
                    break;

                //if there is "0d 0a 0d 0a" stop and return the read size
                if (payload[i+2] == 0x0d && payload[i+3] == 0x0a) {
                    readSize+=4;
                    break;
                }
                fprintf(stdout, "\n\t\t\t\t");
            }
        }
        if (isprint(payload[i]))    //only print if it is printable ascii characters
            fprintf(stdout, "%c", payload[i]);
        i++;
        readSize++;
    }
    return readSize;
}


/**
 * @brief this function tests if the telnet payload is a command (start by 0xff)
 * @param payload
 * @return 1 if it is a command (start by 0xff), else 0
 */
int is_command(const u_char* payload){
    if (payload[0] == 0xff)
        return 1;
    return 0;
}


/**
 * @brief this function prints the name of the telnet option
 * @param option
 */
void telnetOptions(int option){
    fprintf(stdout, "%02d: ", option);
    switch (option) {
        case TELOPT_BINARY:     //00
            fprintf(stdout, "Binary");
            break;
        case TELOPT_ECHO:       //01
            fprintf(stdout, "Echo");
            break;
        case TELOPT_SGA:        //03
            fprintf(stdout, "Supress Go Ahead");
            break;
        case TELOPT_TTYPE:      //24
            fprintf(stdout, "Terminal Type");
            break;
        case TELOPT_NAWS:       //31
            fprintf(stdout, "Window Size");
            break;
        case TELOPT_TSPEED:     //32
            fprintf(stdout, "Terminal Speed");
            break;
        case TELOPT_LINEMODE:   //34
            fprintf(stdout, "Linemode");
            break;
        case TELOPT_OLD_ENVIRON:   //36
            fprintf(stdout, "Old Environment Variables");
            break;
        case TELOPT_NEW_ENVIRON:   //39
            fprintf(stdout, "New Environment Variables");
            break;
        default:
            fprintf(stdout, "Unknown");
            break;
    }
}


/**
 * @brief this function prints the name of the telnet command, and option of the command
 * @param payload
 * @param payload_size
 */
void telnetCommand(const u_char *payload, int payload_size) {
    int command, option;
    int i, next;
    int h, w;
    const u_char* end = payload + payload_size;

    while (payload < end) {
        *payload++; //shift the first 0xff
        command = *payload++;   //read the command
        fprintf(stdout, "\t\t\t\tCommand %d: ", command);
        option = *payload++;    //read options of the command
        switch (command) {
            case DO:        //253
                fprintf(stdout, "DO - ");
                telnetOptions(option);
                break;

            case DONT:      //254
                fprintf(stdout, "DONT - ");
                telnetOptions(option);
                break;

            case WONT:      //252
                fprintf(stdout, "WONT - ");
                telnetOptions(option);
                break;

            case WILL:      //251
                fprintf(stdout, "WILL - ");
                telnetOptions(option);
                break;

            case SB:        //250
                fprintf(stdout, "NEGOCIATION about ");
                    telnetOptions(option);
                    switch (option) {
                        case TELOPT_TSPEED:
                            fprintf(stdout, ": %d", *payload++);
                            break;

                        case TELOPT_NAWS:
                            w = (payload[0] << 8) + payload[1];
                            h = (payload[2] << 8) + payload[3];
                            fprintf(stdout, ": %d x %d", w, h);
                            payload += 4;
                            break;

                        default:
                            fprintf(stdout, ": Unknown");
                            //shift for the size of the option
                            next = payload[0];
                            i = 0;
                            while (next != 0xff)
                                next = payload[i++];
                            payload += (i-1);
                            break;
                    }
                break;

            case SE:        //240
                fprintf(stdout, "END SUB NEGOCIATION");
                break;

            default:
                fprintf(stdout, "Unknown");
                break;
        }

        fprintf(stdout, "\n");
    }
}



/**
 * @brief this function prints the name in dns
 * @param base
 * @param payload
 * @return readSize : the size of the read value
 */
int printDnsName(const u_char* base, const u_char* payload) {
    int readSize = 0;
    int c = *payload++;
    while(c != 0x00) {
        if(c >= 0xC0 && c <= 0xCF) { //if we need to jump to another place in the payload
            int ptr = *payload++;
            int shift = c - 192;
            ptr += (256*shift); //modulo
            printDnsName(base, base + ptr);
            readSize += 1;
            break;
        }
        else {
            readSize += (c + 1);
            fprintf(stdout, "%.*s", c, payload); //print c char of payload
            fprintf(stdout, ".");
            payload += c;
        }
        c = *(payload++);
    }
    readSize++;
    return readSize;
}

/**
 * @brief this function prints type of dns
 * @param type
 */
void printDnsType(int type){
    switch (type) {
        case 1:
            fprintf(stdout, "A");
            break;
        case 2:
            fprintf(stdout, "NS");
            break;
        case 5:
            fprintf(stdout, "CNAME");
            break;
        case 12:
            fprintf(stdout, "PTR");
            break;
        case 15:
            fprintf(stdout, "MX");
            break;
        case 33:
            fprintf(stdout, "SRV");
            break;
        case 251:
            fprintf(stdout, "IXFR");
            break;
        case  252:
            fprintf(stdout, "AXFR");
            break;
        case 255:
            fprintf(stdout, "All");
            break;
        default:
            fprintf(stdout, "Unknown (%d - 0x%x)", type, type);
            break;
    }
}


/**
 * @brief this function prints the class of dns
 * @param class
 */
void printDnsClass(int class) {
    switch (class) {
        case 1:
            fprintf(stdout, "IN");
            break;
        case 3:
            fprintf(stdout, "CH");
            break;
        case 4:
            fprintf(stdout, "HS");
            break;
        case 254:
            fprintf(stdout, "None");
            break;
        case 255:
            fprintf(stdout, "Any");
            break;
        default:
            fprintf(stdout, "Unknown (%d - 0x%x)", class, class);
            break;
    }
}


/**
 * @brief this function prints the dns operation code
 * @param opcode
 */
void printDnsOpcode(int opcode) {
    switch (opcode){
        case 0:
            fprintf(stdout, "standard query");
            break;
        case 1:
            fprintf(stdout, "inverse query");
            break;
        case 2:
            fprintf(stdout, "server status request");
            break;
        case 4:
            fprintf(stdout, "notify");
            break;
        case 5:
            fprintf(stdout, "update");
            break;
        default:
            fprintf(stdout, "unknow opcode (%d)", opcode);
            break;
    }
}


int printDnsData(const u_char* dns_hdr, const u_char* payload){
    int readSize = 0;
    fprintf(stdout, "\n\t\t\t\t\t");

    //name
    readSize = printDnsName(dns_hdr, payload);
    payload += readSize;

    //type
    uint16_t type = ntohs(*(uint16_t*)payload);
    fprintf(stdout, " | Type: ");
    printDnsType(type);
    payload += 2;
    readSize += 2;

    //class
    fprintf(stdout, " | Class: ");
    uint16_t class = ntohs(*(uint16_t*)payload);
    printDnsClass(class);
    payload += 2;
    readSize += 2;

    //time to live
    uint32_t ttl = *(uint32_t*)payload;
    fprintf(stdout, " | TTL: %u", ntohl(ttl));
    payload += 4;
    readSize += 4;

    //data length
    uint16_t len = ntohs(*(uint16_t*)payload);
    fprintf(stdout, " | length: %d", len);
    payload += 2;
    readSize += 2;

    if (type == 1 && class == 1){ //if it is ip address, print it
        fprintf(stdout, " | Addr: ");
        fprintf(stdout, "%d.%d.%d.%d", payload[0], payload[1], payload[2], payload[3]);
    }
    else if (type == 5) {  //print the content
        fprintf(stdout, " | CNAME: ");
        printDnsName(dns_hdr, payload);
    }
    else {
        fprintf(stdout, " | Data: ");
        printDnsName(dns_hdr, payload);
    }
    readSize += len;
    return readSize;
}