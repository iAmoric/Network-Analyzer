
/**
 * Created by Lucas Pierrat.
 */

#include "applicationLayer.h"

/**
 * @brief this function processes the http protocol
 * @param payload
 * @param payload_size
 * @param is_secured: 1 if it is the secure version of http, else 0
 * @param verbosity
 */
void handle_http(const u_char* payload, int payload_size, int is_secured, int verbosity) {
    switch (verbosity) {
        case HIGH:
                fprintf(stdout, "\t\t\tHTTP");
                if (is_secured) {
                    fprintf(stdout, "S");
                    break;  //encrypted, do not continue
                }

                //do not print the rest if there is no data
                if (payload_size <= 0)
                    break;

                //header
                if (has_header(payload)) {
                    fprintf(stdout, "\n\t\t\t\tHeader:\n");
                    int shift = printHeader(payload, verbosity);

                    //shift the payload
                    payload += shift;
                    payload_size -= shift;
                }

                //data
                if (payload_size > 0){
                    fprintf(stdout, "\n\t\t\t\tData:");
                    printHexaAscii(payload, payload_size);
                }
            break;

        case MEDIUM:
            fprintf(stdout, "HTTP");
            if (is_secured) {
                fprintf(stdout, "S");
                break;  //do not continue if encrypted
            }

            //do not print the rest if there is no data
            if (payload_size <= 0)
                break;


            //header
            if (has_header(payload)) {
                fprintf(stdout, ", ");
                printHeader(payload, verbosity);
            }

            break;

        case LOW:
            //do not continue if encrypted
            if (is_secured)
                break;

            //do not print the rest if there is no data
            if (payload_size <= 0)
                break;

            //header
            if (has_header(payload))
                printHeader(payload, verbosity);
            else
                fprintf(stdout, "Data - %d bytes", payload_size);

            break;

        default:
            break;
    }
}


/**
 * @brief this function processes the pop protocol
 * @param payload
 * @param payload_size
 * @param verbosity
 */
void handle_pop(const u_char* payload, int payload_size, int verbosity) {
    switch (verbosity) {
        case HIGH:
            fprintf(stdout, "\t\t\tPOP3");
            if (payload_size > 0)
                printHexaAscii(payload, payload_size);
            break;

        case MEDIUM:
            fprintf(stdout, "POP3");
            break;

        case LOW:
            break;

        default:
            break;

    }

}


/**
 * @brief this function processes the smtp protocol
 * @param payload
 * @param payload_size
 * @param is_secured: 1 if it is the secure version of smtp, else 0
 * @param verbosity
 */
void handle_smtp(const u_char* payload, int payload_size, int is_secured, int verbosity) {
    switch (verbosity) {
        case HIGH:
                fprintf(stdout, "\t\t\tSMTP");
                if (is_secured)
                    fprintf(stdout, "S");

                //only print the content if there is still data
                if (payload_size > 0)
                    printHexaAscii(payload, payload_size);
            break;

        case MEDIUM:
            fprintf(stdout, "SMTP");
            if (is_secured)
                fprintf(stdout, "S");
            break;

        case LOW:
            break;
        default:
            break;
    }
}


/**
 * @brief this function processes the imap protocol
 * @param payload
 * @param payload_size
 * @param verbosity
 */
void handle_imap(const u_char* payload, int payload_size, int verbosity) {
    switch (verbosity) {
        case HIGH:
            fprintf(stdout, "\t\t\tIMAP");
            if (payload_size > 0)
                printHexaAscii(payload, payload_size);
            break;

        case MEDIUM:
            fprintf(stdout, "IMAP");
            break;

        case LOW:
            break;

        default:
            break;

    }
}

/**
 * @brief this function processes the telnet protocol
 * @param payload
 * @param payload_size
 * @param verbosity
 */
void handle_telnet(const u_char* payload, int payload_size, int verbosity){
    switch (verbosity) {
        case HIGH:
                fprintf(stdout, "\t\t\tTELNET\n");

                //do not continue if there is no data
                if (payload_size <= 0)
                    break;

                if (is_command(payload)) {
                    fprintf(stdout, "\t\t\t\tCommands\n");
                    telnetCommand(payload, payload_size);
                }
                else {
                    fprintf(stdout, "\t\t\t\tData");
                    fprintf(stdout, ": ");
                    fprintf(stdout, "\n\t\t\t\t");
                    printAscii(payload, payload_size);
                }

            break;

        case MEDIUM:
            if (is_command(payload))
                fprintf(stdout, "TELNET Commands...");
            else
                fprintf(stdout, "TELNET Data...");
            break;

        case LOW:
            if (is_command(payload))
                fprintf(stdout, "TELNET Commands...");
            else
                fprintf(stdout, "TELNET Data...");
            fprintf(stdout, "\n");
            break;

        default:
            break;
    }
}


/**
 * @brief this function processes the ftp protocol
 * @param payload
 * @param payload_size
 * @param is_request: 1 if it is a request (port 21), 0 if it is data (port 20)
 * @param verbosity
 */
void handle_ftp(const u_char* payload, int payload_size, int is_request, int verbosity){
    switch (verbosity) {
        case HIGH:
                fprintf(stdout, "\t\t\tFTP");
                if (is_request) {
                    fprintf(stdout, " (request)");

                    if (payload_size > 0) { //only if there is data
                        fprintf(stdout, ": ");
                        printAscii(payload, payload_size);
                    }

                }

                else {
                    fprintf(stdout, " (data)");
                    if (payload_size > 0)
                        printHexaAscii(payload, payload_size);
                }
            break;

        case MEDIUM:
            fprintf(stdout, "FTP");
            if (is_request)
                fprintf(stdout, " (request)");
            else
                fprintf(stdout, " (data)");
            break;

        case LOW:
            if (is_request) {
                fprintf(stdout, "Request");
                if (payload_size > 0) { //only if there is data
                    fprintf(stdout, ": ");
                    printAscii(payload, payload_size);
                }
            }
            break;

        default:
            break;
    }

}


/**
 * @brief this function processes the dns protocol
 * @param packet
 * @param verbosity
 */
void handle_dns(const u_char* payload, int verbosity) {
    struct  dns_header* dns_hdr = (struct dns_header*) payload;
    //TODO move in .h
    char url[MAX_URL_SIZE];
    char cnameUrl[MAX_URL_SIZE];
    int questions = ntohs((uint16_t) dns_hdr->qdcount);
    int answers = ntohs((uint16_t) dns_hdr->ancount);
    int authority = ntohs((uint16_t) dns_hdr->nscount);
    int additional = ntohs((uint16_t) dns_hdr->arcount);

    switch (verbosity) {
        case HIGH:
            fprintf(stdout, "\t\t\tDNS\n");
            fprintf(stdout, "\t\t\t\tTransaction ID: 0x%x\n", ntohs((uint16_t) dns_hdr->tid));

            //query/response
            if (dns_hdr->qr & 1)
                fprintf(stdout, "\t\t\t\tResponse: ");
            else
                fprintf(stdout, "\t\t\t\tQuery: ");

            printDnsOpcode(dns_hdr->opcode);

            fprintf(stdout, "\n\t\t\t\t");

            //authoritative answer
            if (dns_hdr->aa & 1)
                fprintf(stdout, "Answer: authoritative | ");
            else
                fprintf(stdout, "Answer: not authoritative | ");

            //truncated
            if (dns_hdr->tc & 1)
                fprintf(stdout, "Message: truncated | ");
            else
                fprintf(stdout, "Answer: not truncated | ");

            //recursion desired
            if (dns_hdr->rd & 1)
                fprintf(stdout, "Recursion: desired | ");
            else
                fprintf(stdout, "Answer: not desired | ");

            //recusion available
            if (dns_hdr->ra & 1)
                fprintf(stdout, "Recursion: available\n");
            else
                fprintf(stdout, "Recursion: not available\n");

            //total questions/answers etc
            fprintf(stdout, "\t\t\t\tQuestions: %d ", questions);
            fprintf(stdout, "| Answer RRs: %d ", answers);
            fprintf(stdout, "| Authority RRs: %d", authority);
            fprintf(stdout, "| Additional RRs: %d\n", additional);

            //shift packet
            payload += sizeof(struct dns_header);

            //questions
            if (questions > 0)
                fprintf(stdout, "\t\t\t\tQueries:\n");
            for (int i = 0; i < questions; i++) {
                fprintf(stdout, "\t\t\t\t\t");
                //print query name
                payload += 1;
                int j = 0;
                while (payload[j] != 0x00) {
                    if (isprint(payload[j]))
                        url[j] = payload[j];    //save the url for the response
                    else
                        url[j] = '.';
                    j++;
                }
                url[j] = '\0';  //string end
                payload += j + 1;
                fprintf(stdout, "%s", url);

                //type
                uint16_t type = ntohs(*(uint16_t*)payload);
                fprintf(stdout, " | type: ");
                printDnsType(type, 0);
                payload += 2;

                //class
                uint16_t class = ntohs(*(uint16_t*)payload);
                fprintf(stdout, " | Class: ");
                printDnsClass(class);
                payload += 2;

                fprintf(stdout, "\n");
            }   //end of questions


            //answers
            if (answers > 0)
                fprintf(stdout, "\t\t\t\tAnswers:\n");
            int cnameFound = 0;
            for (int i = 0; i < answers; i++) {
                fprintf(stdout, "\t\t\t\t\t");

                //name
                if (cnameFound)
                    fprintf(stdout, "%s", cnameUrl);
                else
                    fprintf(stdout, "%s", url);
                payload += 2;

                //type
                uint16_t type = ntohs(*(uint16_t*)payload);
                fprintf(stdout, " | type: ");
                cnameFound = printDnsType(type, cnameFound);
                payload += 2;

                //class
                fprintf(stdout, " | Class: ");
                uint16_t class = ntohs(*(uint16_t*)payload);
                printDnsClass(class);
                payload += 2;

                //time to live
                uint32_t ttl = *(uint32_t*)payload;
                fprintf(stdout, " | TTL: %u", ntohl(ttl));
                payload += 4;

                //data length
                uint16_t len = ntohs(*(uint16_t*)payload);
                fprintf(stdout, " | length: %d", len);
                payload += 2;

                if (type == 5)
                    fprintf(stdout, " | CNAME: ");
                else
                    fprintf(stdout, " | Addr: ");

                if (type != 5 && class == 1){ //if it is ip address, print it
                    fprintf(stdout, "%d.%d.%d.%d", payload[0], payload[1], payload[2], payload[3]);
                }
                else {  //print the content
                    int j = 0;
                    while(j < len) {
                        if (isprint(payload[j])) {
                            if (type == 5)  //save the url if needed
                                cnameUrl[j] = payload[j];
                            fprintf(stdout, "%c", payload[j]);
                        }
                        else {
                            if (type == 5)
                                cnameUrl[j] = '.';
                            fprintf(stdout, ".");
                        }
                        j++;
                    }

                    cnameUrl[j] = '\0'; //string end
                }

                //shift
                payload += len;

                fprintf(stdout, "\n");
            }   //end of answers


            //authority
            if (authority > 0)
                fprintf(stdout, "\t\t\t\tAuthoritative nameservers:\n");
            for (int i = 0; i < authority; i++){
                fprintf(stdout, "\t\t\t\t\txxx: ");
                payload += 2;

                //type
                uint16_t type = ntohs(*(uint16_t*)payload);
                fprintf(stdout, "type: ");
                printDnsType(type, 0);
                payload += 2;
                //class

                fprintf(stdout, " | Class: ");
                uint16_t class = ntohs(*(uint16_t*)payload);
                printDnsClass(class);
                payload += 2;

                //time to live
                uint32_t ttl = *(uint32_t*)payload;
                fprintf(stdout, " | TTL: %u", ntohl(ttl));
                payload += 4;

                //data length
                uint16_t len = ntohs(*(uint16_t*)payload);
                fprintf(stdout, " | length: %d", len);
                payload += 2;

                if (type == 1 && class == 1)    //print ip address if needed
                    fprintf(stdout, " | Address: %d.%d.%d.%d\n", payload[0], payload[1], payload[2], payload[3]);
                else
                    fprintf(stdout, " | xxx\n");

                //shift
                payload += len;
            }   //end of authoritative nameservers

            //additional
            if (additional > 0)
                fprintf(stdout, "\t\t\t\tAdditional records:\n");
            for (int i = 0; i < additional; i++){
                fprintf(stdout, "\t\t\t\t\txxx: ");
                payload += 2;

                //type
                uint16_t type = ntohs(*(uint16_t*)payload);
                fprintf(stdout, "type: ");
                printDnsType(type, 0);
                payload += 2;

                //class
                fprintf(stdout, " | Class: ");
                uint16_t class = ntohs(*(uint16_t*)payload);
                printDnsClass(class);
                payload += 2;

                //time to live
                uint32_t ttl = *(uint32_t*)payload;
                fprintf(stdout, " | TTL: %u", ntohl(ttl));
                payload += 4;

                //data length
                uint16_t len = ntohs(*(uint16_t*)payload);
                fprintf(stdout, " | length: %d", len);
                payload += 2;

                if (type == 1 && class == 1)    //print ip address if needed
                    fprintf(stdout, " | Address: %d.%d.%d.%d\n", payload[0], payload[1], payload[2], payload[3]);
                else
                    fprintf(stdout, " | xxx\n");

                //shift
                payload += len;
            }   //end of additional
            break;

        case MEDIUM:
            fprintf(stdout, "DNS ");
            //type of query/response
            if (dns_hdr->qr & 1)
                fprintf(stdout, "(Response - ");
            else
                fprintf(stdout, "(Query - ");
            printDnsOpcode(dns_hdr->opcode);
            fprintf(stdout, ")");
            break;

        case LOW:
            fprintf(stdout, "DNS \t");
            //type of query/response
            if (dns_hdr->qr & 1)
                fprintf(stdout, "Response ");
            else
                fprintf(stdout, "Query ");
            printDnsOpcode(dns_hdr->opcode);
            fprintf(stdout, " 0x%x ", ntohs((uint16_t) dns_hdr->tid));

            //shift
            payload += sizeof(struct dns_header);

            if (questions > 0 && answers == 0){ //if query, print 1st question
                payload += 1;
                int j = 0;
                while (payload[j] != 0x00) {
                    if (isprint(payload[j]))
                        url[j] = payload[j];    //save the url for the response
                    else
                        url[j] = '.';
                    j++;
                }
                url[j] = '\0';  //string end
                payload += j + 1;

                //type
                uint16_t type = ntohs(*(uint16_t*)payload);
                printDnsType(type, 0);
                fprintf(stdout, " %s", url);
            }

            if (answers > 0) {  //if response, print 1st answers
                //shift the questions and save the url
                for (int i = 0; i < questions; i++) {
                    payload += 1;
                    int j = 0;
                    while (payload[j] != 0x00) {
                        if (isprint(payload[j]))
                            url[j] = payload[j];    //save the url for the response
                        else
                            url[j] = '.';
                        j++;
                    }
                    url[j] = '\0';  //string end
                    payload += j + 1;   //name
                    payload += 2;       //type
                    payload += 2;       //class
                }

                payload += 2;

                //type
                uint16_t type = ntohs(*(uint16_t*)payload);
                printDnsType(type, 0);
                fprintf(stdout, " %s", url);
                payload += 2;

                if (type == 1) {
                    payload += 2;           //class
                    payload += 4;           //ttl
                    payload += 2;           //length
                    fprintf(stdout, " %d.%d.%d.%d", payload[0], payload[1], payload[2], payload[3]);
                }
                else if (type == 5) {
                    payload += 2;           //class
                    payload += 4;           //ttl
                    //length
                    uint16_t len = ntohs(*(uint16_t*)payload);
                    payload += 2;
                    int j = 0;
                    fprintf(stdout, " ");
                    while(j < len) {
                        if (isprint(payload[j]))
                            fprintf(stdout, "%c", payload[j]);
                        else
                            fprintf(stdout, ".");
                        j++;
                    }

                }


            }

            break;

        default:
            break;
    }


}


/**
 * @brief this function proceses the bootp protocol
 * @param packet
 * @param verbosity
 */
void handle_bootp(const u_char* packet, int verbosity) {
    struct bootp* bootp_hdr = (struct bootp*) packet;

    unsigned char op = bootp_hdr->bp_op;            //
    unsigned char htype = bootp_hdr->bp_htype;      //hardware address type
    unsigned char hlen = bootp_hdr->bp_hlen;        //hardware address length
	unsigned char hops = bootp_hdr->bp_hops;
	unsigned int xid = bootp_hdr->bp_xid;           //id of the transaction
	unsigned short secs = bootp_hdr->bp_secs;
	unsigned short flags = bootp_hdr->bp_flags;
    u_int8_t *vendor = bootp_hdr->bp_vend;          //magic cookie
    const u_int8_t magic_cookie[] = VM_RFC1048;     //magic cookie

    switch (verbosity) {
        case HIGH:
            fprintf(stdout, "\t\t\tBOOTP\n");

            //type of the message
            fprintf(stdout, "\t\t\t\tMsg type: ");
            if (op == BOOTREQUEST)          //request
                fprintf(stdout, "Request (%d) | ", op);
            else if (op == BOOTREPLY)       //reply
                fprintf(stdout, "Reply (%d) | ", op);
            else
                fprintf(stdout, "Unknown (%d) | ", op);

            //hardware address type
            fprintf(stdout, "Hdw type: ");
            if (htype == ETHERNET)          //ethernet
                fprintf(stdout, "Ethernet (Ox%x) | ", htype);
            else
                fprintf(stdout, "Unknown (Ox%x) | ", htype);

            fprintf(stdout, "Hdw addr len: %d | ", hlen);    //hardware addres length
            fprintf(stdout, "Hops: %d | ", hops);
            fprintf(stdout, "Secs: %d\n", ntohs(secs));
            fprintf(stdout, "\t\t\t\tTransaction ID: 0x%x\n", ntohl(xid));   //id of the transaction

            //addresse (ip/mac) from client etc..
            fprintf(stdout, "\t\t\t\tClient IP address: %s\n", inet_ntoa(bootp_hdr->bp_ciaddr));
            fprintf(stdout, "\t\t\t\tYour IP address: %s\n", inet_ntoa(bootp_hdr->bp_yiaddr));
            fprintf(stdout, "\t\t\t\tNext server IP address: %s\n", inet_ntoa(bootp_hdr->bp_siaddr));
            fprintf(stdout, "\t\t\t\tRelay agent IP address: %s\n", inet_ntoa(bootp_hdr->bp_giaddr));
            fprintf(stdout, "\t\t\t\tClient MAC address: ");
            fprintf(stdout, "%02x:%02x:%02x:%02x:%02x:%02x\n",
                   bootp_hdr->bp_chaddr[0], bootp_hdr->bp_chaddr[1], bootp_hdr->bp_chaddr[2],
                   bootp_hdr->bp_chaddr[3], bootp_hdr->bp_chaddr[4], bootp_hdr->bp_chaddr[5]);

            fprintf(stdout, "\t\t\t\tServer host name: ");
            if (bootp_hdr->bp_sname[0] != 0b00000000)   //if the server host name is defined
                fprintf(stdout, "%s\n", bootp_hdr->bp_sname);
            else
                fprintf(stdout, "not given\n");

            fprintf(stdout, "\t\t\t\tBoot file name: ");
            if (bootp_hdr->bp_file[0] != 0b00000000)    //if the boot file name is defined
                fprintf(stdout, "%s\n", bootp_hdr->bp_file);
            else
                fprintf(stdout, "not given\n");

            break;

        case MEDIUM:
            fprintf(stdout, "BOOTP");
            break;

        case LOW:
            //if there is no magic cookie
            if(memcmp(vendor, magic_cookie, 4) != 0) {
                fprintf(stdout, "BOOTP\t");
                return;
            }
            break;

        default:
            break;
    }

    //if there is no Magic cookie, do not continue to dhcp
    if(memcmp(vendor, magic_cookie, 4) != 0)
        return;

    //shift the packet and go to dhcp
    packet = (const u_char *) (vendor + 4);
    handle_dhcp(packet, verbosity, xid);
}


/**
 * @brief this function processes the dhcp protocol
 * @param packet
 * @param verbosity
 * @param xid: id of the transaction. Got from bootp function
 */
void handle_dhcp(const u_char* packet, int verbosity, unsigned int xid){
    int have_options = 1;
    unsigned char option;
    unsigned char length;
    const u_char *value;

    switch (verbosity) {
        case HIGH:
            fprintf(stdout, "\t\t\t\tDHCP \n");
            //get all options
            while (have_options) {
                option = *packet++;
                if (option == TAG_PAD)    //no needs to read/shift for the length if option is padding
                    fprintf(stdout, "\t\t\t\t\tOption %d: (0) Padding\n", option);
                else {
                    length = *packet++;
                    value = packet;

                    fprintf(stdout, "\t\t\t\t\tOption %d: (%d) ", option, length);

                    //print name and value
                    have_options = dhcpOptionName(option);
                    dhcpOptionValue(option, value, length);

                    fprintf(stdout, "\n");

                    //shift
                    packet += length;
                }
            }
            break;

        case MEDIUM:
            //get the message type if exists
            while (have_options) {
                option = *packet++;
                if (option != TAG_PAD) {
                    length = *packet++;
                    //quit if end of option
                    if (option == TAG_END)
                        have_options = 0;
                    else {
                        //if option is MESSAGE TYPE, display the type and quit
                        if (option == TAG_DHCP_MSGTYPE) {
                            dhcpOptionValue(option, packet, 0);
                            have_options = 0;
                        }
                    }
                    //shift the packet
                    packet += length;
                }

            }
            break;

        case LOW:
            fprintf(stdout, "DHCP\t");
            //get the message type if exists
            while (have_options) {
                option = *packet++;
                if (option != TAG_PAD) {
                    length = *packet++;
                    //quit if end of option
                    if (option == TAG_END)
                        have_options = 0;
                    else {
                        //if option is MESSAGE TYPE, display the type and quit
                        if (option == TAG_DHCP_MSGTYPE) {
                            fprintf(stdout, "Message type");
                            dhcpOptionValue(option, packet, 0);
                            fprintf(stdout, " - ");
                            have_options = 0;
                        }
                    }
                    //shift the packet
                    packet += length;
                }
            }

            fprintf(stdout, "Transaction id 0x%x", xid);
            break;

        default:
            break;
    }

}
