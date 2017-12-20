#include "applicationLayer.h"

void printPrintableAscii(const u_char* payload, int payload_size){
    int i = 0;
    while (i < payload_size ) {
    	if (i%50 == 0){
    		printf("\n\t\t\t\t");
    	}
    	if(isprint(payload[i])){
    		printf("%c", payload[i]);
    	}
    	else{
    		printf(".");
    	}
    	i++;
    }
}


void handle_http(const u_char* payload, int payload_size, int is_secured, int verbosity) {
    switch (verbosity) {
        case HIGH:
                printf("\t\t\tHTTP");
                if (is_secured)
                    printf("S");
                if (payload_size > 0)
                    printPrintableAscii(payload, payload_size);
            break;
        case MEDIUM:
            printf("HTTP");
            if (is_secured)
                printf("S");
            break;
        case LOW:
            break;
        default:
            break;
    }
}


void handle_pop(const u_char* payload, int payload_size, int verbosity) {
    switch (verbosity) {
        case HIGH:
            printf("\t\t\tPOP3");
            if (payload_size > 0)
                printPrintableAscii(payload, payload_size);
            break;
        case MEDIUM:
            printf("POP3");
            break;
        case LOW:
            break;
        default:
            break;

    }

}


void handle_smtp(const u_char* payload, int payload_size, int is_secured, int verbosity) {
    switch (verbosity) {
        case HIGH:
                printf("\t\t\tSMTP");
                if (is_secured)
                    printf("S");
                if (payload_size > 0)
                    printPrintableAscii(payload, payload_size);
            break;
        case MEDIUM:
            printf("SMTP");
            if (is_secured)
                printf("S");
            break;
        case LOW:
            break;
        default:
            break;
    }
}

void handle_imap(const u_char* payload, int payload_size, int verbosity) {
    switch (verbosity) {
        case HIGH:
            printf("\t\t\tIMAP");
            if (payload_size > 0)
                printPrintableAscii(payload, payload_size);
            break;
        case MEDIUM:
            printf("IMAP");
            break;
        case LOW:
            break;
        default:
            break;

    }
}

void handle_telnet(const u_char* packet, int verbosity){
    printf("\t\t\tTELNET");
}


void handle_ftp(const u_char* payload, int payload_size, int is_request, int verbosity){
    switch (verbosity) {
        case HIGH:
                printf("\t\t\tFTP");
                if (is_request)
                    printf(" (request)");
                else
                    printf(" (data)");
                if (payload_size > 0)
                    printPrintableAscii(payload, payload_size);
            break;
        case MEDIUM:
            printf("FTP");
            if (is_request)
                printf(" (request)");
            else
                printf(" (data)");
            break;
        case LOW:
            break;
        default:
            break;
    }

}


void handle_dns(const u_char* packet, int verbosity) {
    printf("\t\t\tDNS\n");
}


void handle_bootp(const u_char* packet, int verbosity) {
    struct bootp* bootp_hdr = (struct bootp*) packet;

    unsigned char op = bootp_hdr->bp_op;
    unsigned char htype = bootp_hdr->bp_htype;
    unsigned char hlen = bootp_hdr->bp_hlen;
	unsigned char hops = bootp_hdr->bp_hops;
	unsigned int xid = bootp_hdr->bp_xid;
	unsigned short secs = bootp_hdr->bp_secs;
	unsigned short flags = bootp_hdr->bp_flags;
    u_int8_t *vendor = bootp_hdr->bp_vend;
    const u_int8_t magic_cookie[] = VM_RFC1048;

    switch (verbosity) {
        case HIGH:
            printf("\t\t\tBOOTP\n");
            printf("\t\t\t\tMsg type: ");
            if (op == 1)
                printf("Request (%d) | ", op);
            else if (op == 2)
                printf("Reply (%d) | ", op);
            else
                printf("Unknown (%d) | ", op);

            printf("Hdw type: ");
            if (htype == 1)
                printf("Ethernet (Ox%x) | ", htype);
            else
                printf("Unknown (Ox%x) | ", htype);

            printf("Hdw addr len: %d | ", hlen);
            printf("Hops: %d | ", hops);
            printf("Secs: %d\n", ntohs(secs));
            printf("\t\t\t\tTransaction ID: 0x%x\n", ntohl(xid));

            printf("\t\t\t\tClient IP address: %s\n", inet_ntoa(bootp_hdr->bp_ciaddr));
            printf("\t\t\t\tYour IP address: %s\n", inet_ntoa(bootp_hdr->bp_yiaddr));
            printf("\t\t\t\tNext server IP address: %s\n", inet_ntoa(bootp_hdr->bp_siaddr));
            printf("\t\t\t\tRelay agent IP address: %s\n", inet_ntoa(bootp_hdr->bp_giaddr));
            printf("\t\t\t\tClient MAC address: ");
            printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
                   bootp_hdr->bp_chaddr[0], bootp_hdr->bp_chaddr[1], bootp_hdr->bp_chaddr[2],
                   bootp_hdr->bp_chaddr[3], bootp_hdr->bp_chaddr[4], bootp_hdr->bp_chaddr[5]);

            printf("\t\t\t\tServer host name: ");
            if (bootp_hdr->bp_sname[0] != 0b00000000)
                printf("%s\n", bootp_hdr->bp_sname);
            else
                printf("not given\n");

            printf("\t\t\t\tBoot file name: ");
            if (bootp_hdr->bp_file[0] != 0b00000000)
                printf("%s\n", bootp_hdr->bp_file);
            else
                printf("not given\n");

                break;

        case MEDIUM:
            printf("BOOTP ");
            break;

        case LOW:
            if(memcmp(vendor, magic_cookie, 4) != 0) {
                printf("BOOTP\t");
                return;
            }
            break;

        default:
            break;
    }

    if(memcmp(vendor, magic_cookie, 4) != 0)
        return;

    packet = vendor + 4;
    handle_dhcp(packet, verbosity);
}


void handle_dhcp(const u_char* packet, int verbosity){
    printf("\t\t\t\tDHCP \n");
    int have_options = 1;
    int is_advanced;
    unsigned char option;
    unsigned char length;

    while (have_options) {
        is_advanced = 0;
        option = *packet++;
        length = *packet++;

        printf("\t\t\t\t\tOption: (%d) ", option);

        switch (option) {

            case TAG_SUBNET_MASK:       //1
                printf("Subnet mask: ");
                /*for (int i = 0; i < length-1; i++)
                    printf("%d.", *packet++);
                printf("%d", *packet++);
                is_advanced = 1;*/
                break;

            case TAG_TIME_OFFSET:       //2
                printf("Time offset: ");
                break;

            case TAG_GATEWAY:           //3
                printf("Gateway: ");
                /*for (int i = 0; i < length-1; i++)
                    printf("%d.", *packet++);
                printf("%d", *packet++);
                int is_advanced = 1;*/
                break;

            case TAG_DOMAIN_SERVER:     //6
                printf("Domain Name Server: ");
                break;

            case TAG_HOSTNAME:          //12
                printf("Host name: ");
                break;

            case TAG_DOMAINNAME:        //15
                printf("Domain name: ");
                break;

            case TAG_BROAD_ADDR:        //28
                printf("Broadcast address: ");
                break;

            case TAG_NETBIOS_NS:        //44
                printf("Netbios over name server: ");
                break;

            case TAG_NETBIOS_SCOPE:     //47
                printf("Netbios over scope: ");
                break;
            case TAG_REQ_ADDR:          //50
                printf("Requested IP address: ");
                break;
            case TAG_LEASETIME:         //51
                printf("Lease time: ");
                break;
            case TAG_DHCP_MSGTYPE:      //53
                printf("DHCP message type: ");
                break;
            case TAG_SERVERID:          //54
                printf("Server identifier: ");
                break;
            case TAG_PARAM_REQ:         //54
                printf("Parameter request list: ");
                break;
            case TAG_CLASSID:           //60
                printf("Client identifier: ");
                break;

            /*case TAG_DHCP_MESSAGE:
                u_int8_t dhcp_message = *packet;
                switch (dhcp_message) {
                    case DHCPDISCOVER:
                        printf("DHCP Discover");
                        break;
                    case DHCPOFFER:
                        printf("DHCP Offer");
                        break;
                    case DHCPREQUEST:
                        printf("DHCP Request");
                        break;
                    case DHCPDECLINE:
                        printf("DHCP Decline");
                        break;
                    case DHCPACK:
                        printf("DHCP Ack");
                        break;
                    case DHCPNAK:
                        printf("DHCP N-Ack");
                        break;
                    case DHCPRELEASE:
                        printf("DHCP Release");
                        break;
                    case DHCPINFORM:
                        printf("DHCP Inform");
                        break;
                    default:
                        break;
                }
                break;*/

            case TAG_END:
                printf("End");
                have_options = 0;
                break;

            default:
                break;
        }
        printf("\n");
        for (int i = 0; i < length; i++)
            *packet++;

    }
}
