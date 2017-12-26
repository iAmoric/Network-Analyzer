#include "applicationLayer.h"

void handle_http(const u_char* payload, int payload_size, int is_secured, int verbosity) {
    switch (verbosity) {
        case HIGH:
                printf("\t\t\tHTTP");
                if (is_secured) {
                    printf("S");
                    break;  //do not continue if encrypted
                }

                //do not print the rest if there is no data
                if (payload_size <= 0)
                    break;

                //header
                if (has_header(payload)) {
                    printf("\n\t\t\t\tHeader:\n");
                    int shift = printHeader(payload, verbosity);

                    //shift the payload
                    payload += shift;
                    payload_size -= shift;
                }

                //data
                if (payload_size > 0){
                    printf("\n\t\t\t\tData:");
                    printPrintableAscii(payload, payload_size);
                }
            break;

        case MEDIUM:
            printf("HTTP");
            if (is_secured) {
                printf("S");
                break;  //do not continue if encrypted
            }

            //do not print the rest if there is no data
            if (payload_size <= 0)
                break;


            //header
            if (has_header(payload)) {
                printf(", ");
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

void handle_telnet(const u_char* payload, int payload_size, int verbosity){
    switch (verbosity) {
        case HIGH:
                printf("\t\t\tTELNET\n");

                //do not continue if there is no data
                if (payload_size <= 0)
                    break;

                if (is_command(payload)) {
                    printf("\t\t\t\tCommands\n");
                    printTelnetCommand(payload, payload_size);
                }
                else {
                    printf("\t\t\t\tData");
                    printAscii(payload, payload_size);
                }

            break;

        case MEDIUM:
            if (is_command(payload))
                printf("TELNET Commands...");
            else
                printf("TELNET Data...");
            break;

        case LOW:
            if (is_command(payload))
                printf("TELNET Commands...");
            else
                printf("TELNET Data...");
            printf("\n");
            break;

        default:
            break;
    }
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
            printf("BOOTP");
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

    //if there is no Magic cookie, do not continue to dhcp
    if(memcmp(vendor, magic_cookie, 4) != 0)
        return;

    packet = vendor + 4;
    handle_dhcp(packet, verbosity, xid);
}

void handle_dhcp(const u_char* packet, int verbosity, unsigned int xid){
    int have_options = 1;
    unsigned char option;
    unsigned char length;
    const u_char *value;
    int cpt;

    switch (verbosity) {
        case HIGH:
            printf("\t\t\t\tDHCP \n");
            //get all options
            while (have_options) {
                option = *packet++;
                if (option == 0)
                    printf("\t\t\t\t\tOption %d: (0) Padding\n", option);
                else {
                    length = *packet++;
                    value = packet;

                    printf("\t\t\t\t\tOption %d: (%d) ", option, length);

                    //print name and value
                    have_options = displayOptionName(option);
                    displayOptionValue(option, value, length);

                    printf("\n");

                    //shift
                    for (int i = 0; i < length; i++)
                    *packet++;
                }
            }
            break;

        case MEDIUM:
            //get the message type if exists
            while (have_options) {
                option = *packet++;
                length = *packet++;
                //quit if end of option
                if (option == TAG_END)
                    have_options = 0;
                else {
                    //if option is MESSAGE TYPE, display the type and quit
                    if (option == TAG_DHCP_MSGTYPE) {
                        displayOptionValue(option, packet, 0);
                        have_options = 0;
                    }
                }
                //shift the packet
                for (int i = 0; i < length; i++)
                    *packet++;
            }
            break;

        case LOW:
            printf("DHCP\t");
            //get the message type if exists
            while (have_options) {
                option = *packet++;
                length = *packet++;
                //quit if end of option
                if (option == TAG_END)
                    have_options = 0;
                else {
                    //if option is MESSAGE TYPE, display the type and quit
                    if (option == TAG_DHCP_MSGTYPE) {
                        printf("Message type");
                        displayOptionValue(option, packet, 0);
                        printf(" - ");
                        have_options = 0;
                    }
                }
                //shift the packet
                for (int i = 0; i < length; i++)
                    *packet++;
            }

            printf("Transaction id 0x%x", xid);

            break;
            break;

        default:
            break;
    }

}
