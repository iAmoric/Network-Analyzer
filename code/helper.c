#include "helper.h"

void printPrintableAscii(const u_char* payload, int payload_size){
    int i;
    int j;

    printf("\n" );
    for(i = 0 ; i < payload_size ; i++) {
        if (i != 0 && i%32 == 0) { //if one line of hex printing is complete...

            printf("\t\t");
            for(j = i-32; j < i; j++) {
                if (isprint(payload[j]))
                    printf("%c", payload[j]);
                else printf(".");
            }
            printf("\n");
        }

        if(i%32 == 0) printf("\t\t\t\t");
            printf("%02X ", payload[i]);

        if (i == payload_size - 1) {  //print the last spaces

            for(j = 0; j < 31 - i%32; j++)
                printf("   "); //extra spaces

            printf("\t\t");

            for(j= i - i%32; j <= i; j++) {
                if(isprint(payload[j]))
                    printf("%c", payload[j]);
                else
                    printf(".");
            }

            printf( "\n" );
        }
    }
}

void printIPAddress(const u_char* payload, int payload_size) {
    int cpt = payload_size / 4;
    printf(": ");
    for (int j = 0; j < cpt-1; j++){
        for (int i = 0; i < payload_size-1; i++)
            printf("%d.", *payload++);
        printf("%d | ", *payload++);
    }
    for (int i = 0; i < payload_size-1; i++)
        printf("%d.", *payload++);
    printf("%d", *payload++);
}

void printAscii(const u_char* payload, int payload_size) {
    printf(": ");
    for (int i = 0; i < payload_size; i++)
        printf("%c", *payload++);
}

int displayOptionName(unsigned char option) {
    int end = 1;
    switch (option) {
        case TAG_SUBNET_MASK:       //1
            printf("Subnet mask");
            break;
        case TAG_TIME_OFFSET:       //2
            printf("Time offset");
            break;
        case TAG_GATEWAY:           //3
            printf("Gateway");
            break;
        case TAG_DOMAIN_SERVER:     //6
            printf("Domain Name Server");
            break;
        case TAG_HOSTNAME:          //12
            printf("Host name");
            break;
        case TAG_DOMAINNAME:        //15
            printf("Domain name");
            break;
        case TAG_BROAD_ADDR:        //28
            printf("Broadcast address");
            break;
        case TAG_NETBIOS_NS:        //44
            printf("Netbios over name server");
            break;
        case TAG_NETBIOS_SCOPE:     //47
            printf("Netbios over scope");
            break;
        case TAG_REQ_ADDR:          //50
            printf("Requested IP address");
            break;
        case TAG_LEASETIME:         //51
            printf("Lease time");
            break;
        case TAG_DHCP_MSGTYPE:      //53
            printf("DHCP message type");
            break;
        case TAG_SERVERID:          //54
            printf("Server identifier");
            break;
        case TAG_PARAM_REQ:         //54
            printf("Parameter request list");
            break;
        case TAG_CLASSID:           //60
            printf("Client identifier");
            break;
        case TAG_END:               //255
            printf("End");
            end = 0;
            break;
        default:
            printf("Unknown");
            break;
    }
    return end;
}

void displayOptionValue(unsigned char option, const u_char* payload, int payload_size){
    //print an ip address if the value is an option address
    if (option == TAG_SUBNET_MASK || option == TAG_GATEWAY || option == TAG_DOMAIN_SERVER ||
        option == TAG_BROAD_ADDR || option == TAG_NETBIOS_NS || option == TAG_REQ_ADDR ||
        option == TAG_SERVERID) {
        printIPAddress(payload, payload_size);
    }

    //print the ascii charactere if the value is text
    if (option == TAG_HOSTNAME || option == TAG_DOMAINNAME) {
        printAscii(payload, payload_size);
    }

    // for all options of the request list, print the option name
    if (option == TAG_PARAM_REQ) {
        printf(": ");
        for (int i = 0; i < payload_size; i++){
            printf("\n\t\t\t\t\t\t");
            option = *payload++;
            printf("Option %d: ", option);
            displayOptionName(option);
        }
    }

    // print the dhcp message type if required
    if (option == TAG_DHCP_MSGTYPE) {
        printf(": ");
        option = *payload;
        switch (option) {
            case DHCPDISCOVER:
                printf("Discover");
                break;
            case DHCPOFFER:
                printf("Offer");
                break;
            case DHCPREQUEST:
                printf("Request");
                break;
            case DHCPDECLINE:
                printf("Decline");
                break;
            case DHCPACK:
                printf("Ack");
                break;
            case DHCPNAK:
                printf("N-Ack");
                break;
            case DHCPRELEASE:
                printf("Release");
                break;
            default:
                break;
        }
    }
}

//return 1 if the data start with GET, POST or HTTP, else 0
int has_header(const u_char* payload) {
    if (payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T')
        return 1;

    else if (payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T')
        return 1;

    else if (payload[0] == 'H' && payload[1] == 'T' && payload[2] == 'T' && payload[3] == 'P')
        return 1;

    return 0;
}


//print the header of the HTTP payload
//return the size read
int printHeader(const u_char* payload, int verbosity) {
    int end = 0;
    int i = 0;
    int readSize = 0;

    if (verbosity == HIGH)
        printf("\t\t\t\t");

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
                printf("\n\t\t\t\t");
            }
        }
        if (isprint(payload[i]))
            printf("%c", payload[i]);
        i++;
        readSize++;
    }
    return readSize;
}



//return 1 if it is command, 0 if it is data
int is_command(const u_char* payload){
    if (payload[0] == 0xFF)
        return 1;
    return 0;
}

void printTelnetOptions(int option){
    printf("%02d: ", option);
    switch (option) {
        case TELOPT_BINARY:     //00
            printf("Binary");
            break;
        case TELOPT_ECHO:       //01
            printf("Echo");
            break;
        case TELOPT_SGA:        //03
            printf("Supress Go Ahead");
            break;
        case TELOPT_TTYPE:      //24
            printf("Terminal Type");
            break;
        case TELOPT_NAWS:       //31
            printf("Window Size");
            break;
        case TELOPT_TSPEED:     //32
            printf("Terminal Speed");
            break;
        case TELOPT_LINEMODE:   //34
            printf("Linemode");
            break;
        case TELOPT_OLD_ENVIRON:   //36
            printf("Old Environment Variables");
            break;
        case TELOPT_NEW_ENVIRON:   //39
            printf("New Environment Variables");
            break;
        default:
            printf("Unknown");
    }
}
void printTelnetCommand(const u_char *payload, int payload_size) {
    int command, option;
    int i, next;
    const u_char* end = payload + payload_size;

    while (payload < end) {
        *payload++; //shift the first 0xff
        command = *payload++;   //read the command
        printf("\t\t\t\tCommand %d: ", command);
        option = *payload++;    //read options of the command
        switch (command) {
            case DO:        //253
                printf("DO - ");
                printTelnetOptions(option);
                break;

            case DONT:      //254
                printf("DONT - ");
                printTelnetOptions(option);
                break;

            case WONT:      //252
                printf("WONT - ");
                printTelnetOptions(option);
                break;

            case WILL:      //251
                printf("WILL - ");
                printTelnetOptions(option);
                break;

            case SB:        //250
                printf("NEGOCIATION about ");
                    printTelnetOptions(option);
                    switch (option) {
                        case TELOPT_TSPEED:
                            printf(": %d", *payload++);
                            break;
                        case TELOPT_NAWS:
                            printf(": %d x %d", payload[0], payload[2]);
                            payload += 4;
                            break;
                        default:
                            printf(": Unknown");
                            next = payload[0];
                            i = 0;
                            while (next != 0xff)
                                next = payload[i++];
                            payload += i;
                            break;

                    }
                break;

            case SE:        //240
                printf("END SUB NEGOCIATION");
                break;

            default:
                printf("Unknown");
                break;
        }

        printf("\n");
    }
}
