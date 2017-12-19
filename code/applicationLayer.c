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
    printf("\t\t\tPOP3");

    if (verbosity == HIGH)
        printPrintableAscii(payload, payload_size);
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
    printf("\t\t\tIMAP");

    if (verbosity == HIGH)
        printPrintableAscii(payload, payload_size);
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
