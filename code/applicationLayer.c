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


void handle_http(const u_char* payload, int payload_size, int is_secured) {
    printf("\t\t\tHTTP");
    if (is_secured)
        printf("S");

    printPrintableAscii(payload, payload_size);
}


void handle_pop(const u_char* payload, int payload_size) {
    printf("\t\t\tPOP3");

    printPrintableAscii(payload, payload_size);
}


void handle_smtp(const u_char* payload, int payload_size, int is_secured) {
    printf("\t\t\tSMTP");
    if (is_secured)
        printf("S");

    printPrintableAscii(payload, payload_size);
}

void handle_imap(const u_char* payload, int payload_size) {
    printf("\t\t\tIMAP");

    printPrintableAscii(payload, payload_size);
}

void handle_telnet(const u_char* packet ){
    printf("\t\t\tTELNET");
}


void handle_ftp(const u_char* payload, int payload_size, int is_request){
    printf("\t\t\tFTP (");
    if (is_request) {
        printf("request)");
        printPrintableAscii(payload, payload_size);
    }
    else {
        printf("data)\n");
        printPrintableAscii(payload, 300);  //print max 300 chars
    }

}


void handle_dns(const u_char* packet) {
    printf("\t\t\tDNS\n");

    unsigned short id = (unsigned short)packet;
    printf("\t\t\t\t0x%x\n", id);
}
