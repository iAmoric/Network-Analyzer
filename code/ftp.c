#include "ftp.h"

void handle_ftp(const u_char* payload, int payload_size, int is_request){
    printf("\t\t\tFTP (");
    if (is_request) {
        printf("request)");
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
    else {
        printf("data)\n");
        int i = 0;
        while (i < 300) {
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



}
