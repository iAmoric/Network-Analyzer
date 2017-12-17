#include "http.h"

void handle_http(const u_char* payload, int payload_size, int is_secured) {
    printf("\t\t\tHTTP");
    if (is_secured)
        printf("S");
    //printf("\n");

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
