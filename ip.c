#include "ip.h"

void handle_ip(const u_char* packet, int start) {
    struct ip* ip_hdr;
    int version;

    ip_hdr = (struct ip*) (packet + start);

    //Extract ip version from the first byte;
    version = packet[start];
    version = version >> 4;

    printf("\t\tVersion: %d\n", version);

    //Continue only if IPv4
    if (version != 4) {
        return;
    }
    
}
