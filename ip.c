#include "ip.h"

void handle_ip(const u_char* packet, int start) {
    struct ip* ip_hdr;
    int version;

    ip_hdr = (struct ip*) (packet + start);

    version = packet[start];
    version = version >> 4;

    if (version != 4) {
        //Version IP non supporté
        return;
    }
    else {
        printf("\t\tVersion: %d\n", version);
    }
}
