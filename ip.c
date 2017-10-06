#include "ip.h"

void handle_ip(const u_char* packet) {
    struct ip* ip_hdr;
    ip_hdr = (struct ip*) (packet);

    int version;    //ip version
    int hl;         //header length

    version = ip_hdr->ip_v;

    //Continue only if IPv4
    if (version == 6) {
        fprintf(stdout,"\tIPv6\n");
        return;
    }

    fprintf(stdout,"\tIPv4\n");

    hl = ip_hdr->ip_hl;

    printf("\t\thl: %d\n", hl);

    /*
    printf("\t\t@Src: %d\n", ip_hdr->saddr);
    printf("\t\t@Dest: %d\n", ip_hdr->daddr);
    */
}
