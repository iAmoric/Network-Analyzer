#include "datalinkLayer.h"

void handle_ethernet(const u_char* packet, int verbosity){
    struct ether_header* ethernet_hdr;
    int ethernet_size = sizeof(struct ether_header);
    ethernet_hdr = (struct ether_header*) packet;
    int type = ntohs (ethernet_hdr->ether_type);

    if (verbosity == HIGH){
        printf("ETHERNET\n");
        printf("\t@Dest: %s\n", ether_ntoa((const struct ether_addr *) &ethernet_hdr->ether_dhost));
        printf("\t@Src: %s\n", ether_ntoa((const struct ether_addr *) &ethernet_hdr->ether_shost));
    }
    else if (verbosity == MEDIUM) {
        printf("ETHERNET, ");
        printf("Src: %s, ", ether_ntoa((const struct ether_addr *) &ethernet_hdr->ether_dhost));
        printf("Dst: %s\n", ether_ntoa((const struct ether_addr *) &ethernet_hdr->ether_shost));
    }


    packet += ethernet_size;

    switch (type) {
        case ETHERTYPE_IP:
            handle_ip(packet, verbosity);
        break;
        case ETHERTYPE_ARP:
            handle_arp(packet, verbosity);
        break;
        case ETHERTYPE_IPV6:
            if (verbosity == HIGH)
                printf("\t");
            printf("IPv6 (Unsuppported)\n");
        break;
    }

}
