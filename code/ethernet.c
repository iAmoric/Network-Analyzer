#include "ethernet.h"

void handle_ethernet(const u_char* packet){
    struct ether_header* ethernet_hdr;
    int ethernet_size = sizeof(struct ether_header);
    ethernet_hdr = (struct ether_header*) packet;

    fprintf(stdout, "ETHERNET\n");
    fprintf(stdout, "\t@Dest: %s\n", ether_ntoa((const struct ether_addr *) &ethernet_hdr->ether_dhost));
    fprintf(stdout, "\t@Src: %s\n", ether_ntoa((const struct ether_addr *) &ethernet_hdr->ether_shost));

    packet += ethernet_size;
    int type = ntohs (ethernet_hdr->ether_type);

    switch (type) {
        case ETHERTYPE_IP:
            handle_ip(packet);
        break;
        case ETHERTYPE_ARP:
            handle_arp(packet);
            exit(1);
        break;
        case ETHERTYPE_IPV6:
            fprintf(stdout, "\tIPv6 (Unsuppported)\n");
        break;
    }

}
