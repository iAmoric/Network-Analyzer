
/**
 * Created by Lucas Pierrat.
 */

#include "datalinkLayer.h"

/**
 * this function processes the ethernet protocol
 * @param packet
 * @param verbosity
 */
void handle_ethernet(const u_char* packet, int verbosity){
    struct ether_header* ethernet_hdr;
    int ethernet_size = sizeof(struct ether_header);
    ethernet_hdr = (struct ether_header*) packet;
    int type = ntohs ((uint16_t) ethernet_hdr->ether_type);

    if (verbosity == HIGH){
        fprintf(stdout, "ETHERNET\n");
        fprintf(stdout, "\tSrc: %s\n", ether_ntoa((const struct ether_addr *) &ethernet_hdr->ether_shost));
        fprintf(stdout, "\tDst: %s\n", ether_ntoa((const struct ether_addr *) &ethernet_hdr->ether_dhost));
    }
    else if (verbosity == MEDIUM) {
        fprintf(stdout, "ETHERNET, ");
        fprintf(stdout, "Src: %s, ", ether_ntoa((const struct ether_addr *) &ethernet_hdr->ether_shost));
        fprintf(stdout, "Dst: %s\n", ether_ntoa((const struct ether_addr *) &ethernet_hdr->ether_dhost));
    }

    //shift
    packet += ethernet_size;

    switch (type) {
        case ETHERTYPE_IP:
            handle_ip(packet, verbosity);
        break;

        case ETHERTYPE_ARP:
            handle_arp(packet, verbosity);
        break;

        case ETHERTYPE_IPV6:    //ipv6 is not supported
            if (verbosity == HIGH)
                fprintf(stdout, "\t");
            fprintf(stdout, "IPv6 (Unsuppported)");
        break;

        default:
            break;
    }

}
