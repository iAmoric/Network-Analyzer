#include "ethernet.h"


void handle_ethernet(const u_char* packet){
    struct ether_header* ethernet_hdr;
    int ethernet_size = sizeof(struct ether_header);
    ethernet_hdr = (struct ether_header*) packet;

    if (ntohs (ethernet_hdr->ether_type) != ETHERTYPE_IP && ntohs (ethernet_hdr->ether_type) != ETHERTYPE_ARP) {
        //Type ethernet inconnu
        //Affiche seulement
        return;
    }

    fprintf(stdout, "\nETHERNET\n");
    fprintf(stdout, "\t@Dest: %s\n", ether_ntoa((const struct ether_addr *) &ethernet_hdr->ether_dhost));
    fprintf(stdout, "\t@Src: %s\n", ether_ntoa((const struct ether_addr *) &ethernet_hdr->ether_shost));

    if (ntohs (ethernet_hdr->ether_type) == ETHERTYPE_IP) {
        fprintf(stdout,"\tIP\n");
        handle_ip(packet, ethernet_size);
    }
    else  if (ntohs (ethernet_hdr->ether_type) == ETHERTYPE_ARP) {
        fprintf(stdout,"\tARP\n");
        handle_arp(packet, ethernet_size);
    }

}
