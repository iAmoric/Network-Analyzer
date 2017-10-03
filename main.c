/**
    Projet Analyseur Reseau
    Lucas PIERRAT
    M1 CMI ISR
**/


//gcc -o main main.c -lpcap

#include <stdio.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>


void handle_ip(const u_char* packet, int start) {
    struct ip* ip_hdr;
    ip_hdr = (struct ip*) (packet + start);
    int version;
    
    version = packet[start];
    version = version >> 4;
    printf("\t\tVersion: %d\n", version);
}

void handle_arp(const u_char* packet, int start) {

}


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

void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet){
    handle_ethernet(packet);
}


int main() {

    char* errbuf;
    char* fileName = "traffic";

    pcap_t* capture;
    capture = pcap_open_offline(fileName, errbuf);

    if (capture != 0) {
        //ERREUR
        printf("%s\n",  errbuf);
    }

    int ret;
    ret = pcap_loop(capture, -1, got_packet, NULL);

    if (ret != 0) {
        //ERREUR
        printf("Erreur pcap_loop\n");
    }


  return 0;
}
