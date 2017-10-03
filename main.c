/**
    Projet Analyseur Reseau
    Lucas PIERRAT
    M1 CMI ISR
**/


//gcc -o main main.c -lpcap

#include <stdio.h>
#include <pcap.h>
#include "ethernet.h"


void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet){
    handle_ethernet(packet);
}


int main() {

    /**
    TODO :
     - traiter les options
        - pouvoir choisir entre capture live / offline
        - si live -> ouvrir le descripteur de capture live
        - si offline -> ouvrir le fichier de capture
     - Gérer les filtres (compile + set)
     */


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
