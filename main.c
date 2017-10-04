/**
    Projet Analyseur Reseau
    Lucas PIERRAT
    M1 CMI ISR
**/

//gcc -o main main.c -lpcap

#include <stdio.h>
#include <pcap.h>
#include <getopt.h>
#include "ethernet.h"

//verbosity set to 1 by default
int verbosity = 1;

/**
*/
void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet){
    handle_ethernet(packet);
}

/**
*/
void print_help(){
    fprintf(stdout, "How to use :\n");
    fprintf(stdout, "[-i interface]|[-o capture_file] [-f filter] [-v verbosity]");
    fprintf(stdout, "verbosity between 1 (low) and 3 (high)\n");
}


int main(int argc, char **argv) {

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

    int option;
    int interface = 0;

    while((option = getopt(argc, argv, "hi:o:f:v:")) != -1) {
        switch (option) {
            //help
            case 'h':
                print_help();
                return 0;
            break;

            //live interface
            case 'i':
                if (interface != 0) {
                    fprintf(stdout, "You must choose between live and offline capture  !\n");
                    return 0;
                }
                interface = 1;
                //TODO gérer interface
                printf("live\n");
            break;

            //offline interface
            case 'o':
                if (interface != 0) {
                    fprintf(stdout, "You must choose between live and offline capture  !\n");
                    return 0;
                }
                interface = 1;
                //TODO gérer offline capture
                printf("offline\n");
            break;

            //filter
            case 'f':
                //TODO gérer filtre
                printf("filtre\n");
            break;

            //verbosity
            case 'v':
                //TODO gérer verbosity
                printf("verbosity\n" );
            break;

            default:
                print_help();
                return 0;
            break;
        }
    }

    if (interface == 0){
        print_help();
    }

    /*pcap_t* capture;
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
    }*/


  return 0;
}
