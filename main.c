/**
    Projet Analyseur Reseau
    Lucas PIERRAT
    M1 CMI ISR
**/

//gcc -o main main.c -lpcap

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <getopt.h>
#include "ethernet.h"


char errbuf[PCAP_ERRBUF_SIZE];
/**
callback function
*/
void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet){
    handle_ethernet(packet);
}

/**
print help for usage
*/
void print_help(){
    fprintf(stdout, "How to use :\n");
    fprintf(stdout, "[-i interface]|[-o capture_file] [-f filter] [-v verbosity]");
    fprintf(stdout, "verbosity between 1 (low) and 3 (high)\n");
}


/**
open file for offline capture
*/
pcap_t* capture_offine(char* file) {
    pcap_t* interface;
    if((interface = pcap_open_offline(file, errbuf)) == NULL) {
        fprintf(stderr, "Unable to open %s\n", file);
        exit(EXIT_FAILURE);
    }
    return interface;
}

/**
open file for
*/

int main(int argc, char **argv) {

    /**
    TODO :
     - traiter les options
        - pouvoir choisir entre capture live / offline
        - si live -> ouvrir le descripteur de capture live
        - si offline -> ouvrir le fichier de capture
     - Gérer les filtres (compile + set)
     */

    pcap_t* interface;
    int verbosity = 1;
    int option;
    int interface_selected = 0;

    while((option = getopt(argc, argv, "hi:o:f:v:")) != -1) {
        switch (option) {
            //help
            case 'h':
                print_help();
                return 0;
            break;

            //live interface
            case 'i':
                if (interface_selected != 0) {
                    fprintf(stderr, "You must choose between live and offline capture  !\n");
                    return 0;
                }
                interface_selected = 1;
                //TODO gérer interface
            break;

            //offline interface
            case 'o':
                if (interface_selected != 0) {
                    fprintf(stderr, "You must choose between live and offline capture  !\n");
                    return 0;
                }
                interface_selected = 1;
                //TODO gérer offline capture
                interface = capture_offine(optarg);
            break;

            //filter
            case 'f':
                //TODO gérer filtre

            break;

            //verbosity
            case 'v':
                //TODO gérer verbosity
                verbosity = atoi(optarg);
                if (verbosity < 1 || verbosity > 3) {
                    fprintf(stderr, "verbosity must be between 1 (low) and 3 (high)\n");
                    return 0;
                }
            break;

            default:
                print_help();
                return 0;
            break;
        }
    }

    if (interface_selected == 0){
        print_help();
    }


    int ret;
    ret = pcap_loop(interface, -1, got_packet, NULL);

    if (ret != 0) {
        //ERREUR
        printf("Erreur pcap_loop\n");
    }


  return 0;
}
