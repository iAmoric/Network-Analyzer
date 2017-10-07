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

//buffer for error
char errbuf[PCAP_ERRBUF_SIZE];


/**
callback function
*/
void handle_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet){
    static int nbPacket = 0;
    fprintf(stdout, "\n--- [PACKET #%d] ------------------------------------------------------------ \n", nbPacket);
    handle_ethernet(packet);
    nbPacket++;
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
open interface for live capture
if specified interface failed to be opened, try with auto select another interface
*/
pcap_t* capture_live(char* dev) {
    pcap_t* interface;

    interface = pcap_open_live(dev, 1500, 1, 100, errbuf);

    if (interface == NULL) {
        //interface specified is maybe wrong. Retry with auto select
        fprintf(stderr, "Unable to select interface %s for live capture : %s\n", dev,errbuf);
        fprintf(stderr, "Retrying with auto select...\n");

        dev = pcap_lookupdev(errbuf);

        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            exit(EXIT_FAILURE);
        }

        interface = pcap_open_live(dev, 1500, 1, 100, errbuf);

        if (interface == NULL) {
            fprintf(stderr, "Unable to auto select an interface for live capture : %s\n", errbuf);
            exit(EXIT_FAILURE);
        }
    }

    fprintf(stdout, "Interface %s selected for live capture...\n", dev);
    return interface;
}



int main(int argc, char **argv) {

    /**
    TODO :
     - traiter les options
        - pouvoir choisir entre capture live / offline --> OK
        - si live -> ouvrir le descripteur de capture live --> OK
        - si offline -> ouvrir le fichier de capture --> OK
     - Gérer les filtres (compile + set)
     */

    pcap_t* interface;
    int verbosity = 1;
    int option;
    int interface_selected = 0;
    bpf_u_int32 ip;
    bpf_u_int32 mask;

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
                interface = capture_live(optarg);
            break;

            //offline interface
            case 'o':
                if (interface_selected != 0) {
                    fprintf(stderr, "You must choose between live and offline capture  !\n");
                    return 0;
                }
                interface_selected = 1;
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


    //run treatment loop
    int ret;
    ret = pcap_loop(interface, -1, handle_packet, NULL);

    if (ret != 0) {
        printf("Error pcap_loop\n");
    }

    printf("\n");
    return 0;
}
