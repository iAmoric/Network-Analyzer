/**
    Projet Analyseur Reseau
    Lucas PIERRAT
    M1 CMI ISR
**/

/**
 * Created by Lucas Pierrat.
 */

//gcc -o main main.c -lpcap
//tcpdump -i wlp4s0 -w file

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <getopt.h>

#include "datalinkLayer.h"

//buffer for error
char errbuf[PCAP_ERRBUF_SIZE];

int verbosity = 3;


/**
 * @brief this function is the callback function for pcap_loop. Launch the analysis of the packet
 * @param args
 * @param header
 * @param packet
 */
void handle_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet){
    static int nbPacket = 1;
    fprintf(stdout, "\n--- [PACKET #%d - %d bytes] ----------------------------------------------- \n", nbPacket, header->len);
    handle_ethernet(packet, verbosity);
    fprintf(stdout, "\n");
    nbPacket++;
}


/**
 * @brief this function indicates how to use the programm
 */
void print_help(){
    fprintf(stdout, "How to use :\n");
    fprintf(stdout, "-i <interface>|-o <capture_file> [-f filter] -v <verbosity>\n");
    fprintf(stdout, "verbosity between 1 (low) and 3 (high)\n");
}


/**
 * @brief this function open the file and create the interface for the offline capture
 * @param file
 * @return interface
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
 * @brief this function opens the interface for the live capture.
 *        It tries to auto select another interface if the selected interface failed to open
 * @param dev
 * @return interface
 */
pcap_t* capture_live(char* dev) {
    pcap_t* interface;

    //open the interface
    interface = pcap_open_live(dev, 1500, 1, 100, errbuf);

    if (interface == NULL) {
        //interface specified is maybe wrong. Retry with auto select
        fprintf(stderr, "Unable to select interface %s for live capture : %s\n", dev,errbuf);
        fprintf(stderr, "Retrying with auto select...\n");

        //lookup for another interface
        dev = pcap_lookupdev(errbuf);

        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            exit(EXIT_FAILURE);
        }

        //open the interface
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

    pcap_t* interface = NULL;
    int option;
    int interface_selected = 0;
    int filter_selected = 0;
    char* filter = NULL;
    struct bpf_program fp;
    bpf_u_int32 mask = 0;

    //get the options of the program
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
                filter_selected = 1;
                filter = optarg;
            break;

            //verbosity
            case 'v':
                verbosity = atoi(optarg);

                if (verbosity < 1 || verbosity > 3) {
                    fprintf(stderr, "verbosity must be between 1 (low) and 3 (high).\n");
                    return 0;
                }
            break;

            default:
                print_help();
                return 0;
            break;
        }
    }

    //guaranteed that an interface has been selected
    if (interface_selected == 0){
        print_help();
        return 0;
    }

    //set filter
    if (filter_selected != 0) {
        if(pcap_compile(interface, &fp, filter, 0, mask) != 0) {
            fprintf(stderr, "Error pcap_compile with filter %s\n", filter);
            return 0;
        }

        if(pcap_setfilter(interface, &fp) != 0) {
            fprintf(stderr, "Error pcap_setfilter with filter %s\n", filter);
            return 0;
        }
    }

    //run treatment loop
    int ret;
    ret = pcap_loop(interface, -1, handle_packet, NULL);

    if (ret != 0)
        fprintf(stdout, "Error pcap_loop\n");

    fprintf(stdout, "\n");

    //exit proprely
    if (filter_selected != 0)
        pcap_freecode(&fp);

    pcap_close(interface);

    fprintf(stdout, "------------------------\n");
    fprintf(stdout, "---- end of capture ----\n");
    fprintf(stdout, "------------------------\n");

    return 0;
}
