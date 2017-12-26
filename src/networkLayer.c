#include "networkLayer.h"

/**
        IP
*/
void handle_ip(const u_char* packet, int verbosity) {
    struct ip* ip_hdr;
    ip_hdr = (struct ip*)packet;

    int protocol = ip_hdr->ip_p;
    int payload_size =  ntohs(ip_hdr->ip_len) - sizeof(struct ip);

    switch (verbosity) {
        case HIGH:
            printf("\tIPv4");
            printf("\n\t\thl: %d | ", ip_hdr->ip_hl);
            printf("tos: %d | ", ip_hdr->ip_tos);
            printf("len: %d | ", ntohs(ip_hdr->ip_len));
            printf("id: %d | ", ntohs(ip_hdr->ip_id));
            //TODO check it
            printf("off: %d | ", ip_hdr->ip_off);
            printf("ttl: %d | ", ip_hdr->ip_ttl);
            printf("sum: 0x%x\n", ntohs(ip_hdr->ip_sum));
            printf("\t\t@Src: %s\n", inet_ntoa(ip_hdr->ip_src));
            printf("\t\t@Dest: %s\n", inet_ntoa(ip_hdr->ip_dst));
            break;

        case MEDIUM:
            printf("IPv4");
            printf(", Src: %s, ", inet_ntoa(ip_hdr->ip_src));
            printf("Dst: %s\n", inet_ntoa(ip_hdr->ip_dst));
            break;

        case LOW:
            printf("Src: %s\t", inet_ntoa(ip_hdr->ip_src));
            printf("Dst: %s\t", inet_ntoa(ip_hdr->ip_dst));
            break;
    }


    packet += ip_hdr->ip_hl * 4;

    switch (protocol) {
        case 0x06:
            handle_tcp(packet, payload_size, verbosity);
        break;
        case 0x11:
            handle_udp(packet, payload_size, verbosity);
        break;
        default:
            printf("\t\tUnsupported protocol : 0x%x\n", protocol);
        break;
    }

}


/**
        ARP
*/
void handle_arp(const u_char* packet, int verbosity) {
	struct arp_hdr* arp_hdr;
	arp_hdr = (struct arp_hdr*) packet;

	int hard_addr = ntohs(arp_hdr->htype);
	int hard_pro = ntohs(arp_hdr->ptype);
    int i;
    u_int16_t op = ntohs(arp_hdr->oper);    //opcode

    switch (verbosity) {
        case HIGH:
            printf("\tARP");
            //hardware type
        	printf("\n\t\tHardware type : ");
        	if (hard_addr == 1) {
        		printf("Ethernet ");
        	}
        	else {
        		printf("Unknown ");
        	}

            //hardware length
        	printf("(%d) | ", arp_hdr->hlen);

        	//hardware protocol
        	printf("Hardware protocol : ");
        	if (hard_pro == 2048) {
        		printf("IPv4 ");
        	}
        	else {
        		printf("Unknown ");
        	}

            //protocol length
        	printf("(%d) | ", arp_hdr->plen);

        	//opcode
        	switch (op) {
        		case ARPOP_REQUEST:
        			printf("Request\n");
        		break;
        		case ARPOP_REPLY:
        			printf("Reply\n");
        		break;
        		default:
        			printf("unknown opcode : %d\n", op);
        		break;
        	}

            if (hard_addr == 1 && hard_pro == 2048) {
                //sender
            	printf("\t\tSender Mac : ");
                for (i = 0; i < 5; i++)
                    printf("%02x:", arp_hdr->sha[i]);
                printf("%02x", arp_hdr->sha[i]);
            	printf("\n");

                printf("\t\tSender IP : ");
                for (i = 0; i < 3; i++)
                    printf("%d.", arp_hdr->spa[i]);
                printf("%d", arp_hdr->spa[i]);
            	printf("\n");

                //target
                printf("\t\tTarget Mac : ");
                for (i = 0; i < 5; i++)
                    printf("%02x:", arp_hdr->tha[i]);
                printf("%02x", arp_hdr->tha[i]);
            	printf("\n");

                printf("\t\tTarget IP : ");
                for (i = 0; i < 3; i++)
                    printf("%d.", arp_hdr->tpa[i]);
                printf("%d", arp_hdr->tpa[i]);
            	printf("\n");
            }
            break;

        case MEDIUM:
            printf("ARP");
            switch (op) {
        		case ARPOP_REQUEST:
        			printf(" (Request)\n");
        		break;
        		case ARPOP_REPLY:
        			printf(" (Reply)\n");
        		break;
        		default:
        			printf(" (unknown opcode : %d)\n", op);
        		break;
        	}
            break;

        case LOW:
            printf("Src: ");
            for (i = 0; i < 5; i++)
                printf("%02x:", arp_hdr->sha[i]);
            printf("%02x", arp_hdr->sha[i]);
            printf("\t");

            printf("Dst: ");
            for (i = 0; i < 5; i++)
                printf("%02x:", arp_hdr->tha[i]);
            printf("%02x", arp_hdr->tha[i]);
            printf("\t");

            printf("Protocol: ARP\t");

            if (hard_addr == 1 && hard_pro == 2048) {
                if (op == ARPOP_REQUEST) {
                    printf("Who has ");
                    for (i = 0; i < 3; i++)
                        printf("%d.", arp_hdr->tpa[i]);
                    printf("%d", arp_hdr->tpa[i]);
                    printf("? Tell ");
                    for (i = 0; i < 3; i++)
                        printf("%d.", arp_hdr->spa[i]);
                    printf("%d", arp_hdr->spa[i]);
                }

                else if (op == ARPOP_REPLY) {
                    for (i = 0; i < 3; i++)
                        printf("%d.", arp_hdr->spa[i]);
                    printf("%d", arp_hdr->spa[i]);
                    printf(" is at ");
                    for (i = 0; i < 5; i++)
                        printf("%02x:", arp_hdr->sha[i]);
                    printf("%02x", arp_hdr->sha[i]);
                }
            }
            break;
    }
}
