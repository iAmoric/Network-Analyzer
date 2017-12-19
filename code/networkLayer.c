#include "networkLayer.h"

/**
        IP
*/
void handle_ip(const u_char* packet, enum verbosity verbosity) {
    struct ip* ip_hdr;
    ip_hdr = (struct ip*) (packet);

    int header_length;          //header length
    int type_service;           //type of service
    short total_length;         //total length
    unsigned short identifier;  //identifier
    int fragment_offset;        //fragment offset
    int time_to_live;           //time to live
    int checksum;               //checksum
    char* ip_src;               //ip src
    char* ip_dst;               //ip dst
    int protocol;               //protocol

    if (verbosity == HIGH)
        printf("\tIPv4");
    else if (verbosity == MEDIUM)
        printf("IPv4");

    ip_src = inet_ntoa(ip_hdr->ip_src);
    ip_dst = inet_ntoa(ip_hdr->ip_dst);


    if (verbosity == HIGH){
        header_length = ip_hdr->ip_hl;
        printf("\n\t\thl: %d | ", header_length);

        type_service = ip_hdr->ip_tos;
        printf("tos: %d | ", type_service);

        total_length = ip_hdr->ip_len;
        printf("len: %d | ", ntohs(total_length));

        identifier = ip_hdr->ip_id;
        printf("id: %d | ", ntohs(identifier));

        //TODO check it
        fragment_offset = ip_hdr->ip_off;
        printf("off: %d | ", fragment_offset);

        time_to_live = ip_hdr->ip_ttl;
        printf("ttl: %d | ", time_to_live);

        checksum = ntohs(ip_hdr->ip_sum);
        printf("sum: 0x%x\n", checksum);

        printf("\t\t@Src: %s\n", ip_src);

        printf("\t\t@Dest: %s\n", ip_dst);
    }
    else if (verbosity == MEDIUM) {
        printf(", Src: %s, ", ip_src);
        printf("Dst: %s\n", ip_dst);
    }
    else if (verbosity == LOW) {
        printf("Src: %s\t", ip_src);
        printf("Dst: %s\t", ip_dst);
    }

    protocol = ip_hdr->ip_p;

    packet += header_length*4;
    int payload_size = ntohs(total_length) - sizeof(struct ip);
    switch (protocol) {
        case 0x06:
            handle_tcp(packet, payload_size);
        break;
        case 0x11:
            handle_udp(packet, payload_size);
        break;
        default:
            printf("\t\tUnsupported protocol : 0x%x\n", protocol);
        break;
    }

}


/**
        ARP
*/
void handle_arp(const u_char* packet, enum verbosity verbosity) {
	struct arp_hdr* arp_hdr;
	arp_hdr = (struct arp_hdr*) packet;

	int hard_addr = ntohs(arp_hdr->htype);
	int hard_pro = ntohs(arp_hdr->ptype);
    int i;

    if (verbosity == HIGH)
        printf("\tARP");
    else if (verbosity == MEDIUM)
        printf("ARP");

    //opcode
    u_int16_t op = ntohs(arp_hdr->oper);

    if (verbosity == HIGH) {
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
    }

    else if (verbosity == MEDIUM) {
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
    }

    else if (verbosity == LOW) {
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
    }
}
