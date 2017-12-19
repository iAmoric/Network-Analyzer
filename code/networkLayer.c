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
	struct arphdr* arp_hdr;
	arp_hdr = (struct arphdr*) packet;

	int hard_addr = ntohs(arp_hdr->ar_hrd);
	int hard_pro = ntohs(arp_hdr->ar_pro);

	fprintf(stdout, "\tARP\n");

	//hardware type
	fprintf(stdout, "\t\tHardware type : ");
	if (hard_addr == ARPHRD_ETHER) {
		fprintf(stdout, "Ethernet ");
	}
	else {
		fprintf(stdout, "%d ", hard_addr);
	}
	fprintf(stdout, "(%d) | ", arp_hdr->ar_hln);

	//hardware protocol
	fprintf(stdout, "Hardware protocol : ");
	if (hard_pro == 2048) {
		fprintf(stdout, "IPv4 ");
	}
	else {
		fprintf(stdout, "0x%x ", hard_pro);
	}
	fprintf(stdout, "(%d) | ", arp_hdr->ar_pln);

	//opcode
	int op = ntohs(arp_hdr->ar_op);
	switch (op) {
		case ARPOP_REQUEST:
			fprintf(stdout, "Request\n");
		break;
		case ARPOP_REPLY:
			fprintf(stdout, "Reply\n");
		break;
		default:
			fprintf(stdout, "unknown opcode : %d\n", op);
		break;
	}

	packet += sizeof(struct arphdr);
	char mac_addr[arp_hdr->ar_hln];
	char ip_addr[arp_hdr->ar_pln];

	//sender
	strncpy(mac_addr, (char*) packet, arp_hdr->ar_hln);
	fprintf(stdout, "\t\tSender Mac : %s | ", ether_ntoa((const struct ether_addr *) &mac_addr));
	packet += arp_hdr->ar_hln;

	//TODO
	//ip_addr = get_ip(packet);
	//strncpy(ip_addr, (char*) packet, arp_hdr->ar_pln);
	fprintf(stdout, "Sender IP : \n");
	packet += arp_hdr->ar_pln;


	//target
	strncpy(mac_addr, (char*) packet, arp_hdr->ar_hln);
	fprintf(stdout, "\t\tTarget Mac : %s | ", ether_ntoa((const struct ether_addr *) &mac_addr));
	packet += arp_hdr->ar_hln;

	//strncpy(ip_addr, (char*) packet, arp_hdr->ar_pln);
	fprintf(stdout, "Target Ip : \n");
	packet += arp_hdr->ar_pln;
}
