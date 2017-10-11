#include "arp.h"

void handle_arp(const u_char* packet) {
	struct arphdr* arp_hdr;
	arp_hdr = (struct arphdr*) packet;

	int hard_addr = ntohs(arp_hdr->ar_hrd);
	int hard_pro = ntohs(arp_hdr->ar_pro);

	fprintf(stdout, "\tAPR\n");

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
	strncpy(ip_addr, (char*) packet, arp_hdr->ar_pln);
	fprintf(stdout, "Sender IP : \n");
	packet += arp_hdr->ar_pln;


	//target	
	strncpy(mac_addr, (char*) packet, arp_hdr->ar_hln);	
	fprintf(stdout, "\t\tTarget Mac : %s | ", ether_ntoa((const struct ether_addr *) &mac_addr));
	packet += arp_hdr->ar_hln;

	strncpy(ip_addr, (char*) packet, arp_hdr->ar_pln);
	fprintf(stdout, "Target Ip : \n");
	packet += arp_hdr->ar_pln;

}
