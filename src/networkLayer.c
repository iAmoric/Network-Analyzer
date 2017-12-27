
/**
 * Created by Lucas Pierrat.
 */

#include "networkLayer.h"


/**
 * @brief this function processes the ip protocol
 * @param packet
 * @param verbosity
 */
void handle_ip(const u_char* packet, int verbosity) {
    struct ip* ip_hdr;
    ip_hdr = (struct ip*)packet;

    int protocol = ip_hdr->ip_p;
    int payload_size =  ntohs(ip_hdr->ip_len) - sizeof(struct ip);

    switch (verbosity) {
        case HIGH:
            fprintf(stdout, "\tIPv4");
            fprintf(stdout, "\n\t\thl: %d | ", ip_hdr->ip_hl);       //header length
            fprintf(stdout, "tos: %d | ", ip_hdr->ip_tos);           //type of service
            fprintf(stdout, "len: %d | ", ntohs(ip_hdr->ip_len));    //total packet length
            fprintf(stdout, "id: %d | ", ntohs(ip_hdr->ip_id));      //id of the packet
            //TODO check it
            fprintf(stdout, "off: %d | ", ip_hdr->ip_off);           //offset
            fprintf(stdout, "ttl: %d | ", ip_hdr->ip_ttl);           //time to live
            fprintf(stdout, "sum: 0x%x\n", ntohs(ip_hdr->ip_sum));   //checksum
            fprintf(stdout, "\t\t@Src: %s\n", inet_ntoa(ip_hdr->ip_src));
            fprintf(stdout, "\t\t@Dest: %s\n", inet_ntoa(ip_hdr->ip_dst));
            break;

        case MEDIUM:
            fprintf(stdout, "IPv4");
            fprintf(stdout, ", Src: %s, ", inet_ntoa(ip_hdr->ip_src));
            fprintf(stdout, "Dst: %s\n", inet_ntoa(ip_hdr->ip_dst));
            break;

        case LOW:
            fprintf(stdout, "Src: %s\t", inet_ntoa(ip_hdr->ip_src));
            fprintf(stdout, "Dst: %s\t", inet_ntoa(ip_hdr->ip_dst));
            break;

        default:
            break;
    }

    //shift
    packet += ip_hdr->ip_hl * 4;

    switch (protocol) {
        case 0x06:      //tcp
            handle_tcp(packet, payload_size, verbosity);
        break;
        case 0x11:      //udp
            handle_udp(packet, payload_size, verbosity);
        break;
        default:
            fprintf(stdout, "\t\tUnsupported protocol : 0x%x\n", protocol);
        break;
    }

}


/**
 * @brief this function processes the arp protocol
 * @param packet
 * @param verbosity
 */
void handle_arp(const u_char* packet, int verbosity) {
	struct arp_hdr* arp_hdr;
	arp_hdr = (struct arp_hdr*) packet;

	int hard_addr = ntohs((uint16_t) arp_hdr->htype);      //hardware address type
	int hard_pro = ntohs((uint16_t) arp_hdr->ptype);       //protocol type
    u_int16_t op = ntohs((uint16_t) arp_hdr->oper);        //opcode
    int i;

    switch (verbosity) {
        case HIGH:
            fprintf(stdout, "\tARP");
            //hardware type
        	fprintf(stdout, "\n\t\tHardware type : ");
        	if (hard_addr == ETHERNET) {
        		fprintf(stdout, "Ethernet ");
        	}
        	else {
        		fprintf(stdout, "Unknown ");
        	}

            //hardware length
        	fprintf(stdout, "(%d) | ", arp_hdr->hlen);

        	//hardware protocol
        	fprintf(stdout, "Hardware protocol : ");
        	if (hard_pro == IPV4) {
        		fprintf(stdout, "IPv4 ");
        	}
        	else {
        		fprintf(stdout, "Unknown ");
        	}

            //protocol length
        	fprintf(stdout, "(%d) | ", arp_hdr->plen);

        	//opcode
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

            //only continue if it is ethernet and ipv4
            if (hard_addr == ETHERNET && hard_pro == IPV4) {
                //sender
            	fprintf(stdout, "\t\tSender Mac : ");
                for (i = 0; i < 5; i++)
                    fprintf(stdout, "%02x:", arp_hdr->sha[i]);
                fprintf(stdout, "%02x", arp_hdr->sha[i]);
            	fprintf(stdout, "\n");

                fprintf(stdout, "\t\tSender IP : ");
                for (i = 0; i < 3; i++)
                    fprintf(stdout, "%d.", arp_hdr->spa[i]);
                fprintf(stdout, "%d", arp_hdr->spa[i]);
            	fprintf(stdout, "\n");

                //target
                fprintf(stdout, "\t\tTarget Mac : ");
                for (i = 0; i < 5; i++)
                    fprintf(stdout, "%02x:", arp_hdr->tha[i]);
                fprintf(stdout, "%02x", arp_hdr->tha[i]);
            	fprintf(stdout, "\n");

                fprintf(stdout, "\t\tTarget IP : ");
                for (i = 0; i < 3; i++)
                    fprintf(stdout, "%d.", arp_hdr->tpa[i]);
                fprintf(stdout, "%d", arp_hdr->tpa[i]);
            	fprintf(stdout, "\n");
            }
            break;

        case MEDIUM:
            fprintf(stdout, "ARP");
            switch (op) {
        		case ARPOP_REQUEST:
        			fprintf(stdout, " (Request)\n");
        		break;
        		case ARPOP_REPLY:
        			fprintf(stdout, " (Reply)\n");
        		break;
        		default:
        			fprintf(stdout, " (unknown opcode : %d)\n", op);
        		break;
        	}
            break;

        case LOW:
            fprintf(stdout, "Src: ");
            for (i = 0; i < 5; i++)
                fprintf(stdout, "%02x:", arp_hdr->sha[i]);
            fprintf(stdout, "%02x", arp_hdr->sha[i]);
            fprintf(stdout, "\t");

            fprintf(stdout, "Dst: ");
            for (i = 0; i < 5; i++)
                fprintf(stdout, "%02x:", arp_hdr->tha[i]);
            fprintf(stdout, "%02x", arp_hdr->tha[i]);
            fprintf(stdout, "\t");

            fprintf(stdout, "Protocol: ARP\t");

            if (hard_addr == 1 && hard_pro == 2048) {
                if (op == ARPOP_REQUEST) {
                    fprintf(stdout, "Who has ");
                    for (i = 0; i < 3; i++)
                        fprintf(stdout, "%d.", arp_hdr->tpa[i]);
                    fprintf(stdout, "%d", arp_hdr->tpa[i]);
                    fprintf(stdout, "? Tell ");
                    for (i = 0; i < 3; i++)
                        fprintf(stdout, "%d.", arp_hdr->spa[i]);
                    fprintf(stdout, "%d", arp_hdr->spa[i]);
                }

                else if (op == ARPOP_REPLY) {
                    for (i = 0; i < 3; i++)
                        fprintf(stdout, "%d.", arp_hdr->spa[i]);
                    fprintf(stdout, "%d", arp_hdr->spa[i]);
                    fprintf(stdout, " is at ");
                    for (i = 0; i < 5; i++)
                        fprintf(stdout, "%02x:", arp_hdr->sha[i]);
                    fprintf(stdout, "%02x", arp_hdr->sha[i]);
                }
            }
            break;

        default:
            break;
    }
}
