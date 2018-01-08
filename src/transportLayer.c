
/**
 * Created by Lucas Pierrat.
 */

#include "transportLayer.h"


/**
 * @brief this function processes the tcp protocol
 * @param packet
 * @param payload_size
 * @param verbosity
 */
void handle_tcp(const u_char* packet, int payload_size, int verbosity) {
	struct tcphdr* tcp_hdr;
	tcp_hdr = (struct tcphdr*) (packet);

	u_char flag;

	int data_offset = tcp_hdr->th_off * 4;
	payload_size = payload_size - data_offset;

	switch (verbosity) {

		case HIGH:
			fprintf(stdout, "\t\tTCP\n");
			fprintf(stdout, "\t\t\tSrc port: %d\n", ntohs((uint16_t) tcp_hdr->th_sport));
			fprintf(stdout, "\t\t\tDst port: %d\n", ntohs((uint16_t) tcp_hdr->th_dport));
			fprintf(stdout, "\t\t\tSeq: %d | ", ntohs((uint16_t) tcp_hdr->th_seq));
			fprintf(stdout, "Ack: %d | ", ntohs((uint16_t) tcp_hdr->th_ack));
			fprintf(stdout, "Header length: %d | ", tcp_hdr->th_off * 4);

			//get tcp flags
			flag = (u_char) tcp_hdr->th_flags;
			fprintf(stdout, "Flags: ");
			if (flag & TH_FIN)
				fprintf(stdout, "FIN ");
			if (flag & TH_SYN)
				fprintf(stdout, "SYN ");
			if (flag & TH_RST)
				fprintf(stdout, "RST ");
			if (flag & TH_PUSH)
				fprintf(stdout, "PUSH ");
			if (flag & TH_ACK)
				fprintf(stdout, "ACK ");
			if (flag & TH_URG)
				fprintf(stdout, "URG");
			fprintf(stdout, "| ");

			fprintf(stdout, "Window size: %d | ", ntohs((uint16_t) tcp_hdr->th_win));
			fprintf(stdout, "Urgent pointer: %d\n", tcp_hdr->th_urp);

			//options
			fprintf(stdout, "\t\t\tOptions: ");
			const u_char* end = packet + data_offset; 	// end of the options
			packet += sizeof(struct tcphdr);			// shift the start (normally 20 bytes)

			//get all the tcp options
			while(packet < end) {
				int type = *packet++; 					// type of the option
				int length = 0;							// size of the options

				//size is null for options 0 & 1
				if(type != 0 && type != 1)
					length = *packet++;

				fprintf(stdout, "%d - ", type);
				switch(type) {
					case 0:
						fprintf(stdout, "End of options");
						break;
					case 1:
						fprintf(stdout, "No operation");
						break;
					case 2:
						fprintf(stdout, "MSS ");
						break;
					case 3:
						fprintf(stdout, "Window scale ");
						break;
					case 4:
						fprintf(stdout, "SACK permited ");
						break;
					case 5:
						fprintf(stdout, "SACK ");
						break;
					case 8:
						fprintf(stdout, "Timestamps ");
						break;
					default:
						fprintf(stdout, "Unknown ");
						break;
				}

				// shift the size of the option
				if(type != 0 && type != 1)
					for (int i = 0; i < length - 2; i++)
						fprintf(stdout, " 0x%02x", *packet++);

				fprintf(stdout, " | " );
			}
			fprintf(stdout, "\n");
			break;

		case MEDIUM:
			fprintf(stdout, "TCP, ");
			fprintf(stdout, "Src port: %d, ", ntohs((uint16_t) tcp_hdr->th_sport));
			fprintf(stdout, "Dst port: %d, ", ntohs((uint16_t) tcp_hdr->th_dport));
			fprintf(stdout, "Seq: %d, ", ntohs((uint16_t) tcp_hdr->th_seq));
			fprintf(stdout, "Ack: %d, ", ntohs((uint16_t) tcp_hdr->th_ack));
			fprintf(stdout, "Len: %d\n", payload_size);
			packet += data_offset;
			break;

		case LOW:
			fprintf(stdout, "TCP");
			if (ntohs((uint16_t) tcp_hdr->th_sport) == HTTP || ntohs((uint16_t) tcp_hdr->th_dport) == HTTP)
				fprintf(stdout, "/HTTP\t");
			else if (ntohs((uint16_t) tcp_hdr->th_sport) == HTTPS || ntohs((uint16_t) tcp_hdr->th_dport) == HTTPS)
				fprintf(stdout, "/HTTPS\t");
			else if (ntohs((uint16_t) tcp_hdr->th_sport) == TELNET || ntohs((uint16_t) tcp_hdr->th_dport) == TELNET)
				fprintf(stdout, "/TELNET\t");
			else if (ntohs((uint16_t) tcp_hdr->th_sport) == SMTPS || ntohs((uint16_t) tcp_hdr->th_dport) == SMTPS)
				fprintf(stdout, "/SMTPS\t");
			else if (ntohs((uint16_t) tcp_hdr->th_sport) == SMTP || ntohs((uint16_t) tcp_hdr->th_dport) == SMTP)
				fprintf(stdout, "/SMTP\t");
			else if (ntohs((uint16_t) tcp_hdr->th_sport) == FTP_DATA || ntohs((uint16_t) tcp_hdr->th_dport) == FTP_DATA)
				fprintf(stdout, "/FTP Dat \t");
			else if (ntohs((uint16_t) tcp_hdr->th_sport) == FTP_REQUEST || ntohs((uint16_t) tcp_hdr->th_dport) == FTP_REQUEST)
				fprintf(stdout, "/FTP Req \t");
			else if (ntohs((uint16_t) tcp_hdr->th_sport) == POP3 || ntohs((uint16_t) tcp_hdr->th_dport) == POP3)
				fprintf(stdout, "/POP3\t");
			else if (ntohs((uint16_t) tcp_hdr->th_sport) == IMAP || ntohs((uint16_t) tcp_hdr->th_dport) == 143)
				fprintf(stdout, "/IMAP\t");

			//do not print the rest if HTTP/Telnet/FTP(request) and if there is data
			//it was easier to do 3 if than only one by combining conditions
			if ((ntohs((uint16_t) tcp_hdr->th_sport) == HTTP || ntohs((uint16_t) tcp_hdr->th_dport) == HTTP) && payload_size != 0) {
				packet += data_offset;
				break;
			}
			if ((ntohs((uint16_t) tcp_hdr->th_sport) == TELNET || ntohs((uint16_t) tcp_hdr->th_dport) == TELNET) && payload_size != 0) {
				packet += data_offset;
				break;
			}
			if ((ntohs((uint16_t) tcp_hdr->th_sport) == FTP_REQUEST || ntohs((uint16_t) tcp_hdr->th_dport) == FTP_REQUEST) && payload_size != 0) {
				packet += data_offset;
				break;
			}

			//source port -> destination port
			fprintf(stdout, " \t%d -> %d ", ntohs((uint16_t) tcp_hdr->th_sport), ntohs((uint16_t) tcp_hdr->th_dport));

			//flags
			fprintf(stdout, "[ ");
			flag = (u_char) tcp_hdr->th_flags;
			if (flag & TH_FIN)
				fprintf(stdout, "FIN ");
			if (flag & TH_SYN)
				fprintf(stdout, "SYN ");
			if (flag & TH_RST)
				fprintf(stdout, "RST ");
			if (flag & TH_PUSH)
				fprintf(stdout, "PUSH ");
			if (flag & TH_ACK)
				fprintf(stdout, "ACK ");
			if (flag & TH_URG)
				fprintf(stdout, "URG");
			fprintf(stdout, "] ");

			fprintf(stdout, "Seq=%d ", ntohs((uint16_t) tcp_hdr->th_seq));
			fprintf(stdout, "Ack=%d ", ntohs((uint16_t) tcp_hdr->th_ack));
			fprintf(stdout, "Len=%d ", payload_size);
			fprintf(stdout, "Win=%d", ntohs((uint16_t) tcp_hdr->th_win));
			packet += data_offset;
			break;

		default:
			break;
	}

	//go to the appropriates function for the protocol
	if (ntohs((uint16_t) tcp_hdr->th_sport) == HTTP || ntohs((uint16_t) tcp_hdr->th_dport) == HTTP)
		handle_http(packet, payload_size, 0, verbosity);

	else if (ntohs((uint16_t) tcp_hdr->th_sport) == HTTPS || ntohs((uint16_t) tcp_hdr->th_dport) == HTTPS)
		handle_http(packet, payload_size, 1, verbosity);

	else if (ntohs((uint16_t) tcp_hdr->th_sport) == TELNET || ntohs((uint16_t) tcp_hdr->th_dport) == TELNET)
		handle_telnet(packet, payload_size, verbosity);

	else if (ntohs((uint16_t) tcp_hdr->th_sport) == SMTPS || ntohs((uint16_t) tcp_hdr->th_dport) == SMTPS)
		handle_smtp(packet, payload_size, 1, verbosity);

	else if (ntohs((uint16_t) tcp_hdr->th_sport) == SMTP || ntohs((uint16_t) tcp_hdr->th_dport) == SMTP)
		handle_smtp(packet, payload_size, 0, verbosity);

	else if (ntohs((uint16_t) tcp_hdr->th_sport) == FTP_DATA || ntohs((uint16_t) tcp_hdr->th_dport) == FTP_DATA)
		handle_ftp(packet, payload_size, 0, ntohs((uint16_t) tcp_hdr->th_sport), verbosity);

	else if (ntohs((uint16_t) tcp_hdr->th_sport) == FTP_REQUEST || ntohs((uint16_t) tcp_hdr->th_dport) == FTP_REQUEST)
		handle_ftp(packet, payload_size, 1, ntohs((uint16_t) tcp_hdr->th_sport), verbosity);

	else if (ntohs((uint16_t) tcp_hdr->th_sport) == POP3 || ntohs((uint16_t) tcp_hdr->th_dport) == POP3)
		handle_pop(packet, payload_size, verbosity);

	else if (ntohs((uint16_t) tcp_hdr->th_sport) == IMAP || ntohs((uint16_t) tcp_hdr->th_dport) == IMAP)
		handle_imap(packet, payload_size, verbosity);

}


/**
 * @brief this function processes the udp protocol
 * @param packet
 * @param payload_size
 * @param verbosity
 */
void handle_udp(const u_char* packet, int payload_size, int verbosity) {

	struct udphdr *udp_hdr = (struct udphdr*) packet;

	switch (verbosity) {
		case HIGH:
			fprintf(stdout, "\t\tUDP\n" );
			fprintf(stdout, "\t\t\tSrc port: %d\n", ntohs((uint16_t) udp_hdr->uh_sport));
			fprintf(stdout, "\t\t\tDest port: %d\n", ntohs((uint16_t) udp_hdr->uh_dport));
			fprintf(stdout, "\t\t\tlen: %d | ", ntohs((uint16_t) udp_hdr->uh_ulen));
			fprintf(stdout, "sum: 0x%x\n", ntohs((uint16_t) udp_hdr->uh_sum));
			break;

		case MEDIUM:
			fprintf(stdout, "UDP, ");
			fprintf(stdout, "Src Port: %d, ", ntohs((uint16_t) udp_hdr->uh_sport));
			fprintf(stdout, "Dst Port: %d\n", ntohs((uint16_t) udp_hdr->uh_dport));
			break;

		case LOW:
			break;

		default:
			break;
	}

	//shift
	packet += sizeof(struct udphdr);

	if(ntohs((uint16_t) udp_hdr->uh_sport) == DNS || ntohs((uint16_t) udp_hdr->uh_dport) == DNS) {
        handle_dns(packet, verbosity);
    }
	if(ntohs((uint16_t) udp_hdr->uh_sport) == BOOTPC || ntohs((uint16_t) udp_hdr->uh_dport) == BOOTPC ||
	   ntohs((uint16_t) udp_hdr->uh_sport) == BOOTPS || ntohs((uint16_t) udp_hdr->uh_dport) == BOOTPS) {
        handle_bootp(packet, verbosity);
    }

}
