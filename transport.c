#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "application.h"

//--------------------------------------
//COUCHE TRANSPORT (4) MODELE OSI
//-------------------------------------


// gestion des paquets udp
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//-----------------------------------------------------------------
//|          Source Port          |        Destination Port       |
//-----------------------------------------------------------------
//|             Length            |            Checksum           |
//-----------------------------------------------------------------

void udp_view(const u_char *packet) {

	struct udphdr* udp = (struct udphdr*)(packet);
	int udp_size = sizeof(struct udphdr);

	void (*next_layer)(const u_char*, int) = NULL;

	printf("\033[1m");
	printf("\t\t▭▭▭ UDP ▭▭▭\n");
	printf("\033[0m");
	printf("\t\tSource port: %d\n", ntohs(udp->uh_sport)); //1ere case, le port source
	
	switch(ntohs(udp->uh_sport)) {
		case 53: // si le port source est 53, c'est du DNS
			next_layer = dns_view; // on appellera l'analyseur concerné
			break;
		case 67: // si c'est 67, c'est bootp
			next_layer = bootp_view;
			break;
		case 68: // et 68 aussi !
			next_layer = bootp_view;
			break;
	}
	
	printf("\t\tDestination port: %d\n", ntohs(udp->uh_dport)); //2ème case, le port de destination
	if(next_layer == NULL) {
		switch(ntohs(udp->uh_dport)) {
			case 53: //même chose qu'avant
				next_layer = dns_view;
				break;
			case 67:
				next_layer = bootp_view;
				break;
			case 68:
				next_layer = bootp_view;
				break;
		}
	}

	//affiche les infos de l'en-tête restantes
	printf("\t\tLength: %d\n", ntohs(udp->uh_ulen));
	printf("\t\tChecksum: 0x%04x\n", ntohs(udp->uh_sum));

	if(next_layer != NULL && (int)(ntohs(udp->uh_ulen) - udp_size) > 0)
		(*next_layer)(packet + udp_size, (int)(ntohs(udp->uh_ulen) - udp_size)); // appel de la couche supérieure (ex: DNS)
}


// gestion des paquets tcp

// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|          Source Port          |        Destination Port       |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|                        Sequence Number                        |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|                     Acknowledgment Number                     |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//| Offset|  Res. |     Flags     |             Window            |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|            Checksum           |         Urgent Pointer        |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|                    Options                    |    Padding    |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

void tcp_view(const u_char *packet, int tcp_size) {

	struct tcphdr* tcp = (struct tcphdr*)(packet);
	int i, j, tmp, tcphdr_size = tcp->th_off*4;

	void (*next_layer)(const u_char*, int) = NULL;

	printf("\033[1m");
	printf("\t\t▭▭▭ TCP ▭▭▭\n");
	printf("\033[0m");
	printf("\t\tSource port: %d\n", ntohs(tcp->th_sport)); // port source (première case)
	
	switch(ntohs(tcp->th_sport)) {
		case 80: // port source 80 ? donc http !
			next_layer = http_view;
			break;
		case 23: // port source 23 ? donc telnet !
			next_layer = telnet_view;
			break;
		case 25: // etc :-)
			next_layer = smtp_view;
			break;
		case 110:
			next_layer = pop_view;
			break;
		case 143:
			next_layer = imap_view;
			break;
		case 20:
			next_layer = ftp_view;
			break;
		case 21:
			next_layer = ftp_view;
			break;
	}
	
	printf("\t\tDestination port: %d\n", ntohs(tcp->th_dport)); // port destination (2ème case)
	if(next_layer == NULL) {
		switch(ntohs(tcp->th_dport)) {
			case 80: // même chose qu'avant, on appelle l'analyseur concerné
				next_layer = http_view;
				break;
			case 23:
				next_layer = telnet_view;
				break;
			case 25:
				next_layer = smtp_view;
				break;
			case 110:
				next_layer = pop_view;
				break;
			case 143:
				next_layer = imap_view;
				break;
			case 20:
				next_layer = ftp_view;
				break;
			case 21:
				next_layer = ftp_view;
				break;
		}		
	}
	//affiche les infos suivantes de l'en-tête TCP
	printf("\t\tSequence number: %d (0x%04x)\n", ntohl(tcp->th_seq), ntohl(tcp->th_seq));
	printf("\t\tAcknowledgment number: %d\n", ntohl(tcp->th_ack));
	printf("\t\tHeader length: %d bytes\n", tcphdr_size);
	printf("\t\tFlags: 0x%02x\n", tcp->th_flags);
	
	// détails additionnels sur les flags
	if(TH_FIN & tcp->th_flags)
		printf("\t\t - FIN\n");
	if(TH_SYN & tcp->th_flags)
		printf("\t\t - SYN\n");
	if(TH_RST & tcp->th_flags)
		printf("\t\t - RST\n");
	if(TH_PUSH & tcp->th_flags)
		printf("\t\t - PSH\n");
	if(TH_ACK & tcp->th_flags)
		printf("\t\t - ACK\n");
	if(TH_URG & tcp->th_flags)
		printf("\t\t - URG\n");
	
	// affiche le reste de l'en-tête
	printf("\t\tWindow: %d\n", ntohs(tcp->th_win));
	printf("\t\tChecksum: 0x%04x\n", ntohs(tcp->th_sum));
	printf("\t\tUrgent pointer: %d\n",ntohs(tcp->th_urp));
	
	// il nous reste à observer les éventuelles options
	// 1 octet pour le type de l'option, 1 octets pour sa longueur et 2 pour sa valeur
	// source est + d'infos sur https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml

	if(tcp_size > sizeof(struct tcphdr)) {
	
		printf("\t\tOptions:\n");
		for(i=sizeof(struct tcphdr); i<tcphdr_size && packet[i] != 0x00; i++) {
			switch(packet[i]) {
				case 1: // le numéro donne le type de l'option (voir lien ci-dessus)
					printf("\t\t - NOP\n"); // pas d'options...
					break;
				case 2:
					printf("\t\t - Type: maximum segment size (%d)\n", packet[i]); //1er octet (type)
					printf("\t\t   Length: %d\n", packet[i+1]); //2ème octet (longueur)
					tmp = packet[i+2]<<8 | packet[i+3]; //3ème et 4ème octets (valeur)
					printf("\t\t   MSS value: %d\n", tmp);
					i += (int)packet[i+1]-1;
					break;
				case 3:
					printf("\t\t - Type: windows scale (%d)\n", packet[i]);
					printf("\t\t   Length: %d\n", packet[i+1]);
					printf("\t\t   windows scale value: %d\n", packet[i+2]);
					i += (int)packet[i+1]-1;
					break;
				case 4:
					printf("\t\t - Type: SACK permited\n");
					printf("\t\t   Length: %d\n", packet[i+1]);
					i += (int)packet[i+1]-1;
					break;
				case 8:
					printf("\t\t - Type: timestamps(%d)\n", packet[i]);
					printf("\t\t   Length: %d\n", packet[i+1]);
					tmp = packet[i+2] << 24 | packet[i+3] << 16 | packet[i+4] << 8 | packet[i+5];
					printf("\t\t   timestamps value: %d\n", tmp);
					tmp = packet[i+6] << 24 | packet[i+7] << 16 | packet[i+8] << 8 | packet[i+9];
					printf("\t\t   timestamps echo reply: %d\n", tmp);
					i += (int)packet[i+1]-1;	
					break;
				default:
					printf("\t\t - Type: unknown (%d)\n", packet[i]);
					printf("\t\t   Length %d\n", packet[i+1]);
					if((int)packet[i+1]>2) {
						printf("\t\t   Value 0x");
						for(j=2; j<(int)packet[i+1]; j++) {
							printf("%02x", packet[j+i]);
						}
						printf("\n");
					}
					i += (int)packet[i+1]-1;
					break;
			}
		}
		
	}

	if(next_layer != NULL && (tcp_size - tcphdr_size) > 0)
		(*next_layer)(packet + tcphdr_size, tcp_size - tcphdr_size); // appel de la couche supérieure (ex: HTTP)

}
