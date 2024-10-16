#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "network.h"
#include "transport.h"

//----------------------------
//COUCHE RESEAU (3) MODELE OSI
//----------------------------


// gère les paquets IPv4
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|Version|  IHL  |Type of Service|
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|          Total Length         |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|         Identification        |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|Flags|     Fragment Offset     |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|  Time to Live |    Protocol   |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        Header Checksum        |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|                               |
//+         Source Address        +
//|                               |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|                               |
//+      Destination Address      +
//|                               |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|            Options            |
//+               +-+-+-+-+-+-+-+-+
//|               |    Padding    |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

void ip_view(const u_char *packet) {
	struct ip *ip = (struct ip*)(packet);
	int i, j, ip_size = 4*ip->ip_hl;

	void (*next_udp)(const u_char*) = NULL;
	void (*next_tcp)(const u_char*, int) = NULL;

	printf("\033[1m");
	printf("\t▭▭▭ IPv4 ▭▭▭\n");
	printf("\033[0m");

	// ip version (première case)
	printf("\tVersion: %d\n", ip->ip_v);
	// ihl (2ème case, etc)
	printf("\tIHL: %d (%d bytes)\n", ip->ip_hl, ip->ip_hl*4);
	printf("\tToS: 0x%02x\n", ip->ip_tos); // TOS
	// longueur total
	printf("\tTotal length: %d bytes\n", ntohs(ip->ip_len));
	printf("\tIdentification: 0x%04x (%d)\n", ntohs(ip->ip_id), ntohs(ip->ip_id)); // id 
	// flags
	printf("\tFlags: ");
	if(ntohs(ip->ip_off) & IP_RF) 
		printf("reserved bit\n");
	else if(ntohs(ip->ip_off) & IP_DF)
		printf("don't fragment\n");
	else if(ntohs(ip->ip_off) & IP_MF)
		printf("more fragment (fragment offset: %d)\n", (ntohs(ip->ip_off) & IP_OFFMASK)*8);
	else
		printf("none set\n");

	printf("\tTime to live: %d\n", ip->ip_ttl); // TTL

	// protocole de la prochaine couche
	printf("\tProtocol: ");
	switch(ip->ip_p) {
		case 0x01:
			printf("ICMP ");
			break;
		case SOL_UDP:
			printf("UDP ");
			next_udp = udp_view;
			break;
		case SOL_TCP:
			printf("TCP ");
			next_tcp = tcp_view;
			break;
		default:
			printf("Unknown ");
			break;
	} 
	printf("(0x%02x)\n", ip->ip_p);
	printf("\tChecksum: 0x%04x\n", ntohs(ip->ip_sum)); // checksum

	printf("\tSource: %s\n", inet_ntoa(ip->ip_src)); // adresse IP source
	printf("\tDestination: %s\n", inet_ntoa(ip->ip_dst)); // adresse IP destination
	
	if(ip->ip_hl > 5) {
		printf("\tOptions:\n"); //options de la forme : type, longueur, valeur
		for(i = sizeof(struct ip); i < ip_size && packet[i] != 0x00; i++) {
			switch(packet[i]) {
				default:
					printf("\t  Type: %d\n", packet[i]);
					printf("\t  Length %d\n", packet[i+1]);
					printf("\t  Value 0x");
					for(j=2; j<(int)packet[i+1];j++) {
						printf("%02x", packet[i+j+1]);
					}
					printf("\n");
					i+=(int)packet[i+1];
					break;
			}		
		}
	}
	

	if(next_udp != NULL)
		(*next_udp)(packet + ip_size); // appel de la couche udp
	else if(next_tcp != NULL)
		(*next_tcp)(packet + ip_size, ntohs(ip->ip_len) - ip_size); // appel de la couche tcp
}


// gère les paquets ARP
//pas de header sous la main désolé
void arp_view(const u_char *packet) {
	struct arphdr *arp = (struct arphdr*)(packet);
	int arp_size = sizeof(struct arphdr);

	printf("\033[1m");
	printf("\t▭▭▭ ARP ▭▭▭\n");
	printf("\033[0m");

	// hardware type
	printf("\tHardware type: ");
	switch(ntohs(arp->ar_hrd)) {
		case ARPHRD_ETHER:
			printf("Ethernet 10/100Mbps");
			break;
		default:
			printf("Unknown");
			break;
	}

	printf(" (0x%04x)\n", ntohs(arp->ar_hrd));


	// protocole 
	printf("\tProtocol type: ");
	switch(ntohs(arp->ar_pro)) {
		case ETHERTYPE_IP:
			printf("IPv4");
			break;
		case ETHERTYPE_IPV6:
			printf("IPv6");
			break;
		default:
			printf("Unknown");
			break;
	}
	
	printf(" (0x%04x)\n", ntohs(arp->ar_pro));
	printf("\tHardware address length: %d bytes\n", arp->ar_hln);
	printf("\tProtocol address length: %d bytes\n", arp->ar_pln);
	
	printf("\tOperation : ");
	switch(ntohs(arp->ar_op)) {
		case ARPOP_REQUEST:
			printf("ARP Request\n");
			break;
		case ARPOP_REPLY:
			printf("ARP Reply\n");
			break;
		case ARPOP_RREQUEST:
			printf("RARP Request\n");
			break;
		case ARPOP_RREPLY:
			printf("RARP Reply\n");
			break;
		case ARPOP_InREQUEST:
			printf("InARP Request\n");
			break;
		case ARPOP_InREPLY:
			printf("InARP Reply\n");
			break;
		case ARPOP_NAK:
			printf("ARP NAK\n");
			break;
		default:
			printf("Unknown\n");
			break;
		

		struct arpaddr *arpaddr = (struct arpaddr*)(packet + arp_size);

		printf("\tSender hardware address: %02x:%02x:%02x:%02x:%02x:%02x\n", 
			arpaddr->ar_sha[0],
			arpaddr->ar_sha[1],		
			arpaddr->ar_sha[2],
			arpaddr->ar_sha[3],
			arpaddr->ar_sha[4],
			arpaddr->ar_sha[5]
		);
		printf("\tSender protocol address: %d.%d.%d.%d\n", 
			arpaddr->ar_spa[0],
			arpaddr->ar_spa[1],
			arpaddr->ar_spa[2],
			arpaddr->ar_spa[3]
		);
		printf("\tTarget hardware address: %02x:%02x:%02x:%02x:%02x:%02x\n", 
			arpaddr->ar_tha[0],
			arpaddr->ar_tha[1],		
			arpaddr->ar_tha[2],
			arpaddr->ar_tha[3],
			arpaddr->ar_tha[4],
			arpaddr->ar_tha[5]
		);
		printf("\tSender protocol address: %d.%d.%d.%d\n", 
			arpaddr->ar_tpa[0],
			arpaddr->ar_tpa[1],
			arpaddr->ar_tpa[2],
			arpaddr->ar_tpa[3]
		);
	}

}
