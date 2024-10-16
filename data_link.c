#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include "network.h"

//--------------------------------------
//COUCHE LIAISON DONNEES (2) MODELE OSI
//-------------------------------------


// gestion des paquets ethernet
void ethernet_view(const u_char *packet) {
	struct ether_header *ethernet;
	ethernet = (struct ether_header*)(packet);
	int size_ethernet = sizeof(struct ether_header);

	// pointeur sur la fonction de la prochaine couche
	void (*next_layer)(const u_char*) = NULL;

	
	printf("\033[1m");
	printf("\n▭▭▭ Ethernet ▭▭▭\n");
	printf("\033[0m");

	// adresse mac de destination
	printf("Destination: %02x:%02x:%02x:%02x:%02x:%02x\n", 
		ethernet->ether_dhost[0],
		ethernet->ether_dhost[1],
		ethernet->ether_dhost[2],
		ethernet->ether_dhost[3],
		ethernet->ether_dhost[4],
		ethernet->ether_dhost[5]);

	// adresse mac source
	printf("Source: %02x:%02x:%02x:%02x:%02x:%02x\n", 
		ethernet->ether_shost[0],
		ethernet->ether_shost[1],
		ethernet->ether_shost[2],
		ethernet->ether_shost[3],
		ethernet->ether_shost[4],
		ethernet->ether_shost[5]);

	// type de protocole 
	printf("Type: ");
	switch(ntohs(ethernet->ether_type)) {
		case ETHERTYPE_IP:
			printf("IPv4 ");
			next_layer = ip_view; // appelera l'analyseur d'en-têtes ip
			break;
		case ETHERTYPE_IPV6:
			printf("IPv6 ");
			break; // pas encore implémenté...
		case ETHERTYPE_ARP:
			printf("ARP ");
			next_layer = arp_view;
			break;
		default:
			printf("Unknown ");
			break;
	}

	printf("(0x%04x)\n", ntohs(ethernet->ether_type));
	

	if(next_layer != NULL)
		(*next_layer)(packet + size_ethernet); // appel de la fonction pour la couche suivante
}
