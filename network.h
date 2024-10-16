#ifndef __NETWORK_H
#define __NETWORK_H
#define IP_ALEN 4


struct arpaddr {
	unsigned char ar_sha[ETH_ALEN];
	unsigned char ar_spa[IP_ALEN];
	unsigned char ar_tha[ETH_ALEN];
	unsigned char ar_tpa[IP_ALEN];
};

// affiche (dump) le contenu d'un paquet IP
void ip_view(const u_char*);

//affiche (dump) le contenu d'un paquet ARP
void arp_view(const u_char*);

//autre fonctions définissables pour d'autres protocoles si besoin (couche réseau ici)
#endif
