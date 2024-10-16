#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include "data_link.h"

int numero;
pcap_t *handle;


// gère le signal d'arrêt du programme (CTRL + C)
static void signal_handler(int signo) {
    pcap_breakloop(handle); // on arrête tout, car demandé
}

// gère les paquets reçus
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	
	struct tm *ts;
	char buf[80];
	numero++; // compte le nombre de paquets capturés
	ts = localtime(&(header->ts.tv_sec));
	strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S %Z", ts); //affiche l'heure de réception
	//affiche le numéro du paquet, et sa taille
	printf("Paquet #%d -- %s | longueur %d octets\n", numero, buf, header->len);

	ethernet_view(packet); //on lit la trame ethernet au début
	printf("\n");
}

// affichage de l'aide si besoin
void usage() {
	printf("Utilisation : ./sniffer\n\t[-i <interface>\n\t-o <fichier>\n\t-f <filtre BPF>]\n");
}

// fonction principale du programme
int main(int argc, char *argv[]) {

	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	numero = 0;
	char *fichier = NULL, *filtre = NULL, *interface = NULL;

	// Enregistre le signal pour pouvoir le gérer ensuite
    if (signal(SIGINT, signal_handler) == SIG_ERR) {
        printf("An error occurred while setting a signal handler.\n");
        return -1;
    }

    // gère les arguments de ligne de commande fournis
	char c;
	while((c = getopt(argc, argv, "i:o:f:h")) != -1) {
		switch(c) {
			case 'i': // interface
				interface = optarg;
				break;
			case 'o': // fichier 'o'ffline
				fichier = optarg;
				break;
			case 'f': // filtre pcap
				filtre = optarg;
				break;
			case 'h': // help
				usage();
				return -1;
		}
	}

	// choisit automatiquement l'interface par défaut si non spécifiée
	if(interface == NULL) {
		interface = pcap_lookupdev(errbuf);
		if (interface == NULL) {
			fprintf(stderr, "Impossible de trouver l'interface par défaut: %s\n", errbuf);
			return -1;
		}
	}

	// récupère le masque réseau
	if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Impossible de récupérer le masque réseau: %s: %s\n", interface, errbuf);
		net = 0;
		mask = 0;
	}

	if(fichier == NULL) {
		// ouverture de la session en temps réel
		handle = pcap_open_live(interface, BUFSIZ, 1, 0, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Impossible de démarrer la capture: %s: %s\n", interface, errbuf);
			return -1;
		}
		// compilation et application du filtre si il y en a
		if(filtre != NULL) {
			if (pcap_compile(handle, &fp, filtre, 0, net) == -1) {
				fprintf(stderr, "Impossible de compiler le filtre donné (%s): %s\n", filtre, pcap_geterr(handle));
				return -1;
			}
			if (pcap_setfilter(handle, &fp) == -1) {
				fprintf(stderr, "Impossible d'installer le filtre (%s): %s\n", filtre, pcap_geterr(handle));
				return -1;
			}
		}
	}
	else { // si on a donné un fichier pcap à la place :
		handle = pcap_open_offline(fichier, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Impossible d'ouvrir le fichier %s: %s\n", fichier, errbuf);
			return -1;
		}
	}

	printf("Interface utilisée : %s\n\n", interface);
	int verbose = 4; //niveau de verbosité, ici 4 = MAX

	// boucle sur les paquets reçu/analysés
	pcap_loop(handle, -1, packet_handler, (u_char*)&verbose);

	//Si l'on a terminé le programem (CTRL+C), on arrive ici (fin du code)
	printf("\n\n%d paquets capturés\n", numero);
	// fermeture propre de la session
	pcap_close(handle);
	return 0;
}
