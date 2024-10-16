#ifndef __TRANSPORT_H
#define __TRANSPORT_H

// affiche (dump) le contenu d'un paquet UDP
void udp_view(const u_char*);

//affiche (dump) le contneu d'un paquet TCP
void tcp_view(const u_char*, int);

#endif
