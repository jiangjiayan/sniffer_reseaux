# sniffer_reseaux

## Modifié à partir de la version d'il y a deux ans：
1.Le programme a été écrit sous Linux, cette fois j'ai résout le problème d'incompatibilité Mac dans l'environnement Linux.

2.Fonction pcap_lookupdev obsolète,la fonction pcap_lookupdev est obsolète et vous devez la remplacer par pcap_findalldevs.

## Comment ça fonctionne 

```bash
git clone

```
```bash
make
```

Il va générer un programme sniffer.

```bash
  sudo ./sniffer
```
on va regarder 

```
Interface par défaut sélectionnée : en0
Interface utilisée : en0

^C

0 paquets capturés
```
J'ai proposé quelques exemples dans 'pcap-example'

```bash
  sudo ./sniffer -o ./pacp-exemples/icmp.pcap
```

on va regarder les info dans la paquet comme suivant :
```
Paquet #1 -- Wed 2013-06-19 10:45:56 CEST | longueur 74 octets

▭▭▭ Ethernet ▭▭▭
Destination: 00:50:56:e0:14:49
Source: 00:0c:29:34:0b:de
Type: IPv4 (0x0800)
        ▭▭▭ IPv4 ▭▭▭
        Version: 4
        IHL: 5 (20 bytes)
        ToS: 0x00
        Total length: 60 bytes
        Identification: 0xd743 (55107)
        Flags: none set
        Time to live: 128
        Protocol: ICMP (0x01)
        Checksum: 0x2b73
        Source: 192.168.158.139
        Destination: 174.137.42.77

Paquet #2 -- Wed 2013-06-19 10:45:57 CEST | longueur 74 octets

▭▭▭ Ethernet ▭▭▭
Destination: 00:0c:29:34:0b:de
Source: 00:50:56:e0:14:49
Type: IPv4 (0x0800)
        ▭▭▭ IPv4 ▭▭▭
        Version: 4
        IHL: 5 (20 bytes)
        ToS: 0x00
        Total length: 60 bytes
        Identification: 0x76e1 (30433)
        Flags: none set
        Time to live: 128
        Protocol: ICMP (0x01)
        Checksum: 0x8bd5
        Source: 174.137.42.77
        Destination: 192.168.158.139

Paquet #3 -- Wed 2013-06-19 10:45:57 CEST | longueur 74 octets

▭▭▭ Ethernet ▭▭▭
Destination: 00:50:56:e0:14:49
Source: 00:0c:29:34:0b:de
Type: IPv4 (0x0800)
        ▭▭▭ IPv4 ▭▭▭
        Version: 4
        IHL: 5 (20 bytes)
        ToS: 0x00
        Total length: 60 bytes
        Identification: 0xd746 (55110)
        Flags: none set
        Time to live: 128
        Protocol: ICMP (0x01)
        Checksum: 0x2b70
        Source: 192.168.158.139
        Destination: 174.137.42.77

Paquet #4 -- Wed 2013-06-19 10:45:58 CEST | longueur 74 octets

▭▭▭ Ethernet ▭▭▭
Destination: 00:0c:29:34:0b:de
Source: 00:50:56:e0:14:49
Type: IPv4 (0x0800)
        ▭▭▭ IPv4 ▭▭▭
        Version: 4
        IHL: 5 (20 bytes)
        ToS: 0x00
        Total length: 60 bytes
        Identification: 0x76e4 (30436)
        Flags: none set
        Time to live: 128
        Protocol: ICMP (0x01)
        Checksum: 0x8bd2
        Source: 174.137.42.77
        Destination: 192.168.158.139

Paquet #5 -- Wed 2013-06-19 10:45:58 CEST | longueur 74 octets

▭▭▭ Ethernet ▭▭▭
Destination: 00:50:56:e0:14:49
Source: 00:0c:29:34:0b:de
Type: IPv4 (0x0800)
        ▭▭▭ IPv4 ▭▭▭
        Version: 4
        IHL: 5 (20 bytes)
        ToS: 0x00
        Total length: 60 bytes
        Identification: 0xd749 (55113)
        Flags: none set
        Time to live: 128
        Protocol: ICMP (0x01)
        Checksum: 0x2b6d
        Source: 192.168.158.139
        Destination: 174.137.42.77

Paquet #6 -- Wed 2013-06-19 10:45:59 CEST | longueur 74 octets

▭▭▭ Ethernet ▭▭▭
Destination: 00:0c:29:34:0b:de
Source: 00:50:56:e0:14:49
Type: IPv4 (0x0800)
        ▭▭▭ IPv4 ▭▭▭
        Version: 4
        IHL: 5 (20 bytes)
        ToS: 0x00
        Total length: 60 bytes
        Identification: 0x76f0 (30448)
        Flags: none set
        Time to live: 128
        Protocol: ICMP (0x01)
        Checksum: 0x8bc6
        Source: 174.137.42.77
        Destination: 192.168.158.139

Paquet #7 -- Wed 2013-06-19 10:45:59 CEST | longueur 74 octets

▭▭▭ Ethernet ▭▭▭
Destination: 00:50:56:e0:14:49
Source: 00:0c:29:34:0b:de
Type: IPv4 (0x0800)
        ▭▭▭ IPv4 ▭▭▭
        Version: 4
        IHL: 5 (20 bytes)
        ToS: 0x00
        Total length: 60 bytes
        Identification: 0xd74e (55118)
        Flags: none set
        Time to live: 128
        Protocol: ICMP (0x01)
        Checksum: 0x2b68
        Source: 192.168.158.139
        Destination: 174.137.42.77

Paquet #8 -- Wed 2013-06-19 10:46:00 CEST | longueur 74 octets

▭▭▭ Ethernet ▭▭▭
Destination: 00:0c:29:34:0b:de
Source: 00:50:56:e0:14:49
Type: IPv4 (0x0800)
        ▭▭▭ IPv4 ▭▭▭
        Version: 4
        IHL: 5 (20 bytes)
        ToS: 0x00
        Total length: 60 bytes
        Identification: 0x76f5 (30453)
        Flags: none set
        Time to live: 128
        Protocol: ICMP (0x01)
        Checksum: 0x8bc1
        Source: 174.137.42.77
        Destination: 192.168.158.139



8 paquets capturés

```

On peut ajouter encore les caractéristiques :

```bash
  sudo ./sniffer -o ./pacp-exemples/icmp.pcap -f "tcp and dst port 80"
```
filtrer pour capturer uniquement le trafic HTTP

ou 
```bash
  sudo ./sniffer -i lo
```
Sélectionnez l'interface de bouclage pour la capture

## A besoin d'amélioration

1.Générer une image et la déployer sur Docker.

2.Essayez de le porter sur une interface utilisateur graphique (GUI).

3.Prise en charge de plus de protocoles.

