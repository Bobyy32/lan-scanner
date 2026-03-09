#ifndef PORT_SCAN_H
#define PORT_SCAN_H

#include <pcap.h>

#include "hashtable.h"

typedef struct PortInfo {
    char* service;
    uint16_t port;
    char* protocol;
} port_info;

void parse_service_info(struct HashTable* ht);

void tcp_port_scan(const uint32_t target_ip);

void tcp_port_rcv_callback(const unsigned char* packet, struct pcap_pkthdr* header, void* data);


#endif