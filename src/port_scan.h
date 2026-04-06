#ifndef PORT_SCAN_H
#define PORT_SCAN_H

#include <libnet.h>
#include <pcap.h>

#include "hashtable.h"
#include "device.h"

typedef struct PortInfo {
    char* service;
    uint16_t port;
    char* protocol;
} port_info;

void parse_service_info(struct HashTable* ht); // USE import_ports INSTEAD!!!

void import_ports(const char* filepath, hash_table* ht);

void tcp_port_scan(libnet_t* context, const device_info source_device, const uint8_t* target_mac, const uint32_t target_ip, const uint16_t target_port);

void tcp_port_rcv_callback(const unsigned char* packet, struct pcap_pkthdr* header, void* data);

#endif