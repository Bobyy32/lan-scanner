#ifndef PORT_SCAN_H
#define PORT_SCAN_H

#include "hashtable.h"

typedef struct PortInfo {
    char* service;
    uint16_t port;
    char* protocol;
} port_info;

void parse_service_info(struct HashTable* ht);

void tcp_port_scan(const uint32_t target_ip);


#endif