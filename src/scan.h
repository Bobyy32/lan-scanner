#ifndef SCAN_H
#define SCAN_H

#include "hashtable.h"
#include "device.h"

typedef struct ScanArgs{
    struct DeviceInfo* device;
    struct HashTable* ht;
} scan_args;

typedef struct Thread_Scan_Args
{
    device_info source_device;
    uint8_t* target_mac;
    uint32_t target_ip;
    uint16_t target_port;
} thread_scan_args;

void* arp_scan_thread(void* arg);
void* mdns_scan_thread(void* arg);
void* ssdp_scan_thread(void* arg);

void* tcp_rcv_thread(void* arg);

void arp_scan(struct DeviceInfo* device, struct HashTable* ht);
void mdns_scan(struct DeviceInfo* device, struct HashTable* ht);
void ssdp_scan(struct DeviceInfo* device, struct HashTable* ht);

void tcp_scan(struct DeviceInfo *device, struct HashTable *ht, struct HashTable* ht_ports);
void tcp_rcv(struct DeviceInfo* device, struct HashTable* ht);

#endif