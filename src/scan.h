#ifndef SCAN_H
#define SCAN_H

#include "hashtable.h"
#include "device.h"

typedef struct ScanArgs{
    struct DeviceInfo* device;
    struct HashTable* ht;
} scan_args;

void* arp_scan_thread(void* arg);
void* mdns_scan_thread(void* arg);
void* ssdp_scan_thread(void* arg);

void* tcp_scan_thread(void* arg);

void arp_scan(struct DeviceInfo* device, struct HashTable* ht);
void mdns_scan(struct DeviceInfo* device, struct HashTable* ht);
void ssdp_scan(struct DeviceInfo* device, struct HashTable* ht);

void tcp_scan(struct DeviceInfo* device, struct HashTable* ht);
void tcp_rcv(struct DeviceInfo* device, struct HashTable* ht);

#endif