#ifndef DEVICE_H
#define DEVICE_H

#include <stdint.h>
#include <stdbool.h>
#include <net/if.h>

typedef struct Capture_Hash_Table
{
    struct HashTable* ht;
    struct HashTable* srv_table;
}   capture_ht;

typedef struct MdnsService
{
    char* instance_name;    // Bobyy's Mac mini._smb._tcp.local
    char* service_type;     // _smb._tcp.local
    char* host_name;        // shahs-mac-mini.local
    uint16_t port;
} mdns_service;

typedef struct DeviceInfo
{
    char name[IF_NAMESIZE]; // Name of network interface
    uint32_t ipv4_address;  // Addresses stored in network byte order
    uint32_t subnet_mask;
    uint32_t network_id;
    uint32_t broadcast_address;
    uint8_t mac_address[6];

} device_info;

typedef struct DeviceEntry
{
    char mac[18];       // MAC address
    uint8_t mac_bytes[6];
    char* ssdp_server;  // server header from ssdp
    char* ssdp_location; // location header from ssdp
    mdns_service* services;
    uint8_t service_count;
    uint16_t* open_ports;
    uint16_t open_port_count;
} device_entry;

typedef struct OUI_INFO
{
    char* oui; // only first 3 bytes of MAC (AA:BB:CC)
    char* organization;
} oui_info;

bool get_device_info(device_info* device);

bool get_MAC_addr(char *device, uint8_t* mac_out);

// remember to free returned val
char* get_MAC_addr_str(char* device);

void import_oui(const char* filepath, struct HashTable* ht);

void device_entry_destroy(void* v);
void pending_srv_destroy(void* v);
void port_info_destroy(void *v);
void oui_info_destroy(void *v);

void print_help(const char* prog_name);
void print_device_info(const device_info device);
void print_results(struct HashTable* ht, struct HashTable* ht_ports, struct HashTable* ht_oui);

#endif
