#ifndef DEVICE_H
#define DEVICE_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <pcap.h>
#include <libnet.h>

/*
    Have a struct that holds device details:
    name of interface
    ip
    Subnet Mask
    Network ID
    braodcast address
    mac address
*/

typedef struct MdnsService
{
    char* name;
    char* type;
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
    char mac[18];       // MAC addres
    char* ssdp_server;  // server header from ssdp
    char* ssdp_location; // location header from ssdp
    mdns_service* services;
    uint8_t service_count;
} device_entry;


bool get_device_info(device_info* device);

bool get_MAC_addr(char *device, uint8_t* mac_out);

// remember to free returned val
char* get_MAC_addr_str(char* device);



#endif
