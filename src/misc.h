#ifndef MISC_H
#define MISC_H

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

typedef struct device_info
{
    char name[IF_NAMESIZE]; // Name of network interface
    uint32_t ipv4_address;  // Addresses stored in network byte order
    uint32_t subnet_mask;
    uint32_t network_id;
    uint32_t broadcast_address;
    uint8_t mac_address[6];

} device_info;

/*
    Gets Device's name, ip, subnet, broadcast address, network id, and mac address.
*/
bool get_device_info(device_info* device);

/*
    Redundant. Use libnet_get_hwaddr instead to obtain MAC address. 
*/
bool get_MAC_addr(char *device, uint8_t* mac_out);

#endif
