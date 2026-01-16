#ifndef ARP_H
#define ARP_H

#define _DEFAULT_SOURCE

#include "../misc.h"

#include <time.h>

#include <net/ethernet.h>
#include <netinet/if_ether.h>

bool create_arp_message(libnet_t* context, const device_info device, const uint32_t target_ip);
void arp_scan(libnet_t* context, pcap_t* handle, const device_info device);

#endif