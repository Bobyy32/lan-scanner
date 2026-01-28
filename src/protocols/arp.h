#ifndef ARP_H
#define ARP_H


#include "../misc.h"

bool create_arp_message(libnet_t* context, const device_info device, const uint32_t target_ip);
void arp_scan(libnet_t* context, pcap_t* handle, const device_info device);

#endif