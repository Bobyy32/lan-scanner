#ifndef ARP_H
#define ARP_H

#include "../misc.h"

#include <libnet.h>

bool create_arp_message(libnet_t* context, device_info device, uint32_t target_ip);
void arp_scan(libnet_t* context, device_info device);

#endif