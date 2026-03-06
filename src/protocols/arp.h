#ifndef ARP_H
#define ARP_H


#include <libnet.h>
#include "../device.h"

struct pcap_pkthdr;

bool create_arp_message(libnet_t* context, const device_info device, const uint32_t target_ip);

void arp_sweep(libnet_t* context, const device_info device);
void arp_rcv_callback(const unsigned char* packet, struct pcap_pkthdr* header, void* data);


#endif