#ifndef SSDP_H
#define SSDP_H

#include "../misc.h"

struct pcap_pkthdr;

bool create_ssdp_message(libnet_t* context, const device_info device);
bool ssdp_discovery_send(libnet_t* context, const device_info device);
void ssdp_discovery_rcv_callback(const unsigned char* packet, struct pcap_pkthdr* header, void* data);

#endif