#ifndef CAPTURE_H
#define CAPTURE_H

#include "device.h"

struct pcap_pkthdr;

pcap_t* init_capture(device_info device, const char* filter);
typedef void (*packet_handler)(const unsigned char* packet, struct pcap_pkthdr* header, void* data);
void capture_loop(pcap_t* handle, int timeout, packet_handler handler_callback, void* data);
void capture_close(pcap_t* handle);

#endif