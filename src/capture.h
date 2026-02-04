#ifndef CAPTURE_H
#define CATPURE_H

#include "misc.h"

struct pcap_pktheadr;

pcap_t* init_capture(device_info device, const char* filter);

typedef void (*packet_handler)(const unsigned char* packet, struct pcap_pktheadr* header, void* data);

void capture_loop(pcap_t* handle, int timeout, packet_handler handler_callback, void* data);

void capture_close(pcap_t* handle);

#endif