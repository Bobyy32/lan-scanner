#include "arp.h"

bool create_arp_message(libnet_t* context, device_info source_device, uint32_t target_ip)
{
    // Make Arp Packet
    uint8_t tha[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
    libnet_ptag_t arp_hdr = libnet_autobuild_arp(ARPOP_REQUEST, source_device.mac_address, (uint8_t*)&source_device.ipv4_address, tha, (uint8_t*)&target_ip, context);

    if (arp_hdr == -1)
    {
        fprintf(stderr, "Can't build arp header: %s\n", libnet_geterror(context));
        return false;
    }

    uint8_t broadcast_addr[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    libnet_ptag_t eth_hdr = libnet_autobuild_ethernet(broadcast_addr, ETHERTYPE_ARP, context);

    if (eth_hdr == -1)
    {
        fprintf(stderr, "Cant build ethernet header: %s\n", libnet_geterror(context));
        return false;
    }

    return true;
}

void arp_scan(device_info device)
{

    uint32_t network_id = ntohl(device.network_id); // htonl for other way fuck
    uint32_t broadcast_addr = ntohl(device.broadcast_address);

    for (uint32_t host = network_id + 1; host < broadcast_addr;  host++)
    {
        //printf("%u.%u.%u.%u\n", (host >> 24) & 0xFF, (host >> 16) & 0xFF, (host >> 8) & 0xFF, host & 0xFF);

    }
}
