#include "arp.h"

bool create_arp_message(libnet_t* context, device_info source_device, uint32_t target_ip)
{
    // Make Arp Packet
    uint8_t broadcast_addr[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    libnet_ptag_t arp_hdr = libnet_autobuild_arp(ARPOP_REQUEST, source_device.mac_address, (uint8_t*)&source_device.ipv4_address, broadcast_addr, (uint8_t*)&target_ip, context);

    if (arp_hdr == -1)
    {
        fprintf(stderr, "Can't build arp header: %s\n", libnet_geterror(context));
        return false;
    }

    libnet_ptag_t eth_hdr = libnet_autobuild_ethernet(source_device.mac_address, ETHERTYPE_ARP, context);

    if (eth_hdr == -1)
    {
        fprintf(stderr, "Cant build ethernet header: %s\n", libnet_geterror(context));
        return false;
    }

    return true;
}