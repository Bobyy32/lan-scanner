#include "arp.h"

#include <netinet/if_ether.h>
#include <netinet/in.h>
#include "../hashtable.h"
#include "../debug.h"

bool create_arp_message(libnet_t* context, const device_info source_device, const uint32_t target_ip)
{
    // Make Arp Packet
    uint8_t tha[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
    libnet_ptag_t arp_hdr = libnet_autobuild_arp(ARPOP_REQUEST, source_device.mac_address, (uint8_t*)&source_device.ipv4_address, tha, (uint8_t*)&target_ip, context);

    if (arp_hdr == -1)
    {
        debug_printf("Can't build arp header: %s\n", libnet_geterror(context));
        return false;
    }

    uint8_t broadcast_addr[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    libnet_ptag_t eth_hdr = libnet_autobuild_ethernet(broadcast_addr, ETHERTYPE_ARP, context);

    if (eth_hdr == -1)
    {
        debug_printf("Cant build ethernet header: %s\n", libnet_geterror(context));
        return false;
    }

    return true;
}

void arp_sweep(libnet_t* context, const device_info device)
{

    uint32_t start = ntohl(device.network_id);
    uint32_t end = ntohl(device.broadcast_address);

    for (uint32_t host = start + 1; host < end;  host++)
    {
        uint32_t target = htonl(host);
        if(!create_arp_message(context, device, target))
        {
            debug_printf("Unable to create arp message for %s\n", inet_ntoa((struct in_addr){target}));
            continue;
        }

        // If successfuly create arp message then attempt to send
        int c = libnet_write(context);
        if (c == -1)
        {
            debug_printf("Packet size: %s\n", libnet_geterror(context));
            continue;
        }
        
        libnet_clear_packet(context);
    }
}

void arp_rcv_callback(const unsigned char *packet, struct pcap_pkthdr *header, void *data)
{
    struct HashTable* ht = (struct HashTable*)data;
    struct ether_header* ether_hdr = (struct ether_header*)packet;
        if(ntohs(ether_hdr->ether_type) == ETHERTYPE_ARP)
        {
            struct ether_arp* arp_hdr = (struct ether_arp*)(packet + sizeof(struct ether_header)); 
            
            if (ntohs(arp_hdr->ea_hdr.ar_op) == ARPOP_REPLY)
            {

                if (ht_get(ht, inet_ntoa(*(struct in_addr*)arp_hdr->arp_spa)))
                {
                    return;
                }


                device_entry* value = (device_entry*)calloc(1, sizeof(device_entry));
                if (value == NULL)
                {
                    return;
                }

                snprintf(value->mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x", arp_hdr->arp_sha[0], arp_hdr->arp_sha[1], arp_hdr->arp_sha[2], arp_hdr->arp_sha[3], arp_hdr->arp_sha[4], arp_hdr->arp_sha[5]);
                
                ht_set(ht, inet_ntoa(*(struct in_addr*)arp_hdr->arp_spa), (void*)value);
            } 
        }
}
