#include "ssdp.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "../hashtable.h"
#include "../debug.h"

bool create_ssdp_message(libnet_t *context, const device_info device)
{
    char* ssdp_m_addr = "239.255.255.250";
    char buffer [512];
    snprintf(
        buffer,
        sizeof(buffer),
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST:%s:1900\r\n"
        "MAN:\"ssdp:discover\"\r\n"
        "MX:1\r\n"
        "ST: ssdp:all\r\n"
        "USER-AGENT:OS/version product/version\r\n"
        "\r\n",
        ssdp_m_addr        
    );
    int buffer_len = strlen(buffer);

    libnet_ptag_t udp = libnet_build_udp(1900, 1900, LIBNET_UDP_H + buffer_len, 0, (uint8_t*)buffer, buffer_len, context, LIBNET_PTAG_INITIALIZER);
    if (udp == -1)
    {
        debug_printf("Can't build UDP header: %s\n", libnet_geterror(context));
        return false;
    }

    libnet_ptag_t ipv4 = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_UDP_H + buffer_len, 0, 0, 0, 3, IPPROTO_UDP, 0, device.ipv4_address, inet_addr(ssdp_m_addr), NULL, 0, context, LIBNET_PTAG_INITIALIZER);
    if (ipv4 == -1)
    {
        debug_printf("Can't build IPV4 header: %s\n", libnet_geterror(context));
        return false;
    }

    uint8_t dst[6] = {0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb};
    libnet_ptag_t ether = libnet_autobuild_ethernet(dst, ETHERTYPE_IP, context);
    if (ether == -1)
    {
        debug_printf("Can't build Ethernet header: %s\n", libnet_geterror(context));
        return false;
    }

    return true;
}

bool ssdp_discovery_send(libnet_t *context, const device_info device)
{
    if(!create_ssdp_message(context, device))
    {
        debug_printf("Failed to create ssdp message\n");
        return false;
    }

    int c = libnet_write(context);
    if (c == -1)
    {
        debug_printf("Packet size: %s\n", libnet_geterror(context));
        return false;
    }

    return true;
}

void ssdp_discovery_rcv_callback(const unsigned char *packet, struct pcap_pkthdr *header, void *data)
{
    struct HashTable* ht = (struct HashTable*)data;

    struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct ether_header));
    struct udphdr* udp_hdr = (struct udphdr*)(packet + (ip_hdr->ip_hl << 2) + sizeof(struct ether_header));
    char* ssdp_data = (char *)(packet + sizeof(struct udphdr) + (ip_hdr->ip_hl << 2) + sizeof(struct ether_header));

    unsigned int ssdp_len = ntohs(udp_hdr->len) - sizeof(struct udphdr);
    size_t headers_len = sizeof(struct ether_header) + (ip_hdr->ip_hl << 2) + sizeof(struct udphdr);
    if (headers_len + ssdp_len > header->caplen)
    {
        ssdp_len = header->caplen > headers_len ? header->caplen - headers_len : 0;
    }

    device_entry* value = (device_entry*)ht_get(ht, inet_ntoa(ip_hdr->ip_src));
    if (value == NULL)
    {
        value = (device_entry*)calloc(1, sizeof(device_entry));
        if (value == NULL)
        {
            return;
        }
        ht_set(ht, inet_ntoa(ip_hdr->ip_src), value);
    }

    char* buff = malloc(ssdp_len + 1);
    if (buff == NULL)
    {
        return;
    }

    memcpy(buff, ssdp_data, ssdp_len);
    buff[ssdp_len] = '\0';

    // printf("SSDP Response From %s:\n%s\n", inet_ntoa(ip_hdr->ip_src), buff);

    char* line = strtok(buff, "\r\n");
    while (line)
    {
        char tmp[256] = { 0 };
        if (sscanf(line, "SERVER: %[^\r\n]", tmp) == 1)
        {
            free(value->ssdp_server);
            value->ssdp_server = strdup(tmp);
        }
        else if (sscanf(line, "LOCATION: %[^\n]", tmp) == 1)
        {
            free(value->ssdp_location);
            value->ssdp_location = strdup(tmp);
        }

        line = strtok(NULL, "\r\n");
    }

    free(buff);

}
