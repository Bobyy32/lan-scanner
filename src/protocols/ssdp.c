#include "ssdp.h"

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
        fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(context));
        return false;
    }

    libnet_ptag_t ipv4 = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_UDP_H + buffer_len, 0, 0, 0, 3, IPPROTO_UDP, 0, device.ipv4_address, inet_addr(ssdp_m_addr), NULL, 0, context, LIBNET_PTAG_INITIALIZER);
    if (ipv4 == -1)
    {
        fprintf(stderr, "Can't build IPV4 header: %s\n", libnet_geterror(context));
        return false;
    }

    uint8_t dst[6] = {0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb};
    libnet_ptag_t ether = libnet_autobuild_ethernet(dst, ETHERTYPE_IP, context);
    if (ether == -1)
    {
        fprintf(stderr, "Can't build Ethernet header: %s\n", libnet_geterror(context));
        return false;
    }

    return true;
}

bool ssdp_discovery_send(libnet_t *context, const device_info device)
{
    if(!create_ssdp_message(context, device))
    {
        fprintf(stderr, "Failed to create ssdp message\n");
        return false;
    }

    int c = libnet_write(context);
    if (c == -1)
    {
        fprintf(stderr, "Packet size: %s\n", libnet_geterror(context));
        return false;
    }

    fprintf(stdout, "Successfuly Sent ssdp discovery\n");

    return true;
}

void ssdp_discovery_rcv_callback(const unsigned char *packet, struct pcap_pkthdr *header, void *data)
{
    
}
