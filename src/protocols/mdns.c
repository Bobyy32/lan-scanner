#include "mdns.h"

// Helper to write a DNS label
int write_dns_label(unsigned char *buf, int offset, const char *label)
{
    int len = strlen(label);                                                                                                                                                                                               
    buf[offset++] = (unsigned char)len;                                                                                                                                                                                    
    memcpy(&buf[offset], label, len);                                                                                                                                                                                      
    return offset + len;
}

bool create_mdns_query_msg(libnet_t *context, const device_info device, const uint32_t target_ip)
{
    int offset = 0;
    unsigned char buffer[256];
    
    // Build dns query (_services._dns-sd._udp.local)
    offset = write_dns_label(buffer, offset, "_services");                                                                                                                                                                    
    offset = write_dns_label(buffer, offset, "_dns-sd");                                                                                                                                                                      
    offset = write_dns_label(buffer, offset, "_udp");                                                                                                                                                                         
    offset = write_dns_label(buffer, offset, "local");                                                                                                                                                                        
    buffer[offset++] = 0;;

    struct dns_question question;
    question.qtype = htons(DNS_TYPE_PTR);
    question.qclass = htons(DNS_CLASS_IN_QU);

    memcpy(&buffer[offset], &question, sizeof(question));
    offset += sizeof(question);

    libnet_ptag_t dns = libnet_build_dnsv4(LIBNET_DNS_H, 0, 0, 1, 0, 0, 0, (uint8_t*)buffer, (uint32_t)offset, context, 0);
    if (dns == -1)
    {
        fprintf(stderr, "Can't build DNS header: %s\n", libnet_geterror(context));
        goto bad;
    }

    libnet_ptag_t udp = libnet_build_udp(5353,5353, LIBNET_UDP_H + LIBNET_DNS_H + offset, 0, NULL, 0, context, 0);
    if (udp == -1)
    {
        fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(context));
        goto bad;
    }

    libnet_ptag_t ipv4 = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DNS_H + offset, 0, 0, 0, 255, IPPROTO_UDP, 0, device.ipv4_address, target_ip, NULL, 0, context, 0);
    if (ipv4 == -1)
    {
        fprintf(stderr, "Can't build IPV4 header: %s\n", libnet_geterror(context));
        goto bad;
    }
    
    uint8_t dst[6] = {0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb};
    libnet_ptag_t ether = libnet_autobuild_ethernet(dst, ETHERTYPE_IP, context);
    if (ether == -1)
    {
        fprintf(stderr, "Can't build Ethernet header: %s\n", libnet_geterror(context));
        goto bad;
    }

    return true;

bad:
    return false;
}

bool mdns_discovery_send_m(libnet_t *context, const device_info device)
{

    // multicast ip
    if(!create_mdns_query_msg(context, device, inet_addr("224.0.0.251")))
    {
        fprintf(stderr, "Failed to create multicast mdns message\n");
        goto bad;
    }

    int c = libnet_write(context);
    if (c == -1)
    {
        fprintf(stderr, "Packet size: %s\n", libnet_geterror(context));
        goto bad;
    }
    else
    {
        fprintf(stdout, "Successfuly Sent multicast mDNS request\n");
    }

    return true;

bad:
    return false;
}

void mdns_discovery_send_u(libnet_t* context, const device_info device)
{
    uint32_t start = ntohl(device.network_id);
    uint32_t end = ntohl(device.broadcast_address);
    
    for (uint32_t host = start + 1; host < end; ++host)
    {
        
        //printf("%u.%u.%u.%u\n", (host >> 24) & 0xFF, (host >> 16) & 0xFF, (host >> 8) & 0xFF, host & 0xFF);
        uint32_t target = htonl(host);
        if(!create_mdns_query_msg(context, device, target))
        {
            fprintf(stderr, "Unable to create mdns message for %s\n", inet_ntoa((struct in_addr){target}));
            continue;
        }

        int c = libnet_write(context);
        if (c == -1)
        {
            fprintf(stderr, "Packet size: %s\n", libnet_geterror(context));
            continue;
        }
        
        libnet_clear_packet(context);
    }
}

void mdns_discovery_rcv_callback(const unsigned char* packet, struct pcap_pkthdr* header, void* data)
{
    // https://stackoverflow.com/questions/51376598/c-libpcap-api-extracting-dns-query

    //struct ether_header* ether_hdr = (struct ether_header*)packet;
    struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct ether_header));
    int ip_hdr_len = ip_hdr->ip_hl * 4;
    //struct udphdr* udp_hdr = (struct udphdr*)(packet + ip_hdr_len + sizeof(struct ether_header));
    struct dns_header* dns_hdr = (struct dns_header*)(packet + sizeof(struct udphdr) + ip_hdr_len + sizeof(struct ether_header));
    
    uint16_t flags = ntohs(dns_hdr->flags);
    if (!(flags & DNS_FLAG_QR))
    {
        return;
    }

    uint16_t num_answers = ntohs(dns_hdr->ancount);
    if (num_answers == 0)
    {
        return;
    }

    printf("[mDNS Response] From: %s | Answers: %d\n", inet_ntoa(ip_hdr->ip_src), num_answers);
    
}
