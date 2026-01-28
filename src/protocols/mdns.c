#include "mdns.h"

bool mdns_discovery_send(libnet_t *context, const device_info device)
{

    int offset = 0;
    unsigned char payload[256];
    
    // Build dns query (_services._dns-sd._udp.local)
    offset = write_dns_label(payload, offset, "_services");                                                                                                                                                                    
    offset = write_dns_label(payload, offset, "_dns-sd");                                                                                                                                                                      
    offset = write_dns_label(payload, offset, "_udp");                                                                                                                                                                         
    offset = write_dns_label(payload, offset, "local");                                                                                                                                                                        
    payload[offset++] = 0;

    struct dns_question question;
    question.qtype = htons(DNS_TYPE_PTR);
    question.qclass = htons(DNS_CLASS_IN);

    memcpy(&payload[offset], &question, sizeof(question));
    offset += sizeof(question);

    libnet_ptag_t dns = libnet_build_dnsv4(LIBNET_DNS_H, 0, 0, 1, 0, 0, 0, (uint8_t*)payload, (uint32_t)offset, context, 0);
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

    libnet_ptag_t ipv4 = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DNS_H + offset, 0, 0, 0, 64, IPPROTO_UDP, 0, device.ipv4_address, inet_addr("224.0.0.251"), NULL, 0, context, 0);
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

    int c = libnet_write(context);
    if (c == -1)
    {
        fprintf(stderr, "Packet size: %s\n", libnet_geterror(context));
        goto bad;
    }
    else
    {
        fprintf(stdout, "Successfuly Sent mDNS request\n");
    }

    return true;

bad:
    return false;
}

void mdns_discovery_rcv(device_info device)
{
    // https://stackoverflow.com/questions/51376598/c-libpcap-api-extracting-dns-query

    fprintf(stdout, "\nListening for replies:\n");

    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(device.name, BUFSIZ, 0, 100, errbuff); // 100 redundant but keep
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s, %s\n", device.name, errbuff);
        goto bad;
    }

    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", device.name);
        goto bad;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "udp port 5353 and multicast", 0, device.ipv4_address) == -1)
    {
        fprintf(stderr, "Couldn't parse filter mDNS: %s\n", pcap_geterr(handle));
        goto bad;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(handle));
        goto bad;
    }

    // Set non-blocking mode
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_setnonblock(handle, 1, pcap_errbuf) == -1)
    {
        fprintf(stderr, "Couldn't set non-blocking mode: %s\n", pcap_errbuf);
        goto bad;
    }

    struct timespec time_start, time_now;
    clock_gettime(CLOCK_MONOTONIC, &time_start);
    int wait_sec = 2;
    while(1)
    {
        clock_gettime(CLOCK_MONOTONIC, &time_now);
        double elapsed = (time_now.tv_sec - time_start.tv_sec) + (time_now.tv_nsec - time_start.tv_nsec) / 1000000000.0;

        if (elapsed >= wait_sec)
        {
            break;
        }

        struct pcap_pkthdr* header;
        const unsigned char* packet = NULL;
        int result = pcap_next_ex(handle, &header, &packet);
        if(result != 1)
        {
            // No packet available in non-blocking mode, sleep briefly
            if (result == 0)
            {
                usleep(10000); // 10ms
            }
            else
            {
                fprintf(stderr, "pcap_next_ex error: %d\n", result);
            }
            continue;
        }
        
        //struct ether_header* ether_hdr = (struct ether_header*)packet;
        struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct ether_header));
        int ip_hdr_len = ip_hdr->ip_hl * 4;
        //struct udphdr* udp_hdr = (struct udphdr*)(packet + ip_hdr_len + sizeof(struct ether_header));
        struct dns_header* dns_hdr = (struct dns_header*)(packet + sizeof(struct udphdr) + ip_hdr_len + sizeof(struct ether_header));
        
        uint16_t flags = ntohs(dns_hdr->flags);
        if (!(flags & DNS_FLAG_QR))
        {
            continue;
        }

        uint16_t num_answers = ntohs(dns_hdr->ancount);
        if (num_answers == 0)
        {
            continue;
        }

        printf("[mDNS Response] From: %s | Answers: %d\n", inet_ntoa(ip_hdr->ip_src), num_answers);
    }

    pcap_close(handle);
    return;
bad:
    if (handle)
    {
        pcap_close(handle);
    }
}

// Helper to write a DNS label
int write_dns_label(unsigned char *buf, int offset, const char *label)
{
    int len = strlen(label);                                                                                                                                                                                               
    buf[offset++] = (unsigned char)len;                                                                                                                                                                                    
    memcpy(&buf[offset], label, len);                                                                                                                                                                                      
    return offset + len;
}
