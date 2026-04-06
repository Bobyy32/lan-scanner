#include "port_scan.h"

#include <string.h>
#include <libnet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "debug.h"
#include "device.h"

static int get_port_num()
{
    int sock;
    struct sockaddr_in temp_sock;
    socklen_t len = sizeof(temp_sock);

    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        debug_printf("Failed ot create socket\n");
        return 0;
    }

    temp_sock.sin_family = AF_INET;
    temp_sock.sin_port = htons(0);
    temp_sock.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*) &temp_sock, sizeof(temp_sock)) < 0)
    {
        debug_printf("Failed to bind socket\n");
        close(sock);
        return 0;
    }

    if (getsockname(sock, (struct sockaddr*)&temp_sock, &len) < 0)
    {
        debug_printf("Failed to get socket number\n");
        close(sock);
        return 0;
    }

    int port = ntohs(temp_sock.sin_port);
    close(sock);
    return port;
}

void parse_service_info(struct HashTable *ht)
{
    FILE* f = NULL;
    char* line = NULL;
    size_t len = 0;
    ssize_t read;
    unsigned int count = 0;

    f = fopen("/etc/services", "r");
    if (f == NULL)
    {
        debug_printf("Cannot find /etc/services!\n");
        return;
    }

    while((read = getline(&line, &len, f)) != -1)
    {
        if (line[0] == '#' || line[0] == '\n')
        {
            continue;
        }
        
        char* saveptr1 = NULL; 
        char* service = strtok_r(line, " \t", &saveptr1);
        if(service == NULL)
        {
            continue;
        }
        
        char* temp = strtok_r(NULL, " \t", &saveptr1);
        if (temp == NULL)
        {
            continue;
        }
        

        char* saveptr2 = NULL;
        char* port = strtok_r(temp, "/", &saveptr2);
        char* protocol = strtok_r(NULL, "/", &saveptr2);

        if (port == NULL || protocol == NULL)
        {
            continue;
        }

        protocol[strcspn(protocol, " \t\n\r")] = '\0';

        port_info* info = NULL;
        info = (port_info*)ht_get(ht, port);
        if (info != NULL)
        {
            if (strcmp(info->protocol, protocol) != 0)
            {
                size_t new_size = strlen(info->protocol) + strlen(protocol) + 2;
                char* new_str = malloc(new_size);
                snprintf(new_str, new_size, "%s/%s", info->protocol, protocol);
                free(info->protocol);
                info->protocol = new_str;
            }
        }
        else
        {
            info = calloc(1, sizeof(port_info));
            if (info == NULL)
            {
                continue;
            }

            info->service = strdup(service);
            info->port = (uint16_t)atoi(port);
            info->protocol = strdup(protocol);

            ht_set(ht, port, info);
            count++;
        }
    }

    free(line);
    fclose(f);
}

void import_ports(const char* filepath, hash_table* ht)
{
    if (ht == NULL)
    {
        debug_printf("Hash table is NULL\n");
        return;
    }

    ssize_t read;
    char* line = NULL;
    size_t len = 0;

    FILE* f = fopen(filepath, "r");
    if (f == NULL)
    {
        debug_printf("Failed to open %s\n", filepath);
        return;
    }

    while ((read = getline(&line, &len, f)) != -1)
    {
        char* saveptr = NULL;

        char* service = strtok_r(line, " ", &saveptr);
        char* port = strtok_r(NULL, " ", &saveptr);
        char* protocol = strtok_r(NULL, " \n", &saveptr);

        //printf("%s %s %s\n", service, port, protocol);
        
        port_info* info = NULL;
        info = (port_info*)ht_get(ht, port);
        if (info != NULL)
        {
            if (strcmp(info->protocol, protocol) != 0)
            {
                size_t new_size = strlen(info->protocol) + strlen(protocol) + 2;
                char* new_str = malloc(new_size);
                snprintf(new_str, new_size, "%s/%s", info->protocol, protocol);
                free(info->protocol);
                info->protocol = new_str;
            }
        }
        else
        {
            info = (port_info*)calloc(1, sizeof(port_info));
            if (info == NULL)
            {
                continue;
            }

            info->service = strdup(service);
            info->port = (uint16_t)atoi(port);
            info->protocol = strdup(protocol);

            ht_set(ht, port, info);
        }
    }

    free(line);
    fclose(f);
}

static bool create_tcp_msg(libnet_t* context, const device_info source_device, const uint8_t* target_mac, const uint32_t target_ip, const uint16_t target_port)
{

    libnet_ptag_t tcp_hdr = libnet_build_tcp(get_port_num(), target_port, 0x01010101, 0, TH_SYN, 1024, 0, 0, LIBNET_TCP_H, NULL, 0, context, 0);
    if (tcp_hdr == -1)
    {
        debug_printf("Cant build tcp header: %s\n", libnet_geterror(context));
        return false;
    }

    libnet_ptag_t ipv4_hdr = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0, 0, 0, 255, IPPROTO_TCP, 0, source_device.ipv4_address, target_ip, NULL, 0, context, 0);
    if (ipv4_hdr == -1)
    {
        debug_printf("Cant build IP header: %s\n", libnet_geterror(context));
        return false;
    }

    libnet_ptag_t eth_hdr = libnet_autobuild_ethernet(target_mac, ETHERTYPE_IP, context);
    if (eth_hdr == -1)
    {
        debug_printf("Cant build ethernet header: %s\n", libnet_geterror(context));
        return false;
    }

    return true;
}

void tcp_port_scan(libnet_t* context, const device_info source_device, const uint8_t* target_mac, const uint32_t target_ip, const uint16_t target_port)
{
    if(!create_tcp_msg(context, source_device, target_mac, target_ip, target_port))
    {
        debug_printf("Failed to create tcp packet!\n");
        return;
    }

    int c = libnet_write(context);
    if (c == -1)
    {
        debug_printf("Failed to write tcp packet!\n");
        return;
    }
}

void tcp_port_rcv_callback(const unsigned char *packet, struct pcap_pkthdr *header, void *data)
{
    struct HashTable* ht = (struct HashTable*)data;
    struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct ether_header));
    struct tcphdr* tcp_hdr = (struct tcphdr*)(packet + sizeof(struct ether_header) + (ip_hdr->ip_hl << 2));

    if (tcp_hdr->th_flags == (TH_SYN | TH_ACK))
    {
        uint16_t port = ntohs(tcp_hdr->th_sport);
        char* src_ip = inet_ntoa(ip_hdr->ip_src);
        //debug_printf("Open port at %d from %s\n", port, src_ip);

        device_entry* entry = (device_entry*)ht_get(ht, src_ip);
        if (entry != NULL)
        {
            uint16_t* tmp = realloc(entry->open_ports, (entry->open_port_count + 1) * sizeof(uint16_t));
            if (tmp != NULL)
            {
                entry->open_ports = tmp;
                entry->open_ports[entry->open_port_count] = port;
                entry->open_port_count++;
            }
        }
    }
}
