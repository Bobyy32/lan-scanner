#include "port_scan.h"

#include <string.h>
#include <libnet.h>

#include "debug.h"
#include "device.h"

void parse_service_info(struct HashTable* ht)
{
    FILE* f = NULL;
    char* line = NULL;
    size_t len = 0;
    ssize_t read;

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

        /*
        printf("%s ", service);
        printf("%s ", port);
        printf("%s\n", protocol);
        */

        port_info* info = NULL;
        info = (port_info*)ht_get(ht, port);
        if (info != NULL)
        {
            if (strcmp(info->protocol, protocol))
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
        }
    }

    free(line);
    fclose(f);
}

static bool create_tcp_msg(libnet_t* context, const device_info source_device, const uint8_t* target_mac, const uint32_t target_ip, const uint16_t target_port)
{
    libnet_ptag_t tcp_hdr = libnet_build_tcp(target_port, target_port, 0x01010101, 0, TH_SYN, 1024, 0, 0, LIBNET_TCP_H, NULL, 0, context, 0);
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

void tcp_port_scan(const uint32_t target_ip)
{
   
}
