#include "device.h"
#include "port_scan.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include "debug.h"

bool get_device_info(device_info* device)
{

    // Gets Default Network Interface and name
    pcap_if_t* device_list = NULL;
    char pcap_errbuff[PCAP_ERRBUF_SIZE];
    if ((pcap_findalldevs(&device_list, pcap_errbuff) != 0) || device_list == NULL)
    {
        debug_printf("Couldn't find network device list: %s\n", pcap_errbuff);
        return false;
    }
    else
    {
        strncpy(device->name, device_list[0].name, IF_NAMESIZE - 1);
        device->name[IF_NAMESIZE - 1] = '\0';
        fprintf(stdout, "Device: %s\n", device->name);
    }
    
    for (pcap_addr_t* a = device_list[0].addresses; a != NULL; a = a->next)
    {
        if (a->addr->sa_family == AF_INET)
        {
            // Device IPv4 Address   
            device->ipv4_address = ((struct sockaddr_in*)a->addr)->sin_addr.s_addr;
            printf("Ip Address: %s\n", inet_ntoa((struct in_addr){device->ipv4_address}));

            // Subnet Mask
            device->subnet_mask = ((struct sockaddr_in*)a->netmask)->sin_addr.s_addr;
            printf("Subnet Mask: %s\n", inet_ntoa((struct in_addr){device->subnet_mask}));

            // Broadcast address
            device->broadcast_address = ((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr;
            printf("Broadcast Address: %s\n", inet_ntoa((struct in_addr){device->broadcast_address}));

            // Network ID
            device->network_id = (uint32_t)(device->ipv4_address & device->subnet_mask);
            printf("Network ID: %s\n", inet_ntoa((struct in_addr){device->network_id}));
        }
    }
        
    if (device->ipv4_address == 0)
    {
        debug_printf("Failed to find IPV4 Address\n");
        return false;
    }
    else if (device->subnet_mask == 0)
    {
        debug_printf("Failed to find Subnet Mask\n");
        return false;
    }

    // MAC address
    if(!get_MAC_addr(device->name, device->mac_address))
    {
        debug_printf("Couldn't get MAC address (get_MAC_addr)\n");
        return false;
    }
    else
    {
        printf("MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n\n", 
            device->mac_address[0], device->mac_address[1], device->mac_address[2], device->mac_address[3], device->mac_address[4], device->mac_address[5]);
    }

    pcap_freealldevs(device_list);

    return true;
}

bool get_MAC_addr(char *device, uint8_t* mac_out)
{
    // Get file path to interface's mac file
    char path[64];
    snprintf(path, sizeof(path), "/sys/class/net/%s/address", device);
    //fprintf(stdout, "%s\n", path);

    char mac_addr[18] = {0};

    // Get mac address from file
    FILE* f = fopen(path, "r");
    if (f == NULL)
    {
        debug_printf("Failed to open, %s\n", path);
        return false;
    }

    if(fgets(mac_addr, sizeof(mac_addr), f) == NULL)
    {
        fclose(f);
        debug_printf("Failed to get MAC address\n");
        return false;
    }

    fclose(f);

    sscanf(mac_addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac_out[0], &mac_out[1], &mac_out[2], &mac_out[3], &mac_out[4], &mac_out[5]);

    return true;
}

char *get_MAC_addr_str(char *device)
{
    char path[64];
    snprintf(path, sizeof(path), "/sys/class/net/%s/address", device);

    char* mac_addr = (char*)malloc(18);
    if (mac_addr == NULL)
    {
        return NULL;
    }

    FILE* f = fopen(path, "r");
    if (f == NULL)
    {
        debug_printf("Failed to open, %s\n", path);
        return NULL;
    }

    if(fgets(mac_addr, 18, f) == NULL)
    {
        fclose(f);
        debug_printf("Failed to get MAC address\n");
        return NULL;
    }

    fclose(f);

    return mac_addr;
}


void device_entry_destroy(void* v)
{
    device_entry* entry = (device_entry*)v;

    free(entry->ssdp_server);
    free(entry->ssdp_location);

    free(entry->open_ports);

    if (entry->services)
    {
        for (uint8_t j = 0; j < entry->service_count; ++j)
        {
            free(entry->services[j].service_type);
            free(entry->services[j].instance_name);
            free(entry->services[j].host_name);
        }
        free(entry->services);
    }

    free(entry);
}

void pending_srv_destroy(void* v)
{
    mdns_service* svc = (mdns_service*)v;
    free(svc->host_name);
    free(svc->instance_name);
    free(svc);
}

void port_info_destroy(void *v)
{
    port_info* info = (port_info*)v;
    free(info->service);
    free(info->protocol);
    free(info);
}

void print_help(const char* prog_name)
{
    printf("Usage: %s [OPTIONS]\n\n", prog_name);
    printf("Options:\n");
    printf("  --tcp              Run TCP port scan (all common ports)\n");
    printf("  --arp              Run ARP discovery\n");
    printf("  --mdns             Run mDNS discovery\n");
    printf("  --ssdp             Run SSDP discovery\n");
    printf("  --full             Run all scans\n");
    printf("  -p, --port PORTS   Specify ports to scan (comma-separated, e.g. 22,80,443)\n");
    printf("  -h, --help         Show this help message\n");
}

void print_results(struct HashTable* ht, struct HashTable* ht_ports)
{
    for (size_t i = 0; i < ht->capacity; ++i)
    {
        if (ht->table[i])
        {
            device_entry* entry = (device_entry*)ht->table[i]->value;
            printf("IP: %s\n", ht->table[i]->key);

            if(entry->mac[0] != '\0')
            {
                printf("  MAC address:   %s\n", entry->mac);
            }

            if (entry->ssdp_server)
            {
                printf("  SSDP Server:   %s\n", entry->ssdp_server);
            }
            if (entry->ssdp_location)
            {
                printf("  SSDP Location: %s\n", entry->ssdp_location);
            }

            if (entry->service_count > 0)
            {
                printf("  mDNS Services:\n");
                for (uint8_t j = 0; j < entry->service_count; ++j)
                {
                    printf("    [%d] type: %s | name: %s | host: %s | port: %u\n",
                        j,
                        entry->services[j].service_type ? entry->services[j].service_type : "unknown",
                        entry->services[j].instance_name ? entry->services[j].instance_name : "unknown",
                        entry->services[j].host_name ? entry->services[j].host_name : "unknown",
                        entry->services[j].port
                    );
                }
            }

            if (entry->open_port_count > 0)
            {
                printf("  Open TCP Services:\n");
                for (uint16_t j = 0; j < entry->open_port_count; ++j)
                {
                    char buf[6];
                    snprintf(buf, sizeof(buf), "%u", (unsigned)entry->open_ports[j]);
                    port_info* info = (port_info*)ht_get(ht_ports, buf);
                    if (info == NULL)
                    {
                        printf("    Port: %u | Service: UNKNOWN\n", (unsigned)entry->open_ports[j]);
                    }
                    else
                    {
                        printf("    Port: %u | Service: %s\n", info->port, info->service);
                    }
                }

            }
    
            putc('\n', stdout);
        }
    }
}