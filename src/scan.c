#include "scan.h"

#include "capture.h"
#include "protocols/arp.h"
#include "protocols/mdns.h"
#include "protocols/ssdp.h"
#include "port_scan.h"
#include "debug.h"

void *arp_scan_thread(void *arg)
{
    scan_args* args = (scan_args*)arg;
    arp_scan(args->device, args->ht);
    return NULL;
}

void *mdns_scan_thread(void *arg)
{
    scan_args* args = (scan_args*)arg;
    mdns_scan(args->device, args->ht);
    return NULL;
}

void *ssdp_scan_thread(void *arg)
{
    scan_args* args = (scan_args*)arg;
    ssdp_scan(args->device, args->ht);
    return NULL;
}

void *tcp_scan_thread(void *arg)
{
    return NULL;
}

void arp_scan(struct DeviceInfo *device, struct HashTable *ht)
{
    char filter[256] = {0};
    
    char* mac_str = get_MAC_addr_str(device->name);
    snprintf(
        filter,
        sizeof(filter),
        "arp and not ether src host %s",
        mac_str
    );
    free(mac_str);
    mac_str = NULL;


    char libnet_errbuff[LIBNET_ERRBUF_SIZE];
    libnet_t* context = libnet_init(LIBNET_LINK_ADV, device->name, libnet_errbuff);
    if (!context)
    {
        debug_printf("Unable to initialize libnet context %s\n", libnet_errbuff);
        return;
    }

    pcap_t* handle = init_capture(*device, filter);
    if (!handle)
    {
        debug_printf("Unable to initialize pcap catpure\n");
        libnet_destroy(context);
        return;
    }

    arp_sweep(context, *device);
    capture_loop(handle, 5, arp_rcv_callback, (void*)ht);

    libnet_destroy(context);
    capture_close(handle);
}

void mdns_scan(struct DeviceInfo *device, struct HashTable *ht)
{
    char filter[256] = {0};
    snprintf(
        filter, 
        sizeof(filter),
        "udp port 5353 and not src host %s",
        inet_ntoa((struct in_addr) {device->ipv4_address})
    );

    struct HashTable* srv_ht = ht_create();
    if (srv_ht == NULL)
    {
        debug_printf("Unable to create hash table!\n");
        return;
    }

    char libnet_errbuff[LIBNET_ERRBUF_SIZE];
    libnet_t* context = libnet_init(LIBNET_LINK_ADV, device->name, libnet_errbuff);
    if (!context)
    {
        debug_printf("Unable to initialize libnet context %s\n", libnet_errbuff);
        ht_destroy(srv_ht, pending_srv_destroy);
        return;
    }

    pcap_t* handle = init_capture(*device, filter);
    if (!handle)
    {
        debug_printf("Unable to initialize pcap capture\n");
        ht_destroy(srv_ht, pending_srv_destroy);
        libnet_destroy(context);
        return;
    }

    capture_ht ct = {.ht = ht, .srv_table = srv_ht};
    mdns_discovery_send_m(context, *device);
    capture_loop(handle, 5, mdns_discovery_rcv_callback, (void*)&ct);

    ht_destroy(srv_ht, pending_srv_destroy);
    libnet_destroy(context);
    capture_close(handle);
}

void ssdp_scan(struct DeviceInfo *device, struct HashTable *ht)
{
    char filter[256] = {0};
    snprintf(
        filter,
        sizeof(filter),
        "udp port 1900 and not src host %s",
        inet_ntoa((struct in_addr) {device->ipv4_address})
    );

    char libnet_errbuff[LIBNET_ERRBUF_SIZE];
    libnet_t* context = libnet_init(LIBNET_LINK_ADV, device->name, libnet_errbuff);
    if (!context)
    {
        debug_printf("Unable to initialize libnet context %s\n", libnet_errbuff);
        return;
    }

    pcap_t* handle = init_capture(*device, filter);
    if (!handle)
    {
        debug_printf("Unable to initialize pcap capture\n");
        libnet_destroy(context);
        return;
    }

    ssdp_discovery_send(context, *device);
    capture_loop(handle, 5, ssdp_discovery_rcv_callback, (void*)ht);

    libnet_destroy(context);
    capture_close(handle);
}

void tcp_scan(struct DeviceInfo *device, struct HashTable *ht)
{
    struct HashTable* ht_services = ht_create();
    parse_service_info(ht);

    char libnet_errbuff[LIBNET_ERRBUF_SIZE];
    libnet_t* context = libnet_init(LIBNET_LINK_ADV, device->name, libnet_errbuff);
    if (!context)
    {
        debug_printf("Unable to initialize libnet context %s\n", libnet_errbuff);
        ht_destroy(ht, device_entry_destroy);
        return;
    }

    for (size_t i = 0; i < ht->capacity; ++i)
    {
        if (ht->table[i] == NULL)
        {
            continue;
        }

        device_entry* target = (device_entry*)ht->table[i]->value;
        if (target->mac[0] != '\0')
        {
            //tcp_port_scan(context, *device, target->mac, inet_addr(ht->table[i]->key), target_port)
        }
    }

}

void tcp_rcv(struct DeviceInfo *device, struct HashTable *ht)
{
    char filter[256] = {0};
    snprintf(
        filter,
        sizeof(filter),
        "tcp and not src host %s",
        inet_ntoa((struct in_addr) {device->ipv4_address})
    );

    pcap_t* handle = init_capture(*device, filter);
    if (!handle)
    {
        debug_printf("Unable to initialize pcap catpure\n");
        ht_destroy(ht, device_entry_destroy);
        return;
    }
}
