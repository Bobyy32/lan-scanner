#include "scan.h"

#include "capture.h"
#include "protocols/arp.h"
#include "protocols/mdns.h"
#include "protocols/ssdp.h"
#include "port_scan.h"
#include "thread_pool.h"
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

void *tcp_rcv_thread(void *arg)
{
    scan_args* args = (scan_args*)arg;
    tcp_rcv(args->device, args->ht);
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

static void tcp_port_scan_thread(void* arg)
{
    thread_scan_args* args = (thread_scan_args*)arg;

    char libnet_errbuff[LIBNET_ERRBUF_SIZE];
    libnet_t* context = libnet_init(LIBNET_LINK_ADV, args->source_device.name, libnet_errbuff);
    if (!context)
    {
        debug_printf("Unable to initialize libnet context %s\n", libnet_errbuff);
        return;
    }
    
    tcp_port_scan(context, args->source_device, args->target_mac, args->target_ip, args->target_port);

    libnet_destroy(context);
}

void tcp_scan(struct DeviceInfo *device, struct HashTable *ht, struct HashTable* ht_ports)
{
    thread_pool* pool = init_thread_pool(8);
    unsigned int job_count = 0;

    for (size_t i = 0; i < ht->capacity; ++i)
    {
        if (ht->table[i] == NULL)
        {
            continue;
        }

        device_entry* target = (device_entry*)ht->table[i]->value;
        if (target->mac[0] != '\0')
        {
            for (size_t j = 0; j < ht_ports->capacity; ++j)
            {
                if (ht_ports->table[j] == NULL)
                {
                    continue;
                }

                port_info info = *(port_info*)ht_ports->table[j];

                thread_scan_args* args = (thread_scan_args*)malloc(sizeof(thread_scan_args));
                if (args == NULL)
                {
                    continue;
                }

                args->source_device = *device;
                memcpy(args->target_mac, target->mac_bytes, 6);
                args->target_ip = inet_addr(ht->table[i]->key);
                args->target_port = info.port;

                add_work_thread_pool(pool, tcp_port_scan_thread, args);
                ++job_count;
            }
        }
    }

    start_work_thread_pool(pool);
    wait_thread_pool(pool);
    destroy_thread_pool(pool);
}

void tcp_rcv(struct DeviceInfo *device, struct HashTable *ht)
{
    char filter[256] = {0};
    snprintf(
        filter,
        sizeof(filter),
        "tcp and dst host %s",
        inet_ntoa((struct in_addr) {device->ipv4_address})
    );

    pcap_t* handle = init_capture(*device, filter);
    if (!handle)
    {
        debug_printf("Unable to initialize pcap catpure\n");
        return;
    }

    capture_loop(handle, 30, tcp_port_rcv_callback, (void*)ht);
    capture_close(handle);
}
