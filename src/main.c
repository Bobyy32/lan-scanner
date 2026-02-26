#include "device.h"
#include "capture.h"
#include "hashtable.h"
#include "protocols/arp.h"
#include "protocols/mdns.h"
#include "protocols/ssdp.h"

int main(int argc, char* argv[])
{
    struct HashTable* ht = ht_create();
    if (ht == NULL)
    {
        fprintf(stderr, "Unable to create hash table!\n");
        return (EXIT_FAILURE);
    }

    // Get default device details
    device_info my_device = { 0 };
    if(!get_device_info(&my_device))
    {
        fprintf(stderr, "Unable to get device info!\n");
        ht_destroy(ht);
        return (EXIT_FAILURE);
    }

    // Initialize arp packet context
    char libnet_errbuff[LIBNET_ERRBUF_SIZE];
    libnet_t* context = libnet_init(LIBNET_LINK_ADV, my_device.name, libnet_errbuff);
    if (!context)
    {
        fprintf(stderr, "Unable to intialize libnet context: %s\n", libnet_errbuff);
        goto bad;
    }

    /*
        ARP scan
    */
    char filter[256] = { 0 };
    char* mac_addr = get_MAC_addr_str(my_device.name);
    snprintf(
        filter,
        sizeof(filter),
        "arp and not ether src host %s",
        mac_addr);

    free(mac_addr);
    mac_addr = NULL;

    pcap_t* handle = init_capture(my_device, filter);
    if (!handle)
    {
        fprintf(stderr, "Unable to initialize pcap catpure\n");
        goto bad;
    }

    arp_scan(context, my_device);
    capture_loop(handle, 5, arp_scan_rcv_callback, (void*)ht);
    
    /*
        MDNS
    */
    memset(filter, 0, 256);
    
    snprintf(
        filter, 
        sizeof(filter),
        "udp port 5353 and not src host %s",
        inet_ntoa((struct in_addr) {my_device.ipv4_address})
    );

    change_filter(my_device, handle, filter);
    mdns_discovery_send_m(context, my_device);
    capture_loop(handle, 5, mdns_discovery_rcv_callback, NULL);

    /*
        SSDP
    */
    memset(filter, 0, 256);

    snprintf(
        filter,
        sizeof(filter),
        "udp port 1900 and not src host %s",
        inet_ntoa((struct in_addr) {my_device.ipv4_address})
    );

    change_filter(my_device, handle, filter);
    
    ssdp_discovery_send(context, my_device);
    capture_loop(handle, 5, ssdp_discovery_rcv_callback, (void*)ht);

    for (size_t i = 0; i < ht->capacity; ++i)
    {
        if (ht->table[i])
        {

            device_entry* val = (device_entry*)ht->table[i]->value;
            printf("%s -> %s\n", ht->table[i]->key,val->mac);
            if (val->ssdp_server)
            {
                printf("Server: %s\n", val->ssdp_server);
            }
            if (val->ssdp_location)
            {
                printf("Location: %s\n", val->ssdp_location);
            }

            putc('\n', stdout);
        }
    }
       
    ht_destroy(ht);
    libnet_destroy(context);
    capture_close(handle);
    return 0;

bad:
    if (ht)
    {
        ht_destroy(ht);
    }

    if (context)
    {
        libnet_destroy(context);
    }

    capture_close(handle);

    return (EXIT_FAILURE);
}