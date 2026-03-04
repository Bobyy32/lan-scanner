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
        debug_printf("Unable to create hash table!\n");
        return (EXIT_FAILURE);
    }

    // Get default device details
    device_info my_device = { 0 };
    if(!get_device_info(&my_device))
    {
        debug_printf("Unable to get device info!\n");
        ht_destroy(ht, device_entry_destroy);
        return (EXIT_FAILURE);
    }

    // Initialize arp packet context
    char libnet_errbuff[LIBNET_ERRBUF_SIZE];
    libnet_t* context = libnet_init(LIBNET_LINK_ADV, my_device.name, libnet_errbuff);
    if (!context)
    {
        debug_printf("Unable to intialize libnet context: %s\n", libnet_errbuff);
        goto bad;
    }

    /*
        MDNS
    */
    char filter[256] = { 0 };
    snprintf(
        filter, 
        sizeof(filter),
        "udp port 5353 and not src host %s",
        inet_ntoa((struct in_addr) {my_device.ipv4_address})
    );

    pcap_t* handle = init_capture(my_device, filter);
    if (!handle)
    {
        debug_printf("Unable to initialize pcap catpure\n");
        goto bad;
    }

    mdns_discovery_send_m(context, my_device);
    capture_loop(handle, 5, mdns_discovery_rcv_callback, NULL);

    for (size_t i = 0; i < ht->capacity; ++i)                                                                                                                                                                        
    {                                                                                                                                                                                                                
        if (ht->table[i])
        {
            device_entry* entry = (device_entry*)ht->table[i]->value;
            printf("IP: %s\n", ht->table[i]->key);

            if (entry->ssdp_server)
                printf("  SSDP Server:   %s\n", entry->ssdp_server);
            if (entry->ssdp_location)
                printf("  SSDP Location: %s\n", entry->ssdp_location);

            if (entry->service_count > 0)
            {
                printf("  mDNS Services:\n");
                for (uint8_t j = 0; j < entry->service_count; ++j)
                {
                    printf("    [%d] type: %s\n", j, entry->services[j].service_type ? entry->services[j].service_type : "unknown");
                }
            }

            putc('\n', stdout);
        }
    }
       
    ht_destroy(ht, device_entry_destroy);
    libnet_destroy(context);
    capture_close(handle);
    return 0;

bad:
    if (ht)
    {
        ht_destroy(ht, device_entry_destroy);
    }

    if (context)
    {
        libnet_destroy(context);
    }

    capture_close(handle);

    return (EXIT_FAILURE);
}