
#include <libnet.h>
#include <pcap.h>

#include "../src/debug.h"
#include "../src/hashtable.h"
#include "../src/device.h"
#include "../src/capture.h"
#include "../src/scan.h"
#include "../src/port_scan.h"

int main (void)
{
    struct HashTable* ht = ht_create();
    struct HashTable* ht_ports = ht_create();
    struct DeviceInfo my_device = { 0 };

    if (ht == NULL || ht_ports == NULL)
    {
        debug_printf("Unable to create hash table!\n");

        if (ht)
        {
            ht_destroy(ht, device_entry_destroy);
        }

        if (ht_ports)
        {
            ht_destroy(ht_ports, port_info_destroy);
        }

        return (EXIT_FAILURE);
    }

    if(!get_device_info(&my_device))
    {
        debug_printf("Unable to get device info!\n");
        ht_destroy(ht, device_entry_destroy);
        ht_destroy(ht_ports, port_info_destroy);
        return (EXIT_FAILURE);
    }

    parse_service_info(ht_ports);


    scan_args args= {.device = &my_device, .ht = ht};

    int rc1, rc2, rc3;
    pthread_t thread1, thread2, thread3;

    if ((rc1 = pthread_create(&thread1, NULL, arp_scan_thread, &args)))
    {
        debug_printf("Thread creation failed %d\n", rc1);
    }

    if ((rc2 = pthread_create(&thread2, NULL, mdns_scan_thread, &args)))
    {
        debug_printf("Thread creation failed %d\n", rc2);
    }


    if ((rc3 = pthread_create(&thread3, NULL, ssdp_scan_thread, &args)))
    {
        debug_printf("Thread creation failed %d\n", rc3);
    }

    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    pthread_join(thread3, NULL);
    

    int rc5;
    pthread_t thread5;

    if ((rc5 = pthread_create(&thread5, NULL, tcp_rcv_thread, &args)))
    {
        debug_printf("Thread creation failed %d\n", rc5);
    }

    tcp_scan(&my_device, ht, ht_ports);

    pthread_join(thread5, NULL);


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
                        continue;
                    }
                    printf("    Port: %u | Service %s\n", info->port, info->service);
                }

            }
    
            putc('\n', stdout);
        }
    }


    ht_destroy(ht, device_entry_destroy);
    ht_destroy(ht_ports, port_info_destroy);
    return 0;
}