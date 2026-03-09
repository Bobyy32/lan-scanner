
#include "../src/debug.h"
#include "../src/hashtable.h"
#include "../src/device.h"
#include "../src/capture.h"
#include "../src/protocols/arp.h"
#include "../src/protocols/mdns.h"
#include "../src/protocols/ssdp.h"

int main(void)
{
    struct HashTable* ht = ht_create();
    struct HashTable* srv_ht = ht_create();

    capture_ht ct = {.ht = ht, .srv_table = srv_ht};

    char pcap_errbuff[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline("tests/pcap/logingintoIS.pcap", pcap_errbuff);
    if (!handle)
    {
        debug_printf("Unable to initialize pcap: %s\n", pcap_errbuff);
        goto bad;
    }

    struct pcap_pkthdr* header;
    const unsigned char* packet = NULL;
    unsigned int packet_count = 0;
    while(pcap_next_ex(handle, &header, &packet))
    {
        packet_count++;
        arp_rcv_callback(packet, header, (void*)ct.ht);
        mdns_discovery_rcv_callback(packet, header, (void*)&ct);
        ssdp_discovery_rcv_callback(packet, header, (void*)ct.ht);

        if (packet_count >= 10000)
        {
            break;
        }
    }

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
                        entry->services[j].port);
                }
            }

            putc('\n', stdout);
        }
    }

    ht_destroy(ht, device_entry_destroy);
    ht_destroy(srv_ht, pending_srv_destroy);
    capture_close(handle);
    return 0;

bad:
    if (ht)
    {
        ht_destroy(ht, device_entry_destroy);
    }
    if (srv_ht)
    {
        ht_destroy(srv_ht, pending_srv_destroy);
    }

    capture_close(handle);

    return (EXIT_FAILURE);
}