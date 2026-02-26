#include "../src/device.h"
#include "../src/capture.h"
#include "../src/protocols/mdns.h"


int main(void)
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

    /*
        MDNS
    */
    char pcap_errbuff[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline("tests/pcap/mDNS-CC3000.pcapng", pcap_errbuff);
    if (!handle)
    {
        fprintf(stderr, "Unable to initialize pcap: %s\n", pcap_errbuff); 
        goto bad;
    }

    int dlt = pcap_datalink(handle);
    printf("Link type: %d (%s)\n", dlt, pcap_datalink_val_to_name(dlt));

    struct pcap_pkthdr* header;
    const unsigned char* packet = NULL;
    unsigned int packet_count = 0;
    while(pcap_next_ex(handle, &header, &packet))
    {   
        packet_count++;                                                                                                                                         
        mdns_discovery_rcv_callback(packet, header, (void*)ht);

        if (packet_count >= 500)
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

            if (entry->ssdp_server)
                printf("  SSDP Server:   %s\n", entry->ssdp_server);
            if (entry->ssdp_location)
                printf("  SSDP Location: %s\n", entry->ssdp_location);

            if (entry->service_count > 0)
            {
                printf("  mDNS Services:\n");
                for (uint8_t j = 0; j < entry->service_count; ++j)
                {
                    printf("    [%d] type: %s\n", j, entry->services[j].type ? entry->services[j].type : "unknown");
                }
            }

            putc('\n', stdout);
        }
    }

    ht_destroy(ht);
    capture_close(handle);
    return 0;

bad:
    if (ht)
    {
        ht_destroy(ht);
    }

    capture_close(handle);

    return (EXIT_FAILURE);
}