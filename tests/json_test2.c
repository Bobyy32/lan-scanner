
#include "../src/debug.h"
#include "../src/hashtable.h"
#include "../src/device.h"
#include "../src/scan.h"
#include "../src/port_scan.h"

#include "../src/cjson/cJSON.h"


void export_discovered_hosts(device_info my_device, hash_table* ht, hash_table* ht_ports, hash_table* ht_oui)
{
    cJSON* object = NULL;
    cJSON* network_id = NULL;
    cJSON* subnet = NULL;
    cJSON* hosts = NULL;

    object = cJSON_CreateObject();
    if (object == NULL)
    {
        return;
    }

    network_id = cJSON_CreateString(inet_ntoa((struct in_addr){my_device.ipv4_address}));
    cJSON_AddItemToObject(object, "network_id", network_id);

    subnet = cJSON_CreateString(inet_ntoa((struct in_addr){my_device.subnet_mask}));
    cJSON_AddItemToObject(object, "subnet", subnet);

    hosts = cJSON_CreateArray();
    if (hosts == NULL)
    {
        cJSON_Delete(object);
        return;
    }
    cJSON_AddItemToObject(object, "hosts", hosts);

    for (size_t i = 0; i < ht->capacity; ++i)
    {
        if (ht->table[i] == NULL)
        {
            continue;
        }

        device_entry* entry = (device_entry*)ht->table[i]->value;

        cJSON* host = NULL;
        cJSON* ip = NULL;
        cJSON* mac = NULL;
        cJSON* vendor = NULL;

        cJSON* open_ports = NULL;

        cJSON* mdns_services = NULL;

        cJSON* ssdp_server = NULL;
        cJSON* ssdp_location = NULL;
        
        host = cJSON_CreateObject();
        if (host == NULL)
        {
            continue;
        }
        cJSON_AddItemToArray(hosts, host);

        ip = cJSON_CreateString(ht->table[i]->key);
        cJSON_AddItemToObject(host, "ip", ip);

        mac = cJSON_CreateString(entry->mac);
        cJSON_AddItemToObject(host, "mac", mac);

        char oui[9] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0 };
        snprintf(oui, 9, "%02X:%02X:%02X", entry->mac_bytes[0], entry->mac_bytes[1], entry->mac_bytes[2]);
        oui_info* vendor_info = ht_get(ht_oui, oui);
        if (vendor_info == NULL)
        {
            vendor = cJSON_CreateString("unknown");
        }
        else
        {
            vendor = cJSON_CreateString(vendor_info->organization);
        }
        cJSON_AddItemToObject(host, "vendor", vendor);

        if (entry->open_port_count > 0)
        {
            open_ports = cJSON_CreateArray();
            if (open_ports != NULL)
            {
                cJSON_AddItemToObject(host, "ports", open_ports);
                
                for (uint16_t j = 0; j < entry->open_port_count; ++j)
                {
                    cJSON* port_entry = NULL;
                    cJSON* port = NULL;
                    cJSON* service = NULL;

                    port_entry = cJSON_CreateObject();
                    if (port_entry == NULL)
                    {
                        continue;
                    }
                    cJSON_AddItemToArray(open_ports, port_entry);

                    port = cJSON_CreateNumber((double)entry->open_ports[j]);
                    cJSON_AddItemToObject(port_entry, "port", port);

                    char buf[6];
                    snprintf(buf, sizeof(buf), "%u", (unsigned)entry->open_ports[j]);
                    port_info* service_info = (port_info*)ht_get(ht_ports, buf);
                    if (service_info == NULL)
                    {
                        service = cJSON_CreateString("unknown");
                    }
                    else
                    {
                        service = cJSON_CreateString(service_info->service);
                    }
                    cJSON_AddItemToObject(port_entry, "service", service);
                }
            }
        }

        if (entry->service_count > 0)
        {
            mdns_services = cJSON_CreateArray();
            if (mdns_services)
            {
                cJSON_AddItemToObject(host, "mdns_services", mdns_services);

                for (uint8_t j = 0; j < entry->service_count; ++j)
                {

                    cJSON* mdns_service = NULL;
                    cJSON* mdns_type = NULL;
                    cJSON* mdns_name = NULL;
                    cJSON* mdns_host = NULL;
                    cJSON* mdns_port = NULL;

                    mdns_service = cJSON_CreateObject();
                    if (mdns_service == NULL)
                    {
                        continue;
                    }
                    cJSON_AddItemToArray(mdns_services, mdns_service);

                    mdns_type = cJSON_CreateString(entry->services[j].service_type ? entry->services[j].service_type : "unknown");
                    cJSON_AddItemToObject(mdns_service, "mdns_type", mdns_type);

                    mdns_name = cJSON_CreateString(entry->services[j].instance_name ? entry->services[j].instance_name : "unknown");
                    cJSON_AddItemToObject(mdns_service, "mdns_name", mdns_name);

                    mdns_host = cJSON_CreateString(entry->services[j].host_name ? entry->services[j].host_name : "unknown");
                    cJSON_AddItemToObject(mdns_service, "mdns_host", mdns_host);

                    mdns_port = cJSON_CreateNumber((double)entry->services[j].port);
                    cJSON_AddItemToObject(mdns_service, "mdns_port", mdns_port);
                }

            }
        }

        if (entry->ssdp_server)
        {
            ssdp_server = cJSON_CreateString(entry->ssdp_server);
            cJSON_AddItemToObject(host, "ssdp_server", ssdp_server);
        }

        if (entry->ssdp_location)
        {
            ssdp_location = cJSON_CreateString(entry->ssdp_location);
            cJSON_AddItemToObject(host, "ssdp_location", ssdp_location);
        }
    }

    char* string = cJSON_Print(object);
    if (string == NULL)
    {
        debug_printf("Failed to print object\n");
    }
    else
    {
        FILE* f = fopen("resources/data.json", "w");
        if (f)
        {
            fputs(string, f);
            fclose(f);
        }
        else
        {
            debug_printf("Unable to save data to resources/data.json\n");
        }

        free(string);
    }

    cJSON_Delete(object);
}


int main (void)
{
    // Setup
    struct HashTable* ht = ht_create();
    struct HashTable* ht_ports = ht_create();
    struct HashTable* ht_oui = ht_create();

    struct DeviceInfo my_device = { 0 };

    if (ht == NULL || ht_ports == NULL|| ht_oui == NULL)
    {
        debug_printf("Unable to create hash table!\n");
        goto exit;
    }

    if(!get_device_info(&my_device))
    {
        debug_printf("Unable to get device info!\n");
        goto exit;
    }
    print_device_info(my_device);

    device_entry* value = (device_entry*)calloc(1, sizeof(device_entry));
    if (value == NULL)
    {
        debug_printf("Unable to allocate device entry!\n");
        goto exit;
    }
    snprintf(value->mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             my_device.mac_address[0], my_device.mac_address[1], my_device.mac_address[2],
             my_device.mac_address[3], my_device.mac_address[4], my_device.mac_address[5]);
    memcpy(value->mac_bytes, my_device.mac_address, 6);
    ht_set(ht, inet_ntoa((struct in_addr){my_device.ipv4_address}), (void*)value);

    import_ports("resources/ports.txt", ht_ports);
    import_oui("resources/oui.txt", ht_oui);

    int rc1, rc2, rc3, rc4;
    pthread_t thread1, thread2, thread3, thread4;
    scan_args args= {.device = &my_device, .ht = ht};

    // Initial three point scan
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

    if (rc1 == 0)
    {
        pthread_join(thread1, NULL);
    }

    if (rc2 == 0)
    {
        pthread_join(thread2, NULL);
    }

    if (rc3 == 0)
    {
        pthread_join(thread3, NULL);
    }

    // Secondary TCP port scan
    if ((rc4 = pthread_create(&thread4, NULL, tcp_rcv_thread, &args)))
    {
        debug_printf("Thread creation failed %d\n", rc4);
    }

    if (rc4 == 0)
    {
        tcp_scan(&my_device, ht, ht_ports);
        pthread_join(thread4, NULL);
    }

    if (ht->num_buckets > 1)
    {
        export_discovered_hosts(my_device, ht, ht_ports, ht_oui);
    }

exit:
    if (ht)
    {
        ht_destroy(ht, device_entry_destroy);
    }

    if (ht_ports)
    {
        ht_destroy(ht_ports, port_info_destroy);
    }

    if (ht_oui)
    {
        ht_destroy(ht_oui, oui_info_destroy);
    }

    return 0;
}