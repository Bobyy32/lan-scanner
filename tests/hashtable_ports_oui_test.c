#include "../src/debug.h"
#include "../src/hashtable.h"
#include "../src/device.h"
#include "../src/port_scan.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int import_oui_test();
int import_ports_test();

void import_oui(const char* filepath, hash_table* ht)
{
    if (ht == NULL)
    {
        debug_printf("Hash table is NULL\n");
        return;
    }

    ssize_t read;
    char* line = NULL;
    size_t len = 0;

    FILE* f = fopen(filepath, "r");
    if (f == NULL)
    {
        debug_printf("Failed to open %s\n", filepath);
        return;
    }

    while ((read = getline(&line, &len, f)) != -1)
    {

        char* oui = strtok(line, "\t");
        char* org = strtok(NULL, "\n");
        

        if(ht_get(ht, oui))
        {
            continue;
        }

        oui_info* info = calloc(1, sizeof(oui_info));

        if (info == NULL)
        {
            continue;
        }

        info->oui = strdup(oui);
        info->organization = strdup(org);

        ht_set(ht, oui, info);
    }


    free(line);
    fclose(f);
}

void import_ports(const char* filepath, hash_table* ht)
{
    if (ht == NULL)
    {
        debug_printf("Hash table is NULL\n");
        return;
    }

    ssize_t read;
    char* line = NULL;
    size_t len = 0;

    FILE* f = fopen(filepath, "r");
    if (f == NULL)
    {
        debug_printf("Failed to open %s\n", filepath);
        return;
    }

    while ((read = getline(&line, &len, f)) != -1)
    {
        char* saveptr = NULL;

        char* service = strtok_r(line, " ", &saveptr);
        char* port = strtok_r(NULL, " ", &saveptr);
        char* protocol = strtok_r(NULL, " \n", &saveptr);

        //printf("%s %s %s\n", service, port, protocol);
        
        port_info* info = NULL;
        info = (port_info*)ht_get(ht, port);
        if (info != NULL)
        {
            if (strcmp(info->protocol, protocol) != 0)
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
            info = (port_info*)calloc(1, sizeof(port_info));
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

int main()
{

    return import_oui_test();

}

int import_oui_test()
{
    hash_table* ht_oui = ht_create();
    if (ht_oui == NULL)
    {
        debug_printf("Failed to create hash table\n");
        return 1;
    }

    import_oui("resources/oui.txt", ht_oui);

    /*
    for (size_t i = 0; i < ht_oui->capacity; ++i)
    {
        if (ht_oui->table[i] == NULL)
        {
            continue;
        }


        oui_info* info = (oui_info*)ht_oui->table[i]->value;

        printf("%s %s\n", info->oui, info->organization);
    }
    */

    struct DeviceInfo my_device = { 0 };
    get_device_info(&my_device);
    print_device_info(my_device);

    char my_oui[9] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0 };
    snprintf(my_oui, 9, "%02X:%02X:%02X", my_device.mac_address[0], my_device.mac_address[1], my_device.mac_address[2]);

    oui_info* info = ht_get(ht_oui, my_oui);
    if (info == NULL)
    {
        printf("No oui info\n");
    }
    else
    {
        printf("OUI FOUND! %s %s\n", info->oui, info->organization);
    }

    printf("(ht_oui) Number of elements %u\n", ht_oui->num_buckets);
    printf("(ht_oui) Size of hash table: %lu\n", ht_oui->capacity);

    ht_destroy(ht_oui, oui_info_destroy);

    return 0;
}

int import_ports_test()
{
    hash_table* ht_port = ht_create();
    if (ht_port == NULL)
    {
        debug_printf("Failed to create hash table\n");
        return 1;
    }

    import_ports("resources/ports.txt", ht_port);

    /*
    for (size_t i = 0; i < ht_port->capacity; ++i)
    {
        if (ht_port->table[i] == NULL)
        {
            continue;
        }


        port_info* info = (port_info*)ht_port->table[i]->value;

        printf("%s %u %s\n", info->service, info->port, info->protocol);
    }

    */

    printf("(ht_port) Number of elements %u\n", ht_port->num_buckets);
    printf("(ht_port) Size of hash table: %lu\n", ht_port->capacity);

    ht_destroy(ht_port, port_info_destroy);

    return 0;

}