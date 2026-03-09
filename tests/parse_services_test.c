
#include "../src/port_scan.h"
#include "../src/device.h"
#include "../src/debug.h"

int main(void)
{
    struct HashTable* ports = ht_create();
    if (!ports)
    {
        debug_printf("Failed to create hash table\n");
        return -1;
    }

    parse_service_info(ports); 

    for (uint16_t i = 0; i < ports->capacity; ++i)
    {
        if (ports->table[i])
        {
            port_info* info = (port_info*)ports->table[i]->value;
            printf("%s  %d  %s\n", info->service,info->port, info->protocol);
        }
    }

    ht_destroy(ports, port_info_destroy);
    return 0;
}