
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
    

    


    ht_destroy(ports, port_info_destroy);
    return 0;
}