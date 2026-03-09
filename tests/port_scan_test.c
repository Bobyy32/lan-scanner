

#include "../src/debug.h"
#include "../src/hashtable.h"
#include "../src/device.h"
#include "../src/scan.h"
#include "../src/port_scan.h"

int main (void)
{
    struct HashTable* ht = ht_create();
    struct DeviceInfo my_device = {0};

    if (ht == NULL)
    {
        debug_printf("Unable to create hash table!\n");
        ht_destroy(ht, device_entry_destroy);
        return (EXIT_FAILURE);
    }

    if(!get_device_info(&my_device))
    {
        debug_printf("Unable to get device info!\n");
        ht_destroy(ht, device_entry_destroy);
        return (EXIT_FAILURE);
    }

    arp_scan(&my_device, ht);

    device_entry* target = ht_get(ht, "192.168.88.1");\
    if (target == NULL)
    {
        debug_printf("Target 192.168.88.1 doesn't exist\n");
        ht_destroy(ht, device_entry_destroy);
        return (EXIT_FAILURE);
    }

    printf("Device Ip: 192.168.88.1\nDevice MAC: %s", target->mac);

    return 0;
}