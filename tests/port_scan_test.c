
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

    printf("Device Ip: 192.168.88.1\n");
    printf("Device MAC: %s\n", target->mac);


    char libnet_errbuff[LIBNET_ERRBUF_SIZE];
    libnet_t* context = libnet_init(LIBNET_LINK_ADV, my_device.name, libnet_errbuff);
    if (!context)
    {
        debug_printf("Unable to initialize libnet context %s\n", libnet_errbuff);
        return (EXIT_FAILURE);
    }

    char filter[256] = {0};
    snprintf(
        filter,
        sizeof(filter),
        "tcp and not src host %s",
        inet_ntoa((struct in_addr) {my_device.ipv4_address})
    );

    pcap_t* handle = init_capture(my_device, filter);
    if (!handle)
    {
        debug_printf("Unable to initialize pcap catpure\n");
        libnet_destroy(context);
        ht_destroy(ht, device_entry_destroy);
        return -1;
    }

    uint8_t mac_bytes[6];                                                                                                                    
    sscanf(target->mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",                                                                                     
        &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],                                                                                         
        &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]);
    tcp_port_scan(context, my_device, mac_bytes, inet_addr("192.168.88.1"), 2000);

    capture_loop(handle, 10, tcp_port_rcv_callback, NULL);

    ht_destroy(ht, device_entry_destroy);
    libnet_destroy(context);
    capture_close(handle);
    return 0;
}