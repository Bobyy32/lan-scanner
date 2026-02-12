#include "device.h""
#include "capture.h"
#include "protocols/arp.h"
#include "protocols/mdns.h"
#include "protocols/ssdp.h"

int main(int argc, char* argv[])
{
    // Get default device details
    device_info my_device = { 0 };
    if(!get_device_info(&my_device))
    {
        fprintf(stderr, "Unable to get device info!\n");
        return (EXIT_FAILURE);
    }

    // Initialize arp packet context
    char libnet_errbuff[LIBNET_ERRBUF_SIZE];
    libnet_t* context = libnet_init(LIBNET_LINK_ADV, my_device.name, libnet_errbuff);
    if (!context)
    {
        fprintf(stderr, "Unable to intialize libnet context: %s\n", libnet_errbuff);
        goto bad;
    }


    char filter[256] = { 0 };
    snprintf(
        filter,
        sizeof(filter),
        "udp port 1900 and not src host %s",
        inet_ntoa((struct in_addr) {my_device.ipv4_address})
    );

    pcap_t* handle = init_capture(my_device, filter);
    if (!handle)
    {
        fprintf(stderr, "Unable to initialize pcap catpure\n");
        goto bad;
    }
    
    ssdp_discovery_send(context, my_device);
    capture_loop(handle, 30, ssdp_discovery_rcv_callback, NULL);

    libnet_destroy(context);
    capture_close(handle);
    return 0;

bad:
    if (context)
    {
        libnet_destroy(context);
    }

    capture_close(handle);

    return (EXIT_FAILURE);
}