#include "misc.h"
#include "capture.h"
#include "protocols/arp.h"
#include "protocols/mdns.h"

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

    pcap_t* handle = init_capture(my_device, "udp port 5353");
    if (!handle)
    {
        fprintf(stderr, "Unable to initialize pcap catpure\n");
        goto bad;
    }

    mdns_discovery_send_u(context, my_device);
    capture_loop(handle, 15, mdns_discovery_rcv_callback, NULL);
    
    libnet_destroy(context);
    //pcap_close(handle);
    return 0;

bad:
    if (context)
    {
        libnet_destroy(context);
    }

    capture_close(handle);

    return (EXIT_FAILURE);
}