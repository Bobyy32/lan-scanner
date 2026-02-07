#include "misc.h"
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

    

    ssdp_discovery_send(context, my_device);



    libnet_destroy(context);
    //capture_close(handle);
    return 0;

bad:
    if (context)
    {
        libnet_destroy(context);
    }

    //capture_close(handle);

    return (EXIT_FAILURE);
}