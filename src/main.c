#include "misc.h"
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

    /* // create sniffing session to listen for arp replies
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(my_device.name, BUFSIZ, 0, 100, errbuff); // 100 redundant but keep
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s, %s\n", my_device.name, errbuff);
        goto bad;
    }

    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", my_device.name);
        goto bad;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "arp and arp[6:2] = 2", 0, my_device.ipv4_address) == -1)
    {
        fprintf(stderr, "Couldn't parse filter arp: %s\n", pcap_geterr(handle));
        goto bad;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(handle));
        goto bad;
    }

    // Set non-blocking mode
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_setnonblock(handle, 1, pcap_errbuf) == -1)
    {
        fprintf(stderr, "Couldn't set non-blocking mode: %s\n", pcap_errbuf);
        goto bad;
    } */

    // Initialize arp packet context
    char libnet_errbuff[LIBNET_ERRBUF_SIZE];
    libnet_t* context = libnet_init(LIBNET_LINK_ADV, my_device.name, libnet_errbuff);
    if (!context)
    {
        fprintf(stderr, "Unable to intialize libnet context: %s\n", libnet_errbuff);
        goto bad;
    }

    mdns_discovery_send(context, my_device);
    mdns_discovery_rcv(my_device);
    
    libnet_destroy(context);
    //pcap_close(handle);
    return 0;

bad:
    if (context)
    {
        libnet_destroy(context);
    }

    /* if (handle)
    {
        pcap_close(handle);
    } */

    return (EXIT_FAILURE);
}