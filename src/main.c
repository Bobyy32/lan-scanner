#include "misc.h"
#include "protocols/arp.h"


// https://repolinux.wordpress.com/2011/09/18/libnet-1-1-tutorial/#how-libnet-works
// https://www.tcpdump.org/pcap.html
// https://www.tcpdump.org/manpages/libpcap-1.10.5/pcap-filter.7.html

/*
Open pcap handle on interface
Craft ARP request packet
Send on network
Set pcap filter for ARP replies
Loop and collect responses
Parse response packets for IP/MAC pair
*/

int main(int argc, char* argv[])
{
    // Get default device details
    device_info my_device = { 0 };
    if(!get_device_info(&my_device))
    {
        fprintf(stderr, "Unable to get device info!\n");
        return (EXIT_FAILURE);
    }
    else
    {
        printf("Device name in main: %s\n", my_device.name);
        printf("Ip Address in main: %s\n", inet_ntoa((struct in_addr){my_device.ipv4_address}));
    }

    // Initialize arp packet context
    char libnet_errbuff[LIBNET_ERRBUF_SIZE];
    libnet_t* arp_context = libnet_init(LIBNET_LINK_ADV, my_device.name, libnet_errbuff);
    if (!arp_context)
    {
        fprintf(stderr, "Unable to intialize libnet context: %s\n", libnet_errbuff);
        goto bad;
    }

    // Make Arp Packet
    char* target_ip_str = "172.17.64.67";
    uint32_t target_ip = inet_addr(target_ip_str);
    if(!create_arp_message(arp_context, my_device, target_ip))
    {
        fprintf(stderr, "Unable to create arp message for %s\n", target_ip_str);
        goto bad;
    }
    else
    {
        // If successfuly create arp message then attempt to send
        int c = libnet_write(arp_context);
        if (c == -1)
        {
            fprintf(stderr, "Packet size: %s\n", libnet_geterror(arp_context));
            goto bad;
        }
        else
        {
            fprintf(stdout, "Wrote %d byte ARP packet from arp_context \"%s\"; "
                    "check the wire.\n", c, libnet_cq_getlabel(arp_context));
        }
    }

    libnet_destroy(arp_context);
    return 0;

bad:
    libnet_destroy(arp_context);
    return (EXIT_FAILURE);
}