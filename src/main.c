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

    // create sniffing session to listen for arp replies
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(my_device.name, BUFSIZ, 0, 1000, errbuff);
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
    if (pcap_compile(handle, &fp, "arp", 0, my_device.ipv4_address) == -1)
    {
        fprintf(stderr, "Couldn't parse filter arp: %s\n", pcap_geterr(handle));
        goto bad;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(handle));
        goto bad;
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


    // Record traffic
    struct pcap_pkthdr header;
    const unsigned char* packet = pcap_next(handle, &header);
    printf("Pack length of [%d]\n", header.len);


    libnet_destroy(arp_context);
    pcap_close(handle);
    return 0;

bad:
    if (arp_context)
    {
        libnet_destroy(arp_context);
    }

    if (handle)
    {
        pcap_close(handle);
    }

    return (EXIT_FAILURE);
}