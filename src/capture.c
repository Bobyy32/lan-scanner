#include "capture.h"

#include <time.h>
#include <unistd.h>
#include "debug.h"

pcap_t *init_capture(device_info device, const char *filter)
{
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(device.name, BUFSIZ, 0, 100, errbuff); // 100 redundant but keep
    if (handle == NULL)
    {
        debug_printf("Couldn't open device %s, %s\n", device.name, errbuff);
        goto bad;
    }

    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        debug_printf("Device %s doesn't provide Ethernet headers - not supported\n", device.name);
        goto bad;
    }

    struct bpf_program fp = {0};
    if (pcap_compile(handle, &fp, filter, 0, device.ipv4_address) == -1)
    {
        debug_printf("Couldn't parse filter mDNS: %s\n", pcap_geterr(handle));
        goto bad;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        debug_printf("Couldn't install filter: %s\n", pcap_geterr(handle));
        goto bad;
    }

    // Set non-blocking mode
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_setnonblock(handle, 1, pcap_errbuf) == -1)
    {
        debug_printf("Couldn't set non-blocking mode: %s\n", pcap_errbuf);
        goto bad;
    }

    pcap_freecode(&fp);

    return handle;

bad:
    pcap_freecode(&fp);
    capture_close(handle);
    return NULL;
}

void capture_loop(pcap_t *handle, int timeout, packet_handler handler_callback, void *data)
{    
    struct timespec time_start, time_now;
    clock_gettime(CLOCK_MONOTONIC, &time_start);
    int wait_sec = timeout;
    while(1)
    {
        clock_gettime(CLOCK_MONOTONIC, &time_now);
        double elapsed = (time_now.tv_sec - time_start.tv_sec) + (time_now.tv_nsec - time_start.tv_nsec) / 1000000000.0;

        if (elapsed >= wait_sec)
        {
            break;
        }

        struct pcap_pkthdr* header;
        const unsigned char* packet = NULL;
        int result = pcap_next_ex(handle, &header, &packet);
        if(result != 1)
        {
            // No packet available in non-blocking mode, sleep briefly
            if (result == 0)
            {
                usleep(10000); // 10ms
            }
            else
            {
                debug_printf("pcap_next_ex error: %d\n", result);
            }
            continue;
        }
        
        handler_callback(packet, header, data);
    }
}

void capture_close(pcap_t *handle)
{
    if (handle)
    {
        pcap_close(handle);
    }
}

void change_filter(device_info device, pcap_t *handle, char *new_filter)
{
    struct bpf_program fp;
    pcap_compile(handle, &fp, new_filter, 0, device.ipv4_address);
    pcap_setfilter(handle, &fp);
    pcap_freecode(&fp);
}
